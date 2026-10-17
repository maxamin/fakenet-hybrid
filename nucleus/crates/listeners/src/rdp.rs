//! RDP (MS-RDPBCGR) for capture: the X.224 Connection Request's `mstshash` cookie (the user
//! name) and requested security protocols; then, for NLA clients, TLS and CredSSP
//! (MS-CSSP) far enough to capture the NTLM response inside it as a crackable hash; for TLS
//! or standard-security clients, the MCS Connect-Initial's client core data (computer name,
//! build, keyboard layout, screen). The connection then ends: there's no desktop to show.

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::ntlm;
use crate::session::Session;
use crate::stream::BoxStream;

const MAX_PDU: usize = 64 * 1024;

const PROTOCOL_SSL: u32 = 1;
const PROTOCOL_HYBRID: u32 = 2;
const PROTOCOL_HYBRID_EX: u32 = 8;

/// What the X.224 Connection Request says
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub cookie: Option<String>,
    pub requested: Option<u32>,
}

impl ConnectionRequest {
    /// From a TPKT-framed X.224 Connection Request
    pub fn parse(tpkt: &[u8]) -> Option<ConnectionRequest> {
        if tpkt.len() < 11 || tpkt[0] != 3 || tpkt[5] != 0xe0 {
            return None;
        }
        let mut variable = &tpkt[11..];
        let mut request = ConnectionRequest::default();
        if let Some(rest) = variable.strip_prefix(b"Cookie: ") {
            let end = rest.windows(2).position(|w| w == b"\r\n")?;
            let cookie = String::from_utf8_lossy(&rest[..end]).into_owned();
            request.cookie = Some(cookie.strip_prefix("mstshash=").map(str::to_string).unwrap_or(cookie));
            variable = &rest[end + 2..];
        }
        // RDP_NEG_REQ: type 1, flags, length 8, requested protocols
        if let [1, _, 8, 0, a, b, c, d, ..] = variable {
            request.requested = Some(u32::from_le_bytes([*a, *b, *c, *d]));
        }
        Some(request)
    }
}

fn protocol_names(requested: u32) -> Vec<&'static str> {
    let mut names = vec![];
    if requested == 0 {
        names.push("RDP");
    }
    for (bit, name) in [(PROTOCOL_SSL, "TLS"), (PROTOCOL_HYBRID, "CredSSP"), (4, "RDSTLS"), (PROTOCOL_HYBRID_EX, "CredSSP-EX"), (0x10, "RDSAAD")] {
        if requested & bit != 0 {
            names.push(name);
        }
    }
    names
}

/// An X.224 Connection Confirm, with an RDP_NEG_RSP selecting `selected` when the client
/// negotiated
fn connection_confirm(selected: Option<u32>) -> Vec<u8> {
    let mut x224 = vec![0, 0xd0, 0, 0, 0x12, 0x34, 0];
    if let Some(selected) = selected {
        x224.extend_from_slice(&[2, 0x1f, 8, 0]); // RDP_NEG_RSP; flags: extended data, dynvc gfx, restricted admin...
        x224.extend_from_slice(&selected.to_le_bytes());
    }
    x224[0] = (x224.len() - 1) as u8;
    let length = (4 + x224.len()) as u16;
    [vec![3, 0], length.to_be_bytes().to_vec(), x224].concat()
}

/// TS_UD_CS_CORE inside an MCS Connect-Initial: the client's computer name & more
pub fn client_core_data(pdu: &[u8]) -> Option<Value> {
    let start = pdu.windows(2).enumerate().position(|(i, w)| {
        w == [0x01, 0xc0] && pdu.get(i + 4..i + 8).is_some_and(|v| v[2] == 0x08 && v[3] == 0x00) // Version 0x0008000x
    })?;
    let core = &pdu[start..];
    let u16_at = |at: usize| core.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |at: usize| core.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let name: Vec<u16> = core.get(24..56)?.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|c| *c != 0).collect();
    Some(json!({
        "client_name": String::from_utf16_lossy(&name),
        "client_build": u32_at(20),
        "keyboard_layout": u32_at(16).map(|k| format!("{k:#010x}")),
        "desktop": format!("{}x{}", u16_at(8)?, u16_at(10)?),
    }))
}

pub async fn handle(mut stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let Some(request) = read_tpkt(&mut stream, &session).await? else { return Ok(()) };
    session.client_data(&request);
    let Some(connection) = ConnectionRequest::parse(&request) else { return Ok(()) };
    let requested = connection.requested.unwrap_or(0);
    let meta = json!({ "cookie": connection.cookie, "requested_protocols": protocol_names(requested) });
    session.log("rdp_connect", meta.clone());
    session.notify(&request, meta);
    if let Some(user) = &connection.cookie {
        session.log("credentials", json!({ "mechanism": "RDP cookie", "username": user }));
    }
    let selected = if requested & (PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX) != 0 {
        Some(PROTOCOL_HYBRID)
    } else if requested & PROTOCOL_SSL != 0 {
        Some(PROTOCOL_SSL)
    } else {
        connection.requested.map(|_| 0)
    };
    let confirm = connection_confirm(selected);
    stream.write_all(&confirm).await?;
    session.server_data(&confirm);
    if selected.is_some_and(|s| s != 0) {
        stream = crate::dispatch::terminate_tls(stream, &mut session).await?;
    }
    if selected == Some(PROTOCOL_HYBRID) {
        return credssp(stream, session).await;
    }
    // TLS or standard security: the MCS Connect-Initial describes the client
    if let Some(pdu) = read_tpkt(&mut stream, &session).await? {
        session.client_data(&pdu);
        if let Some(client) = client_core_data(&pdu) {
            session.log("rdp_client", client.clone());
            session.notify(&pdu, json!({ "client": client }));
        }
    }
    Ok(())
}

/// CredSSP: the client's NTLM NEGOTIATE in a TSRequest, our CHALLENGE back, then its
/// AUTHENTICATE, which is captured; the logon then fails
async fn credssp(mut stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let mut challenge = [0u8; 8];
    for _ in 0..4 {
        let Some(request) = read_der(&mut stream, &session).await? else { return Ok(()) };
        session.client_data(&request);
        let version = ts_request_version(&request).unwrap_or(2).min(6);
        let Some(token) = ntlm::find(&request) else { return Ok(()) };
        let reply = match ntlm::message_type(token) {
            Some(1) => {
                challenge = crate::tls::random_bytes();
                ts_request(version, Some(&ntlm::challenge(token, challenge)), None)
            }
            Some(3) => {
                if let Some(authenticate) = ntlm::Authenticate::parse(token) {
                    let record = authenticate.record(&challenge);
                    session.log("credentials", record.clone());
                    session.notify(token, json!({ "credssp": "authenticate", "credentials": record }));
                }
                // STATUS_LOGON_FAILURE, as an NTSTATUS in the TSRequest's errorCode (v3+)
                let reply = ts_request(version, None, Some(0xc000_006d));
                stream.write_all(&reply).await?;
                session.server_data(&reply);
                return Ok(());
            }
            _ => return Ok(()),
        };
        stream.write_all(&reply).await?;
        session.server_data(&reply);
    }
    Ok(())
}

/// TSRequest ::= SEQUENCE { version [0] INTEGER, negoTokens [1] NegoData OPTIONAL, ...,
/// errorCode [4] INTEGER OPTIONAL }
fn ts_request(version: u8, token: Option<&[u8]>, error: Option<u32>) -> Vec<u8> {
    let mut fields = ntlm::der(0xa0, &ntlm::der(0x02, &[version]));
    if let Some(token) = token {
        let nego = ntlm::der(0x30, &ntlm::der(0x30, &ntlm::der(0xa0, &ntlm::der(0x04, token))));
        fields.extend(ntlm::der(0xa1, &nego));
    }
    if let Some(error) = error {
        fields.extend(ntlm::der(0xa4, &ntlm::der(0x02, &[&[0u8][..], &error.to_be_bytes()].concat())));
    }
    ntlm::der(0x30, &fields)
}

fn ts_request_version(request: &[u8]) -> Option<u8> {
    // 30 len a0 03 02 01 VERSION
    let at = request.windows(3).position(|w| w == [0xa0, 0x03, 0x02])?;
    request.get(at + 4).copied()
}

async fn read_tpkt(stream: &mut BoxStream, session: &Session) -> anyhow::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    match tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut header)).await {
        Err(_) => return Ok(None),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Ok(result) => result?,
    };
    if header[0] != 3 {
        return Ok(None); // Fast-path PDUs aren't expected before the connection is set up
    }
    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
    anyhow::ensure!((4..=MAX_PDU).contains(&length), "bad TPKT length");
    let mut pdu = header.to_vec();
    pdu.resize(length, 0);
    tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut pdu[4..])).await??;
    Ok(Some(pdu))
}

/// One DER SEQUENCE (a CredSSP TSRequest)
async fn read_der(stream: &mut BoxStream, session: &Session) -> anyhow::Result<Option<Vec<u8>>> {
    let mut head = [0u8; 2];
    match tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut head)).await {
        Err(_) => return Ok(None),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Ok(result) => result?,
    };
    if head[0] != 0x30 {
        return Ok(None);
    }
    let mut data = head.to_vec();
    let length = match head[1] {
        n if n < 0x80 => usize::from(n),
        n @ 0x81..=0x83 => {
            let mut bytes = vec![0u8; usize::from(n & 0x7f)];
            tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut bytes)).await??;
            data.extend_from_slice(&bytes);
            bytes.iter().fold(0usize, |n, b| (n << 8) | usize::from(*b))
        }
        _ => anyhow::bail!("bad DER length"),
    };
    anyhow::ensure!(length <= MAX_PDU, "TSRequest too large");
    let start = data.len();
    data.resize(start + length, 0);
    tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut data[start..])).await??;
    Ok(Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connection_requests() {
        // FreeRDP 3: cookie, then RDP_NEG_REQ asking for TLS | CredSSP | CredSSP-EX
        let mut request = b"\x03\x00\x00\x2b\x26\xe0\x00\x00\x00\x00\x00Cookie: mstshash=alice\r\n".to_vec();
        request.extend_from_slice(&[1, 0, 8, 0, 0x0b, 0, 0, 0]);
        let parsed = ConnectionRequest::parse(&request).unwrap();
        assert_eq!(parsed, ConnectionRequest { cookie: Some("alice".into()), requested: Some(0x0b) });
        assert_eq!(protocol_names(0x0b), ["TLS", "CredSSP", "CredSSP-EX"]);
        assert_eq!(ConnectionRequest::parse(b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00"), Some(ConnectionRequest::default()));
        assert_eq!(ConnectionRequest::parse(b"\x03\x00\x00\x0b\x06\xd0"), None);
    }

    #[test]
    fn confirms_with_the_selected_protocol() {
        let confirm = connection_confirm(Some(PROTOCOL_HYBRID));
        assert_eq!(confirm.len(), 19);
        assert_eq!(&confirm[..4], &[3, 0, 0, 19]);
        assert_eq!(confirm[4], 14); // X.224 length indicator
        assert_eq!(&confirm[15..], &PROTOCOL_HYBRID.to_le_bytes());
        assert_eq!(connection_confirm(None).len(), 11);
    }

    #[test]
    fn reads_client_core_data() {
        let mut core = vec![0x01, 0xc0, 0xd8, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x00, 0x05, 0x00, 0x03, 0x01, 0xca, 0x03, 0xaa];
        core.extend_from_slice(&0x0409u32.to_le_bytes());
        core.extend_from_slice(&19045u32.to_le_bytes());
        let mut name: Vec<u8> = "VICTIM-PC".encode_utf16().flat_map(u16::to_le_bytes).collect();
        name.resize(32, 0);
        core.extend_from_slice(&name);
        let pdu = [b"\x03\x00\x01\x00junk".to_vec(), core].concat();
        let client = client_core_data(&pdu).unwrap();
        assert_eq!(client["client_name"], "VICTIM-PC");
        assert_eq!(client["client_build"], 19045);
        assert_eq!(client["desktop"], "1280x768");
        assert_eq!(client["keyboard_layout"], "0x00000409");
    }

    #[test]
    fn ts_requests_carry_tokens_and_errors() {
        let request = ts_request(6, Some(b"NTLMSSP\0\x02"), None);
        assert_eq!(ts_request_version(&request), Some(6));
        assert!(ntlm::find(&request).is_some());
        let error = ts_request(6, None, Some(0xc000_006d));
        assert!(error.ends_with(&[0xa4, 0x07, 0x02, 0x05, 0x00, 0xc0, 0x00, 0x00, 0x6d]));
    }
}
