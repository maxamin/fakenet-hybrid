//! SMB (MS-SMB2) for credential capture: NetBIOS session framing, the SMB1 multi-protocol
//! negotiate (answered by moving the client to SMB2), SMB2 NEGOTIATE, and SESSION_SETUP
//! with NTLM inside SPNEGO. The client's AUTHENTICATE is logged as `credentials` with a
//! crackable NetNTLM hash, then the logon fails (STATUS_LOGON_FAILURE): a fake server can't
//! derive the signing keys a real session needs, and a failed logon makes worms try their
//! next credentials, which are captured too. Each step goes to the daemon as an event.

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::ntlm;
use crate::session::Session;
use crate::stream::BoxStream;

/// A NetBIOS session message's largest accepted size (clients send far less before logon)
const MAX_MESSAGE: usize = 1 << 20;

const STATUS_SUCCESS: u32 = 0;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xc000_0016;
const STATUS_LOGON_FAILURE: u32 = 0xc000_006d;
const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;

const NEGOTIATE: u16 = 0;
const SESSION_SETUP: u16 = 1;
const LOGOFF: u16 = 2;

/// Dialects we speak, best first: 3.1.1 needs negotiate contexts (preauth integrity),
/// which a capture-only server gains nothing from
const DIALECTS: &[u16] = &[0x0302, 0x0300, 0x0210, 0x0202];

struct State {
    challenge: [u8; 8],
    session_id: u64,
    server_guid: [u8; 16],
}

pub async fn handle(mut stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let mut state = State {
        challenge: crate::tls::random_bytes(),
        session_id: u64::from_le_bytes(crate::tls::random_bytes()) | 1,
        server_guid: crate::tls::random_bytes(),
    };
    loop {
        let Some((kind, message)) = read_message(&mut stream, &session).await? else { return Ok(()) };
        session.client_data(&message);
        let reply = match kind {
            // NetBIOS session request (port 139): accept it
            0x81 => {
                session.log("netbios_session", json!({}));
                send(&mut stream, &session, 0x82, &[]).await?;
                continue;
            }
            0x00 => match message.get(..4) {
                Some(b"\xffSMB") => match smb1_negotiate(&message, &mut session, &state) {
                    Some(reply) => reply,
                    None => return Ok(()),
                },
                Some(b"\xfeSMB") => match smb2(&message, &mut session, &mut state) {
                    Some(reply) => reply,
                    None => return Ok(()),
                },
                _ => return Ok(()),
            },
            _ => continue, // Keep-alives
        };
        send(&mut stream, &session, 0x00, &reply).await?;
    }
}

/// One NetBIOS session message: (type, contents)
async fn read_message(stream: &mut BoxStream, session: &Session) -> anyhow::Result<Option<(u8, Vec<u8>)>> {
    let mut header = [0u8; 4];
    match tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut header)).await {
        Err(_) => return Ok(None),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Ok(result) => result?,
    };
    let length = (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
    anyhow::ensure!(length <= MAX_MESSAGE, "SMB message too large");
    let mut message = vec![0u8; length];
    tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut message)).await??;
    Ok(Some((header[0], message)))
}

async fn send(stream: &mut BoxStream, session: &Session, kind: u8, message: &[u8]) -> std::io::Result<()> {
    let length = message.len() as u32;
    let mut frame = vec![kind, (length >> 16) as u8, (length >> 8) as u8, length as u8];
    frame.extend_from_slice(message);
    stream.write_all(&frame).await?;
    session.server_data(message);
    Ok(())
}

fn u16_at(data: &[u8], at: usize) -> u16 {
    data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0)
}

fn u64_at(data: &[u8], at: usize) -> u64 {
    data.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes"))).unwrap_or(0)
}

/// SMB1 NEGOTIATE (the "multi-protocol" negotiate older or cautious clients start with):
/// if it offers SMB 2, answer with an SMB2 NEGOTIATE response for the wildcard dialect 2.???,
/// and the client continues in SMB2. SMB1-only clients (old worms among them) are logged and
/// disconnected, as by current Windows with SMB1 disabled.
fn smb1_negotiate(message: &[u8], session: &mut Session, state: &State) -> Option<Vec<u8>> {
    let dialects: Vec<String> = message
        .get(35..)
        .unwrap_or_default()
        .split(|b| *b == 0)
        .filter_map(|d| d.strip_prefix(&[0x02]))
        .map(|d| String::from_utf8_lossy(d).into_owned())
        .collect();
    session.log("smb_negotiate", json!({ "smb1": true, "dialects": dialects }));
    session.notify(message, json!({ "command": "NEGOTIATE", "smb1": true, "dialects": dialects }));
    dialects.iter().any(|d| d.starts_with("SMB 2.")).then(|| header(STATUS_SUCCESS, NEGOTIATE, 0, 0, 0, 1, &negotiate_body(0x02ff, state)))
}

/// An SMB2 response: the 64-byte header, then `body`
fn header(status: u32, command: u16, message_id: u64, tree_id: u32, session_id: u64, credits: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + body.len());
    out.extend_from_slice(b"\xfeSMB");
    out.extend_from_slice(&64u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // Credit charge
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&command.to_le_bytes());
    out.extend_from_slice(&credits.max(1).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // SMB2_FLAGS_SERVER_TO_REDIR
    out.extend_from_slice(&0u32.to_le_bytes()); // Next command
    out.extend_from_slice(&message_id.to_le_bytes());
    out.extend_from_slice(&0xfeffu32.to_le_bytes()); // Process ID (sync)
    out.extend_from_slice(&tree_id.to_le_bytes());
    out.extend_from_slice(&session_id.to_le_bytes());
    out.extend_from_slice(&[0; 16]); // Signature
    out.extend_from_slice(body);
    out
}

fn negotiate_body(dialect: u16, state: &State) -> Vec<u8> {
    let security = ntlm::spnego_init();
    let mut body = Vec::with_capacity(64 + security.len());
    body.extend_from_slice(&65u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes()); // Signing enabled, not required
    body.extend_from_slice(&dialect.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&state.server_guid);
    body.extend_from_slice(&7u32.to_le_bytes()); // DFS, leasing, large MTU
    for _ in 0..3 {
        body.extend_from_slice(&0x0080_0000u32.to_le_bytes()); // Max transact / read / write: 8 MiB
    }
    body.extend_from_slice(&ntlm::filetime_now().to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes()); // Server start time
    body.extend_from_slice(&128u16.to_le_bytes()); // Security buffer offset (header + 64)
    body.extend_from_slice(&(security.len() as u16).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&security);
    body
}

/// An SMB2 error response body
fn error_body() -> Vec<u8> {
    vec![9, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn session_setup_body(security: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + security.len());
    body.extend_from_slice(&9u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // Session flags
    body.extend_from_slice(&72u16.to_le_bytes()); // Security buffer offset (header + 8)
    body.extend_from_slice(&(security.len() as u16).to_le_bytes());
    body.extend_from_slice(security);
    body
}

/// One SMB2 request -> its response; None closes the connection
fn smb2(message: &[u8], session: &mut Session, state: &mut State) -> Option<Vec<u8>> {
    if message.len() < 64 {
        return None;
    }
    let command = u16_at(message, 12);
    let credits = u16_at(message, 14);
    let message_id = u64_at(message, 24);
    let tree_id = u16_at(message, 36) as u32 | (u32::from(u16_at(message, 38)) << 16);
    let body = &message[64..];
    let reply = |status: u32, session_id: u64, body: &[u8]| Some(header(status, command, message_id, tree_id, session_id, credits, body));
    match command {
        NEGOTIATE => {
            let count = usize::from(u16_at(body, 2));
            let offered: Vec<u16> = (0..count.min(64)).map(|i| u16_at(body, 36 + 2 * i)).filter(|d| *d != 0).collect();
            let client_guid: String = body.get(12..28).unwrap_or_default().iter().map(|b| format!("{b:02x}")).collect();
            let chosen = DIALECTS.iter().copied().find(|d| offered.contains(d));
            let names: Vec<String> = offered.iter().map(|d| format!("{}.{}.{}", d >> 8, (d >> 4) & 0xf, d & 0xf)).collect();
            session.log("smb_negotiate", json!({ "dialects": names, "client_guid": client_guid, "chosen": chosen.map(|d| format!("{d:#06x}")) }));
            session.notify(message, json!({ "command": "NEGOTIATE", "dialects": names, "client_guid": client_guid }));
            match chosen {
                Some(dialect) => reply(STATUS_SUCCESS, 0, &negotiate_body(dialect, state)),
                None => reply(STATUS_NOT_SUPPORTED, 0, &error_body()),
            }
        }
        SESSION_SETUP => {
            let offset = usize::from(u16_at(body, 12));
            let length = usize::from(u16_at(body, 14));
            let security = message.get(offset..offset.saturating_add(length)).unwrap_or_default();
            match ntlm::find(security) {
                Some(token) if ntlm::message_type(token) == Some(1) => {
                    state.challenge = crate::tls::random_bytes();
                    let challenge = ntlm::challenge(token, state.challenge);
                    session.notify(token, json!({ "command": "SESSION_SETUP", "ntlm": "negotiate" }));
                    reply(STATUS_MORE_PROCESSING_REQUIRED, state.session_id, &session_setup_body(&ntlm::spnego_response(1, Some(&challenge))))
                }
                Some(token) if ntlm::message_type(token) == Some(3) => {
                    if let Some(authenticate) = ntlm::Authenticate::parse(token) {
                        let record = authenticate.record(&state.challenge);
                        session.log("credentials", record.clone());
                        session.notify(token, json!({ "command": "SESSION_SETUP", "ntlm": "authenticate", "credentials": record }));
                    }
                    reply(STATUS_LOGON_FAILURE, state.session_id, &error_body())
                }
                // Kerberos (or anything else) first: point the client at NTLM
                _ => reply(STATUS_MORE_PROCESSING_REQUIRED, state.session_id, &session_setup_body(&ntlm::spnego_response(1, None))),
            }
        }
        LOGOFF => reply(STATUS_SUCCESS, state.session_id, &[4, 0, 0, 0]),
        other => {
            session.log("smb_command", json!({ "command": other }));
            reply(STATUS_ACCESS_DENIED, state.session_id, &error_body())
        }
    }
}
