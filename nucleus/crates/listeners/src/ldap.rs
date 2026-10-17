//! LDAP (RFC 4511) as a domain controller a sample might query: binds are captured (simple
//! binds' DN & password; NTLM by Microsoft's Sicily bind or SASL GSS-SPNEGO, as a crackable
//! hash), searches are logged with their filter rendered as text, the root DSE describes a
//! plausible domain, and other searches find nothing. StartTLS upgrades the connection.
//! Every operation also goes to the daemon as an event.

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::ntlm;
use crate::session::Session;
use crate::stream::BoxStream;

const MAX_MESSAGE: usize = 1 << 20;
const MAX_DEPTH: usize = 32;

const SUCCESS: u8 = 0;
const SASL_BIND_IN_PROGRESS: u8 = 14;
const INVALID_CREDENTIALS: u8 = 49;
const UNWILLING_TO_PERFORM: u8 = 53;
const PROTOCOL_ERROR: u8 = 2;

const START_TLS: &str = "1.3.6.1.4.1.1466.20037";

/// A BER element: (tag, contents)
type Element<'a> = (u8, &'a [u8]);

/// Splits one element off the front of `data`
fn element(data: &[u8]) -> Option<(Element<'_>, &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = match first {
        n if n < 0x80 => (usize::from(n), rest),
        0x81..=0x84 => {
            let count = usize::from(first & 0x7f);
            let bytes = rest.get(..count)?;
            (bytes.iter().fold(0usize, |n, b| (n << 8) | usize::from(*b)), &rest[count..])
        }
        _ => return None,
    };
    let contents = rest.get(..length)?;
    Some(((tag, contents), &rest[length..]))
}

/// All the elements in a constructed value
fn elements(mut data: &[u8]) -> Vec<Element<'_>> {
    let mut out = Vec::new();
    while let Some((e, rest)) = element(data) {
        out.push(e);
        data = rest;
    }
    out
}

fn integer(bytes: &[u8]) -> i64 {
    bytes.iter().take(8).fold(if bytes.first().is_some_and(|b| b & 0x80 != 0) { -1 } else { 0 }, |n, b| (n << 8) | i64::from(*b))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Escapes a value inside a rendered filter (RFC 4515)
fn escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for c in String::from_utf8_lossy(bytes).chars() {
        match c {
            '*' | '(' | ')' | '\\' | '\0' => out.push_str(&format!("\\{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A search filter as RFC 4515 text, e.g. "(&(objectClass=user)(sAMAccountName=adm*))"
pub fn render_filter(filter: Element<'_>, depth: usize) -> String {
    if depth > MAX_DEPTH {
        return "(…)".into();
    }
    let (tag, contents) = filter;
    let pair = || {
        let parts = elements(contents);
        (parts.first().map(|p| text(p.1)).unwrap_or_default(), parts.get(1).map(|p| escape(p.1)).unwrap_or_default())
    };
    match tag {
        0xa0 | 0xa1 => {
            let op = if tag == 0xa0 { '&' } else { '|' };
            format!("({op}{})", elements(contents).into_iter().map(|f| render_filter(f, depth + 1)).collect::<String>())
        }
        0xa2 => format!("(!{})", elements(contents).first().map(|f| render_filter(*f, depth + 1)).unwrap_or_default()),
        0xa3 => {
            let (attribute, value) = pair();
            format!("({attribute}={value})")
        }
        0xa4 => {
            let parts = elements(contents);
            let attribute = parts.first().map(|p| text(p.1)).unwrap_or_default();
            let (mut initial, mut any, mut last) = (String::new(), Vec::new(), String::new());
            for (kind, value) in parts.get(1).map(|p| elements(p.1)).unwrap_or_default() {
                match kind {
                    0x80 => initial = escape(value),
                    0x81 => any.push(escape(value)),
                    _ => last = escape(value),
                }
            }
            let middle: String = any.iter().map(|a| format!("{a}*")).collect();
            format!("({attribute}={initial}*{middle}{last})")
        }
        0xa5 | 0xa6 | 0xa8 => {
            let (attribute, value) = pair();
            let op = match tag {
                0xa5 => ">=",
                0xa6 => "<=",
                _ => "~=",
            };
            format!("({attribute}{op}{value})")
        }
        0x87 => format!("({}=*)", text(contents)),
        _ => "(?)".into(),
    }
}

/// An LDAP message: SEQUENCE { messageID, protocolOp }
fn message(id: i64, op: Vec<u8>) -> Vec<u8> {
    let id_bytes = {
        let bytes = id.to_be_bytes();
        let skip = bytes.iter().take(7).take_while(|b| **b == 0).count();
        // Keep a leading zero when the next byte's high bit is set (a positive INTEGER)
        let skip = if bytes[skip] & 0x80 != 0 && skip > 0 { skip - 1 } else { skip };
        bytes[skip..].to_vec()
    };
    ntlm::der(0x30, &[ntlm::der(0x02, &id_bytes), op].concat())
}

/// An LDAPResult-shaped response with application tag `tag`, plus `extra` fields
fn result(tag: u8, code: u8, matched: &[u8], diagnostic: &str, extra: &[u8]) -> Vec<u8> {
    ntlm::der(tag, &[ntlm::der(0x0a, &[code]), ntlm::der(0x04, matched), ntlm::der(0x04, diagnostic.as_bytes()), extra.to_vec()].concat())
}

/// The root DSE: what clients read first to find the domain
fn root_dse() -> Vec<u8> {
    let attribute = |name: &str, values: &[&str]| {
        let values: Vec<u8> = values.iter().flat_map(|v| ntlm::der(0x04, v.as_bytes())).collect();
        ntlm::der(0x30, &[ntlm::der(0x04, name.as_bytes()), ntlm::der(0x31, &values)].concat())
    };
    let base = "DC=fakenet,DC=local";
    let attributes = [
        attribute("defaultNamingContext", &[base]),
        attribute("rootDomainNamingContext", &[base]),
        attribute("namingContexts", &[base, "CN=Configuration,DC=fakenet,DC=local", "CN=Schema,CN=Configuration,DC=fakenet,DC=local"]),
        attribute("dnsHostName", &["filesrv01.fakenet.local"]),
        attribute("serverName", &["CN=FILESRV01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=fakenet,DC=local"]),
        attribute("supportedLDAPVersion", &["3", "2"]),
        attribute("supportedSASLMechanisms", &["GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"]),
        attribute("supportedCapabilities", &["1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670", "1.2.840.113556.1.4.1791"]),
        attribute("domainFunctionality", &["7"]),
        attribute("forestFunctionality", &["7"]),
        attribute("domainControllerFunctionality", &["7"]),
        attribute("isGlobalCatalogReady", &["TRUE"]),
    ]
    .concat();
    ntlm::der(0x64, &[ntlm::der(0x04, b""), ntlm::der(0x30, &attributes)].concat())
}

pub async fn handle(mut stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let mut challenge = [0u8; 8];
    loop {
        let Some(data) = read_message(&mut stream, &session).await? else { return Ok(()) };
        session.client_data(&data);
        let Some(((0x30, contents), _)) = element(&data) else { return Ok(()) };
        let parts = elements(contents);
        let (Some(&(0x02, id)), Some(&(op, body))) = (parts.first(), parts.get(1)) else { return Ok(()) };
        let id = integer(id);
        let fields = elements(body);
        let mut replies = Vec::new();
        let mut start_tls = false;
        let meta = match op {
            // BindRequest: version, name, authentication
            0x60 => {
                let name = fields.get(1).map(|f| text(f.1)).unwrap_or_default();
                let (kind, credentials) = fields.get(2).copied().unwrap_or((0x80, &[]));
                let (code, matched, sasl, mechanism): (u8, Vec<u8>, Option<Vec<u8>>, String) = match kind {
                    // Simple: the password in the clear
                    0x80 => {
                        let password = text(credentials);
                        if !name.is_empty() || !password.is_empty() {
                            session.log("credentials", json!({ "mechanism": "LDAP simple bind", "username": name, "password": password }));
                        }
                        (SUCCESS, Vec::new(), None, "simple".into())
                    }
                    // Sicily package discovery, then NTLM negotiate (our challenge goes back
                    // in matchedDN), then the response
                    0x89 => (SUCCESS, b"NTLM".to_vec(), None, "sicily".into()),
                    0x8a => {
                        challenge = crate::tls::random_bytes();
                        (SUCCESS, ntlm::challenge(credentials, challenge), None, "sicily NTLM".into())
                    }
                    0x8b => {
                        capture_ntlm(&mut session, credentials, &challenge);
                        (INVALID_CREDENTIALS, Vec::new(), None, "sicily NTLM".into())
                    }
                    // SASL: NTLM inside GSS-SPNEGO (or plain NTLM)
                    0xa3 => {
                        let sasl = elements(credentials);
                        let mechanism = sasl.first().map(|m| text(m.1)).unwrap_or_default();
                        let token = sasl.get(1).map(|c| c.1).unwrap_or_default();
                        match ntlm::find(token) {
                            Some(token) if ntlm::message_type(token) == Some(1) => {
                                challenge = crate::tls::random_bytes();
                                let reply = ntlm::challenge(token, challenge);
                                let reply = if mechanism.eq_ignore_ascii_case("GSS-SPNEGO") { ntlm::spnego_response(1, Some(&reply)) } else { reply };
                                (SASL_BIND_IN_PROGRESS, Vec::new(), Some(reply), mechanism)
                            }
                            Some(token) => {
                                capture_ntlm(&mut session, token, &challenge);
                                (INVALID_CREDENTIALS, Vec::new(), None, mechanism)
                            }
                            None => (INVALID_CREDENTIALS, Vec::new(), None, mechanism),
                        }
                    }
                    _ => (UNWILLING_TO_PERFORM, Vec::new(), None, format!("{kind:#04x}")),
                };
                let extra = sasl.map(|s| ntlm::der(0x87, &s)).unwrap_or_default();
                replies.push(message(id, result(0x61, code, &matched, "", &extra)));
                json!({ "operation": "bind", "name": name, "mechanism": mechanism, "result": code })
            }
            // SearchRequest: base, scope, deref, size & time limits, typesOnly, filter, attributes
            0x63 => {
                let base = fields.first().map(|f| text(f.1)).unwrap_or_default();
                let scope = fields.get(1).map(|f| integer(f.1)).unwrap_or(0);
                let filter = fields.get(6).map(|f| render_filter(*f, 0)).unwrap_or_default();
                let attributes: Vec<String> = fields.get(7).map(|a| elements(a.1).iter().map(|v| text(v.1)).collect()).unwrap_or_default();
                session.log("ldap_search", json!({ "base": base, "scope": scope, "filter": filter, "attributes": attributes }));
                if base.is_empty() && scope == 0 {
                    replies.push(message(id, root_dse()));
                }
                replies.push(message(id, result(0x65, SUCCESS, b"", "", &[])));
                json!({ "operation": "search", "base": base, "scope": scope, "filter": filter, "attributes": attributes })
            }
            // ExtendedRequest: StartTLS, or anything else (unsupported)
            0x77 => {
                let name = fields.first().map(|f| text(f.1)).unwrap_or_default();
                start_tls = name == START_TLS;
                let code = if start_tls { SUCCESS } else { PROTOCOL_ERROR };
                replies.push(message(id, result(0x78, code, b"", "", &ntlm::der(0x8a, name.as_bytes()))));
                json!({ "operation": "extended", "name": name })
            }
            0x42 => {
                session.notify(&data, json!({ "operation": "unbind" }));
                return Ok(());
            }
            0x50 => json!({ "operation": "abandon" }),
            // Modify, add, delete, modify DN, compare: accepted (and logged)
            0x66 | 0x68 | 0x4a | 0x6c | 0x6e => {
                let target = match op {
                    0x4a => text(body),
                    _ => fields.first().map(|f| text(f.1)).unwrap_or_default(),
                };
                let operation = match op {
                    0x66 => "modify",
                    0x68 => "add",
                    0x4a => "delete",
                    0x6c => "modify DN",
                    _ => "compare",
                };
                session.log("ldap_change", json!({ "operation": operation, "dn": target }));
                // Compare answers compareFalse (5)
                replies.push(message(id, result(op + 1, if op == 0x6e { 5 } else { SUCCESS }, b"", "", &[])));
                json!({ "operation": operation, "dn": target })
            }
            _ => {
                replies.push(message(id, result(0x61, PROTOCOL_ERROR, b"", "unsupported operation", &[])));
                json!({ "operation": format!("{op:#04x}") })
            }
        };
        session.notify(&data, meta);
        for reply in &replies {
            stream.write_all(reply).await?;
            session.server_data(reply);
        }
        if start_tls {
            stream = crate::dispatch::terminate_tls(stream, &mut session).await?;
        }
    }
}

fn capture_ntlm(session: &mut Session, token: &[u8], challenge: &[u8; 8]) {
    if let Some(authenticate) = ntlm::find(token).and_then(ntlm::Authenticate::parse) {
        session.log("credentials", authenticate.record(challenge));
    }
}

/// One whole LDAP message (a BER SEQUENCE)
async fn read_message(stream: &mut BoxStream, session: &Session) -> anyhow::Result<Option<Vec<u8>>> {
    let mut head = [0u8; 2];
    match tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut head)).await {
        Err(_) => return Ok(None),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Ok(result) => result?,
    };
    anyhow::ensure!(head[0] == 0x30, "not an LDAP message");
    let mut data = head.to_vec();
    let length = match head[1] {
        n if n < 0x80 => usize::from(n),
        n @ 0x81..=0x84 => {
            let mut bytes = vec![0u8; usize::from(n & 0x7f)];
            tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut bytes)).await??;
            data.extend_from_slice(&bytes);
            bytes.iter().fold(0usize, |n, b| (n << 8) | usize::from(*b))
        }
        _ => anyhow::bail!("bad BER length"),
    };
    anyhow::ensure!(length <= MAX_MESSAGE, "LDAP message too large");
    let start = data.len();
    data.resize(start + length, 0);
    tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut data[start..])).await??;
    Ok(Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_filters() {
        // (&(objectClass=user)(|(sAMAccountName=adm*)(!(cn=x\29)))(mail=*))
        let filter = ntlm::der(
            0xa0,
            &[
                ntlm::der(0xa3, &[ntlm::der(0x04, b"objectClass"), ntlm::der(0x04, b"user")].concat()),
                ntlm::der(
                    0xa1,
                    &[
                        ntlm::der(0xa4, &[ntlm::der(0x04, b"sAMAccountName"), ntlm::der(0x30, &ntlm::der(0x80, b"adm"))].concat()),
                        ntlm::der(0xa2, &ntlm::der(0xa3, &[ntlm::der(0x04, b"cn"), ntlm::der(0x04, b"x)")].concat())),
                    ]
                    .concat(),
                ),
                ntlm::der(0x87, b"mail"),
            ]
            .concat(),
        );
        let (parsed, _) = element(&filter).unwrap();
        assert_eq!(render_filter(parsed, 0), "(&(objectClass=user)(|(sAMAccountName=adm*)(!(cn=x\\29)))(mail=*))");
    }

    #[test]
    fn deep_or_broken_filters_are_bounded() {
        let mut filter = ntlm::der(0x87, b"x");
        for _ in 0..100 {
            filter = ntlm::der(0xa2, &filter);
        }
        let (parsed, _) = element(&filter).unwrap();
        assert!(render_filter(parsed, 0).contains('…'));
        assert!(element(&[0x30, 0x85, 1, 2, 3, 4, 5]).is_none());
        assert!(element(&[0x30, 0x05, 1]).is_none());
    }

    #[test]
    fn message_ids_are_positive_integers() {
        assert_eq!(message(1, vec![]), [0x30, 0x03, 0x02, 0x01, 0x01]);
        assert_eq!(message(200, vec![]), [0x30, 0x04, 0x02, 0x02, 0x00, 0xc8]);
        assert_eq!(integer(&[0x00, 0xc8]), 200);
    }
}
