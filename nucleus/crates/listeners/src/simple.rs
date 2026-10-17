//! The classic small services: echo (RFC 862), discard (863), daytime (867), chargen (864),
//! time (868), quote of the day (865), finger (1288) and whois (3912). Malware and scanners
//! still probe them. daytime, qotd, finger and whois ask the daemon (`meta.service`,
//! `meta.query`), whose response replaces the reply; the others answer by the RFC.

use std::time::{SystemTime, UNIX_EPOCH};

use fakenet_schema::Protocol;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::lines::{preview, Lines};
use crate::session::Session;
use crate::stream::BoxStream;

const QUOTE: &str = "\"The network is the computer.\" - John Gage\r\n";
/// Chargen streams forever per the RFC; stop after this much
const CHARGEN_MAX_BYTES: usize = 1 << 20;

/// "Weekday, Month Day, Year HH:MM:SS-UTC" (RFC 867 leaves the format free)
pub fn daytime_string(now: SystemTime) -> String {
    let format = time::macros::format_description!("[weekday], [month repr:long] [day padding:none], [year] [hour]:[minute]:[second]-UTC\r\n");
    time::OffsetDateTime::from(now).format(&format).unwrap_or_default()
}

/// Seconds since 1900, truncated to 32 bits (RFC 868)
pub fn rfc868_time(now: SystemTime) -> [u8; 4] {
    let unix = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    ((unix + 2_208_988_800) as u32).to_be_bytes()
}

/// Line `n` of the RFC 864 pattern: 72 of the 95 printable characters, shifted by one per line
pub fn chargen_line(n: usize) -> Vec<u8> {
    let mut line: Vec<u8> = (0..72).map(|i| b' ' + ((n + i) % 95) as u8).collect();
    line.extend_from_slice(b"\r\n");
    line
}

fn default_reply(protocol: Protocol, query: &str) -> Vec<u8> {
    match protocol {
        Protocol::Daytime => daytime_string(SystemTime::now()).into_bytes(),
        Protocol::Time => rfc868_time(SystemTime::now()).to_vec(),
        Protocol::Qotd => QUOTE.as_bytes().to_vec(),
        Protocol::Chargen => {
            let mut reply = Vec::new();
            let mut n = 0;
            while reply.len() + 74 <= 512 {
                reply.extend(chargen_line(n));
                n += 1;
            }
            reply
        }
        Protocol::Finger => {
            // "/W" asks for verbose output (RFC 1288 2.5.1); "user@host" asks us to forward
            let user = query.trim().trim_start_matches("/W").trim();
            if user.contains('@') {
                b"Finger forwarding service denied\r\n".to_vec()
            } else if user.is_empty() {
                b"Login     Name       Tty      Idle  Login Time   Office\r\nadmin     Administrator  pts/0  -     Jan  1 00:00\r\n".to_vec()
            } else {
                format!("Login: {user:<24}Name: {user}\r\nDirectory: /home/{user}\r\nNo mail.\r\nNo Plan.\r\n").into_bytes()
            }
        }
        Protocol::Whois => format!(
            "   Domain Name: {}\r\n   Registry Domain ID: FAKENET-1\r\n   Registrar: FakeNet Registrar\r\n   Creation Date: 2001-01-01T00:00:00Z\r\n   Name Server: NS1.FAKENET.LOCAL\r\n>>> Last update of whois database: now <<<\r\n",
            query.trim().to_ascii_uppercase()
        )
        .into_bytes(),
        _ => Vec::new(),
    }
}

fn asks_daemon(protocol: Protocol) -> bool {
    matches!(protocol, Protocol::Daytime | Protocol::Qotd | Protocol::Finger | Protocol::Whois)
}

pub async fn handle_tcp(mut stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let protocol = session.protocol();
    let timeout = session.ctx.timeout;
    match protocol {
        Protocol::Echo | Protocol::Discard => {
            let mut buffer = vec![0u8; 16 * 1024];
            let (mut total, mut first) = (0, Vec::new());
            loop {
                let read = match tokio::time::timeout(timeout, stream.read(&mut buffer)).await {
                    Err(_) | Ok(Ok(0)) => break,
                    Ok(result) => result?,
                };
                session.client_data(&buffer[..read]);
                if first.len() < 256 {
                    first.extend_from_slice(&buffer[..read.min(256 - first.len())]);
                }
                total += read;
                if protocol == Protocol::Echo {
                    stream.write_all(&buffer[..read]).await?;
                    session.server_data(&buffer[..read]);
                }
            }
            session.log(protocol.name(), json!({ "total_bytes": total, "text": preview(&first, 256) }));
            Ok(())
        }
        Protocol::Chargen => {
            session.log("chargen", json!({}));
            let (mut sent, mut n) = (0, 0);
            while sent < CHARGEN_MAX_BYTES {
                let line = chargen_line(n);
                if !matches!(tokio::time::timeout(timeout, stream.write_all(&line)).await, Ok(Ok(()))) {
                    break;
                }
                sent += line.len();
                n += 1;
            }
            Ok(())
        }
        _ => {
            // One query (finger/whois) or none (daytime/time/qotd), one reply, close
            let mut lines = Lines::new(stream);
            let query = if matches!(protocol, Protocol::Finger | Protocol::Whois) { lines.read(&session).await?.unwrap_or_default() } else { String::new() };
            session.log("query", json!({ "service": protocol.name(), "query": query }));
            let default = String::from_utf8_lossy(&default_reply(protocol, &query)).into_owned();
            if asks_daemon(protocol) {
                lines.respond(&mut session, query.as_bytes(), json!({ "service": protocol.name(), "query": query }), default, true).await?;
            } else {
                let reply = default_reply(protocol, &query);
                lines.send(&session, &reply).await?;
            }
            Ok(())
        }
    }
}

pub async fn handle_udp(data: &[u8], session: &mut Session) -> Option<Vec<u8>> {
    session.client_data(data);
    let protocol = session.protocol();
    session.log(protocol.name(), json!({ "bytes": data.len(), "text": preview(data, 256) }));
    let reply = match protocol {
        Protocol::Echo => data.to_vec(),
        Protocol::Discard => return None,
        p if asks_daemon(p) => {
            let default = default_reply(p, "");
            session.answer(data, json!({ "service": p.name(), "query": "" }), default, false).await.0
        }
        p => default_reply(p, ""),
    };
    session.server_data(&reply);
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_the_rfcs() {
        assert_eq!(chargen_line(0)[0], b' ');
        assert_eq!(chargen_line(1)[0], b'!');
        assert_eq!(chargen_line(0).len(), 74);
        let time = rfc868_time(UNIX_EPOCH);
        assert_eq!(u32::from_be_bytes(time), 2_208_988_800);
        assert_eq!(daytime_string(UNIX_EPOCH), "Thursday, January 1, 1970 00:00:00-UTC\r\n");
        assert!(String::from_utf8(default_reply(Protocol::Finger, "bob@elsewhere")).unwrap().contains("denied"));
    }
}
