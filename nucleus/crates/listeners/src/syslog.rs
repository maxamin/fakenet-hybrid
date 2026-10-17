//! Syslog collector (RFC 5424 and BSD RFC 3164, over UDP, or TCP with RFC 6587 framing).
//! Each message is logged with its facility & severity and reported to the daemon (as an
//! event needing no reply). Never answers.

use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

use crate::session::Session;
use crate::stream::{read_line, BoxStream};

const MAX_MESSAGE: usize = 64 * 1024;
const SEVERITIES: [&str; 8] = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"];

fn record(message: &str, session: &mut Session) {
    let details = match fakenet_sniffer::syslog_priority(message) {
        Some((facility, severity, rest)) => json!({
            "facility": facility, "severity": SEVERITIES[severity as usize],
            "format": if rest.starts_with("1 ") { "rfc5424" } else { "rfc3164" }, "message": rest,
        }),
        None => json!({ "message": message }),
    };
    session.log("syslog_message", details.clone());
    session.notify(message.as_bytes(), details);
}

pub fn handle_udp(data: &[u8], session: &mut Session) -> Option<Vec<u8>> {
    session.client_data(data);
    record(String::from_utf8_lossy(data).trim_end(), session);
    None
}

/// RFC 6587: octet-counted ("LEN <PRI>...") or newline-delimited messages
pub async fn handle_tcp(stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let timeout = session.ctx.timeout;
    let mut conn = BufReader::new(stream);
    loop {
        let first = match tokio::time::timeout(timeout, conn.fill_buf()).await {
            Ok(Ok(buffer)) if !buffer.is_empty() => buffer[0],
            _ => return Ok(()),
        };
        if first.is_ascii_digit() {
            let mut length = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                conn.read_exact(&mut byte).await?;
                if byte[0] == b' ' {
                    break;
                }
                anyhow::ensure!(byte[0].is_ascii_digit() && length.len() <= 6, "invalid octet count");
                length.push(byte[0]);
            }
            let length: usize = String::from_utf8_lossy(&length).parse()?;
            anyhow::ensure!(length <= MAX_MESSAGE, "message too large");
            let mut message = vec![0u8; length];
            tokio::time::timeout(timeout, conn.read_exact(&mut message)).await??;
            session.client_data(&message);
            record(String::from_utf8_lossy(&message).trim_end(), &mut session);
        } else {
            let Some(line) = read_line(&mut conn, timeout).await? else { return Ok(()) };
            session.client_data(line.as_bytes());
            record(&line, &mut session);
        }
    }
}
