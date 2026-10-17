//! Line-oriented connections (SMTP, POP3, FTP, IRC): bounded line reads, sends that are
//! recorded in the pcap, daemon-or-default replies, and STARTTLS.

use std::io;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

use crate::session::Session;
use crate::stream::{read_line, read_raw_line, send, BoxStream};

pub struct Lines {
    conn: BufReader<BoxStream>,
}

impl Lines {
    pub fn new(stream: BoxStream) -> Lines {
        Lines { conn: BufReader::new(stream) }
    }

    /// The next line (without CRLF), or None at EOF/idle timeout
    pub async fn read(&mut self, session: &Session) -> io::Result<Option<String>> {
        let line = read_line(&mut self.conn, session.ctx.timeout).await?;
        if let Some(line) = &line {
            session.client_data(format!("{line}\r\n").as_bytes());
        }
        Ok(line)
    }

    /// The next line's raw bytes (for protocols with binary in-band data, like Telnet)
    pub async fn read_raw(&mut self, session: &Session) -> io::Result<Option<Vec<u8>>> {
        let line = read_raw_line(&mut self.conn, session.ctx.timeout).await?;
        if let Some(line) = &line {
            let mut recorded = line.clone();
            recorded.push(b'\n');
            session.client_data(&recorded);
        }
        Ok(line)
    }

    /// Exactly `length` bytes (binary framing: Redis bulk strings, SSH packets)
    pub async fn read_exact(&mut self, session: &Session, length: usize) -> anyhow::Result<Vec<u8>> {
        let mut data = vec![0u8; length];
        tokio::time::timeout(session.ctx.timeout, self.conn.read_exact(&mut data)).await??;
        session.client_data(&data);
        Ok(data)
    }

    pub async fn send(&mut self, session: &Session, data: &[u8]) -> io::Result<()> {
        send(&mut self.conn, data).await?;
        session.server_data(data);
        Ok(())
    }

    /// Answers one client step (`payload`: its line, or e.g. an uploaded file): the daemon's
    /// response or `default`. Returns false when the connection should now close (the
    /// daemon asked to, or `close` was set, e.g. QUIT).
    pub async fn respond(&mut self, session: &mut Session, payload: &[u8], meta: Value, default: String, close: bool) -> io::Result<bool> {
        let (reply, close) = session.answer(payload, meta, default.into_bytes(), close).await;
        if !reply.is_empty() {
            self.send(session, &reply).await?;
        }
        if close {
            let _ = self.conn.shutdown().await;
        }
        Ok(!close)
    }

    /// Upgrades to TLS after a STARTTLS/STLS reply. Anything the client pipelined before
    /// the handshake is discarded, never executed inside the TLS session (the CVE-2011-0411
    /// class of command injection).
    pub async fn starttls(self, session: &mut Session) -> anyhow::Result<Lines> {
        let pipelined = self.conn.buffer().len();
        if pipelined > 0 {
            session.log("starttls_injection_discarded", json!({ "bytes": pipelined }));
        }
        let tls = crate::dispatch::terminate_tls(self.conn.into_inner(), session).await?;
        session.builder.tls = true;
        Ok(Lines::new(tls))
    }
}

/// "VERB argument" -> ("VERB", "argument")
pub fn split_command(line: &str) -> (String, String) {
    match line.trim_start().split_once(' ') {
        Some((verb, arg)) => (verb.to_ascii_uppercase(), arg.trim().to_string()),
        None => (line.trim().to_ascii_uppercase(), String::new()),
    }
}

/// Printable preview of a payload for the event log
pub fn preview(data: &[u8], max: usize) -> String {
    let text: String = data[..data.len().min(max)].iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect();
    if data.len() > max { format!("{text}...") } else { text }
}
