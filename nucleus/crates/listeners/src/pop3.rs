//! POP3 (RFC 1939, CAPA per RFC 2449, STLS per RFC 2595): accepts any login and serves one
//! fake message. Each command is an event (`meta.command`, `meta.argument`); a daemon
//! response replaces the whole reply, e.g. a scripted message for `RETR`.

use serde_json::json;

use crate::lines::{split_command, Lines};
use crate::session::Session;
use crate::stream::BoxStream;

pub const MESSAGE: &str = "From: FakeNet <fakenet@fakenet.local>\r\n\
To: user@fakenet.local\r\n\
Subject: FakeNet\r\n\
Date: Mon, 01 Jan 2001 00:00:00 +0000\r\n\
Message-ID: <1@fakenet.local>\r\n\
\r\n\
FakeNet message body.\r\n";

/// Dot-stuffing for multi-line responses (RFC 1939 3)
pub fn dot_stuffed(text: &str) -> String {
    text.split("\r\n").map(|line| if line.starts_with('.') { format!(".{line}") } else { line.to_string() }).collect::<Vec<_>>().join("\r\n")
}

/// The headers plus the first `lines` body lines (TOP)
fn top(lines: usize) -> String {
    let (headers, body) = MESSAGE.split_once("\r\n\r\n").unwrap_or((MESSAGE, ""));
    let body: Vec<&str> = body.split("\r\n").take(lines).collect();
    format!("{headers}\r\n\r\n{}", body.join("\r\n"))
}

pub async fn handle(stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let mut lines = Lines::new(stream);
    lines.send(&session, b"+OK FakeNet POP3 server ready\r\n").await?;
    let size = MESSAGE.len();
    let mut user: Option<String> = None;
    while let Some(line) = lines.read(&session).await? {
        let (verb, arg) = split_command(&line);
        let numbered = arg.split_whitespace().next() == Some("1");
        let mut close = false;
        let default = match verb.as_str() {
            "USER" => {
                user = Some(arg.clone());
                "+OK\r\n".to_string()
            }
            "PASS" => {
                session.log("credentials", json!({ "username": user, "password": arg }));
                "+OK Logged in\r\n".into()
            }
            "APOP" => {
                let (name, digest) = arg.split_once(' ').unwrap_or((&arg, ""));
                session.log("credentials", json!({ "username": name, "apop_digest": digest }));
                "+OK Logged in\r\n".into()
            }
            "CAPA" => {
                let stls = if session.builder.tls { "" } else { "STLS\r\n" };
                format!("+OK Capability list follows\r\nUSER\r\nUIDL\r\nTOP\r\n{stls}.\r\n")
            }
            "STLS" if !session.builder.tls => {
                lines.send(&session, b"+OK Begin TLS negotiation\r\n").await?;
                lines = lines.starttls(&mut session).await?;
                user = None;
                continue;
            }
            "STAT" => format!("+OK 1 {size}\r\n"),
            "LIST" if arg.is_empty() => format!("+OK 1 messages\r\n1 {size}\r\n.\r\n"),
            "UIDL" if arg.is_empty() => "+OK\r\n1 fakenet-1\r\n.\r\n".into(),
            "LIST" | "UIDL" | "RETR" | "TOP" | "DELE" if !numbered => "-ERR No such message\r\n".into(),
            "LIST" => format!("+OK 1 {size}\r\n"),
            "UIDL" => "+OK 1 fakenet-1\r\n".into(),
            "RETR" => format!("+OK {size} octets\r\n{}\r\n.\r\n", dot_stuffed(MESSAGE.trim_end_matches("\r\n"))),
            "TOP" => {
                let count = arg.split_whitespace().nth(1).and_then(|n| n.parse().ok()).unwrap_or(0);
                format!("+OK\r\n{}\r\n.\r\n", dot_stuffed(top(count).trim_end_matches("\r\n")))
            }
            "DELE" => "+OK Message deleted\r\n".into(),
            "NOOP" | "RSET" => "+OK\r\n".into(),
            "QUIT" => {
                close = true;
                "+OK Bye\r\n".into()
            }
            _ => "-ERR Unknown command\r\n".into(),
        };
        let meta = json!({ "command": verb, "argument": arg });
        if !lines.respond(&mut session, line.as_bytes(), meta, default, close).await? {
            return Ok(());
        }
    }
    Ok(())
}
