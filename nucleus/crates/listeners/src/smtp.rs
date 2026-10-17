//! SMTP (RFC 5321, STARTTLS per RFC 3207, AUTH PLAIN/LOGIN per RFC 4954): accepts every
//! message. Each command is an event (`meta.command`, `meta.argument`); a finished message
//! is an event with the message as payload (`meta.command = "MESSAGE"`, from/to/subject),
//! and is saved under files/. A daemon response replaces that step's reply.

use serde_json::json;

use crate::lines::{preview, split_command, Lines};
use crate::session::Session;
use crate::stream::BoxStream;

const MAX_MESSAGE: usize = 32 * 1024 * 1024;

#[derive(Default)]
struct Envelope {
    from: Option<String>,
    to: Vec<String>,
}

pub async fn handle(stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let hostname = session.ctx.defaults.mail.hostname.clone();
    let mut lines = Lines::new(stream);
    lines.send(&session, format!("220 {hostname} ESMTP FakeNet\r\n").as_bytes()).await?;

    let mut envelope = Envelope::default();
    while let Some(line) = lines.read(&session).await? {
        let (verb, arg) = split_command(&line);
        let meta = json!({ "command": verb, "argument": arg });
        let mut close = false;
        let default = match verb.as_str() {
            "HELO" => format!("250 {hostname}\r\n"),
            "EHLO" => {
                let mut caps = vec![hostname.clone(), "SIZE 33554432".into(), "8BITMIME".into(), "AUTH PLAIN LOGIN".into()];
                if !session.builder.tls {
                    caps.push("STARTTLS".into());
                }
                caps.push("HELP".into());
                let last = caps.len() - 1;
                caps.iter().enumerate().map(|(i, c)| format!("250{}{c}\r\n", if i == last { ' ' } else { '-' })).collect()
            }
            "STARTTLS" if !session.builder.tls => {
                lines.send(&session, b"220 Ready to start TLS\r\n").await?;
                lines = lines.starttls(&mut session).await?;
                envelope = Envelope::default(); // RFC 3207 4.2: forget everything
                continue;
            }
            "AUTH" => auth(&mut lines, &session, &arg).await?,
            "MAIL" => {
                envelope = Envelope { from: Some(address_argument(&arg)), to: Vec::new() };
                "250 OK\r\n".into()
            }
            "RCPT" if envelope.from.is_none() => "503 Need MAIL before RCPT\r\n".into(),
            "RCPT" => {
                envelope.to.push(address_argument(&arg));
                "250 OK\r\n".into()
            }
            "DATA" if envelope.to.is_empty() => "503 Need RCPT before DATA\r\n".into(),
            "DATA" => {
                lines.send(&session, b"354 End data with <CR><LF>.<CR><LF>\r\n").await?;
                let message = read_message(&mut lines, &session).await?;
                let meta = record_message(&session, &envelope, &message);
                envelope = Envelope::default();
                if !lines.respond(&mut session, &message, meta, "250 OK queued as FAKENET\r\n".into(), false).await? {
                    return Ok(());
                }
                // The message itself was the event; no separate one for the DATA line
                continue;
            }
            "RSET" => {
                envelope = Envelope::default();
                "250 OK\r\n".into()
            }
            "NOOP" => "250 OK\r\n".into(),
            "VRFY" | "EXPN" => "252 Cannot VRFY user, but will accept message\r\n".into(),
            "HELP" => "214 FakeNet SMTP\r\n".into(),
            "QUIT" => {
                close = true;
                "221 Bye\r\n".into()
            }
            _ => "500 Command not recognized\r\n".into(),
        };
        if !lines.respond(&mut session, line.as_bytes(), meta, default, close).await? {
            return Ok(());
        }
    }
    Ok(())
}

/// "FROM:<a@b> SIZE=1" -> "a@b"
fn address_argument(arg: &str) -> String {
    let after_colon = arg.split_once(':').map(|(_, rest)| rest).unwrap_or(arg);
    let address = after_colon.split_whitespace().next().unwrap_or("");
    address.trim_start_matches('<').trim_end_matches('>').to_string()
}

fn decode(text: &str) -> Option<String> {
    fakenet_schema::decode_base64(text.trim()).ok().map(|d| String::from_utf8_lossy(&d).into_owned())
}

/// The AUTH exchange; logs the credentials and returns the final reply
async fn auth(lines: &mut Lines, session: &Session, arg: &str) -> anyhow::Result<String> {
    let mut parts = arg.split_whitespace();
    let mechanism = parts.next().unwrap_or("").to_ascii_uppercase();
    let initial = parts.next().map(str::to_string);
    let credentials = match mechanism.as_str() {
        "PLAIN" => {
            let response = match initial {
                Some(response) if response != "=" => response,
                _ => {
                    lines.send(session, b"334 \r\n").await?;
                    lines.read(session).await?.unwrap_or_default()
                }
            };
            decode(&response).and_then(|plain| {
                let mut fields = plain.split('\0').skip(1); // authzid
                Some((fields.next()?.to_string(), fields.next()?.to_string()))
            })
        }
        "LOGIN" => {
            let user = match initial {
                Some(user) => user,
                None => {
                    lines.send(session, b"334 VXNlcm5hbWU6\r\n").await?; // "Username:"
                    lines.read(session).await?.unwrap_or_default()
                }
            };
            lines.send(session, b"334 UGFzc3dvcmQ6\r\n").await?; // "Password:"
            let password = lines.read(session).await?.unwrap_or_default();
            decode(&user).zip(decode(&password))
        }
        _ => return Ok("504 Unrecognized authentication type\r\n".into()),
    };
    Ok(match credentials {
        Some((username, password)) => {
            session.log("credentials", json!({ "mechanism": mechanism, "username": username, "password": password }));
            "235 Authentication successful\r\n".into()
        }
        None => "501 Malformed authentication response\r\n".into(),
    })
}

/// Reads DATA until the lone "." line, undoing dot-stuffing (RFC 5321 4.5.2)
async fn read_message(lines: &mut Lines, session: &Session) -> anyhow::Result<Vec<u8>> {
    let mut message = Vec::new();
    while let Some(line) = lines.read(session).await? {
        if line == "." {
            break;
        }
        let line = line.strip_prefix('.').unwrap_or(&line);
        anyhow::ensure!(message.len() + line.len() + 2 <= MAX_MESSAGE, "message too large");
        message.extend_from_slice(line.as_bytes());
        message.extend_from_slice(b"\r\n");
    }
    Ok(message)
}

/// Saves & logs a message; returns the event meta describing it
fn record_message(session: &Session, envelope: &Envelope, message: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(message);
    let subject = text
        .lines()
        .take_while(|l| !l.is_empty())
        .find_map(|l| l.split_once(':').filter(|(name, _)| name.eq_ignore_ascii_case("subject")).map(|(_, v)| v.trim().to_string()));
    let saved = session.ctx.capture.save_file("smtp", "message.eml", message).ok().map(|p| p.display().to_string());
    let meta = json!({
        "command": "MESSAGE", "from": envelope.from, "to": envelope.to, "subject": subject,
        "size": message.len(), "saved": saved,
    });
    let mut log = meta.clone();
    log["preview"] = json!(preview(message, 512));
    session.log("email", log);
    meta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_addresses() {
        assert_eq!(address_argument("FROM:<a@b.c> SIZE=12"), "a@b.c");
        assert_eq!(address_argument("TO: <x@y>"), "x@y");
    }
}
