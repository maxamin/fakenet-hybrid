//! IMAP4 (RFC 3501/9051, STARTTLS): accepts any login, serves one fake message. Each
//! command is an event (`meta.tag`, `meta.command`, `meta.argument`); a daemon response
//! replaces the whole reply (e.g. a scripted FETCH).

use serde_json::json;

use crate::lines::Lines;
use crate::pop3::MESSAGE;
use crate::session::Session;
use crate::stream::BoxStream;

/// IMAP arguments: atoms and "quoted strings" (with \\ escapes)
pub fn parse_arguments(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if c == '"' {
            chars.next();
            let mut value = String::new();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => value.extend(chars.next()),
                    '"' => break,
                    other => value.push(other),
                }
            }
            args.push(value);
        } else {
            let mut value = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                value.push(c);
                chars.next();
            }
            args.push(value);
        }
    }
    args
}

fn decode_plain(response: &str) -> Option<(String, String)> {
    let decoded = fakenet_schema::decode_base64(response.trim()).ok()?;
    let mut fields = decoded.split(|&b| b == 0).skip(1);
    Some((String::from_utf8_lossy(fields.next()?).into_owned(), String::from_utf8_lossy(fields.next()?).into_owned()))
}

pub async fn handle(stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let mut lines = Lines::new(stream);
    lines.send(&session, b"* OK [CAPABILITY IMAP4rev1 IMAP4rev2 STARTTLS AUTH=PLAIN] FakeNet IMAP ready\r\n").await?;
    while let Some(line) = lines.read(&session).await? {
        let mut parts = line.splitn(3, ' ');
        let tag = parts.next().unwrap_or("*").to_string();
        let mut command = parts.next().unwrap_or("").to_ascii_uppercase();
        let mut rest = parts.next().unwrap_or("").to_string();
        // UID FETCH etc. behave like their sequence-number versions here
        if command == "UID" {
            let mut inner = rest.splitn(2, ' ');
            command = inner.next().unwrap_or("").to_ascii_uppercase();
            rest = inner.next().unwrap_or("").to_string();
        }
        let mut close = false;
        let default = match command.as_str() {
            "CAPABILITY" => {
                let starttls = if session.builder.tls { "" } else { " STARTTLS" };
                format!("* CAPABILITY IMAP4rev1 IMAP4rev2{starttls} AUTH=PLAIN\r\n{tag} OK CAPABILITY completed\r\n")
            }
            "STARTTLS" if !session.builder.tls => {
                lines.send(&session, format!("{tag} OK Begin TLS negotiation now\r\n").as_bytes()).await?;
                lines = lines.starttls(&mut session).await?;
                continue;
            }
            "LOGIN" => {
                let args = parse_arguments(&rest);
                session.log("credentials", json!({ "username": args.first(), "password": args.get(1) }));
                format!("{tag} OK LOGIN completed\r\n")
            }
            "AUTHENTICATE" => {
                let mut args = rest.split_whitespace();
                if !args.next().is_some_and(|m| m.eq_ignore_ascii_case("PLAIN")) {
                    format!("{tag} NO Unsupported authentication mechanism\r\n")
                } else {
                    let response = match args.next() {
                        Some(initial) => initial.to_string(),
                        None => {
                            lines.send(&session, b"+ \r\n").await?;
                            lines.read(&session).await?.unwrap_or_default()
                        }
                    };
                    match decode_plain(&response) {
                        Some((username, password)) => {
                            session.log("credentials", json!({ "mechanism": "PLAIN", "username": username, "password": password }));
                            format!("{tag} OK AUTHENTICATE completed\r\n")
                        }
                        None => format!("{tag} BAD Invalid response\r\n"),
                    }
                }
            }
            "SELECT" | "EXAMINE" => format!(
                "* 1 EXISTS\r\n* 0 RECENT\r\n* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n\
                 * OK [UIDVALIDITY 1] UIDs valid\r\n* OK [UIDNEXT 2] Predicted next UID\r\n\
                 {tag} OK [{}] {command} completed\r\n",
                if command == "SELECT" { "READ-WRITE" } else { "READ-ONLY" }
            ),
            "LIST" | "LSUB" => format!("* {command} (\\HasNoChildren) \"/\" INBOX\r\n{tag} OK {command} completed\r\n"),
            "STATUS" => format!("* STATUS INBOX (MESSAGES 1 RECENT 0 UIDNEXT 2 UIDVALIDITY 1 UNSEEN 0)\r\n{tag} OK STATUS completed\r\n"),
            "FETCH" => fetch(&tag, &rest),
            "SEARCH" => format!("* SEARCH 1\r\n{tag} OK SEARCH completed\r\n"),
            "ID" => format!("* ID (\"name\" \"FakeNet\")\r\n{tag} OK ID completed\r\n"),
            "NOOP" | "CHECK" | "CLOSE" | "UNSELECT" | "EXPUNGE" | "STORE" | "COPY" | "CREATE" | "DELETE" | "RENAME"
            | "SUBSCRIBE" | "UNSUBSCRIBE" | "APPEND" | "ENABLE" => format!("{tag} OK {command} completed\r\n"),
            "LOGOUT" => {
                close = true;
                format!("* BYE FakeNet logging out\r\n{tag} OK LOGOUT completed\r\n")
            }
            _ => format!("{tag} BAD Unknown command\r\n"),
        };
        let meta = json!({ "tag": tag, "command": command, "argument": rest });
        if !lines.respond(&mut session, line.as_bytes(), meta, default, close).await? {
            return Ok(());
        }
    }
    Ok(())
}

/// A FETCH of message 1 with the items asked for (the whole message for any body item)
fn fetch(tag: &str, arguments: &str) -> String {
    let upper = arguments.to_ascii_uppercase();
    let mut items = vec!["UID 1".to_string(), "FLAGS (\\Seen)".to_string()];
    if ["RFC822.SIZE", "FAST", "ALL", "FULL"].iter().any(|i| upper.contains(i)) {
        items.push(format!("RFC822.SIZE {}", MESSAGE.len()));
    }
    let body_item = if upper.contains("RFC822.HEADER") {
        None
    } else if upper.contains("BODY.PEEK[") || upper.contains("BODY[") {
        Some("BODY[]")
    } else if upper.contains("RFC822") && !upper.contains("RFC822.SIZE") {
        Some("RFC822")
    } else {
        None
    };
    if let Some(item) = body_item {
        items.push(format!("{item} {{{}}}\r\n{MESSAGE}", MESSAGE.len()));
    }
    format!("* 1 FETCH ({})\r\n{tag} OK FETCH completed\r\n", items.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_arguments_and_fetches() {
        assert_eq!(parse_arguments(r#""al ice" "p\"w" atom"#), ["al ice", "p\"w", "atom"]);
        assert!(fetch("a", "1 (BODY.PEEK[])").contains(&format!("BODY[] {{{}}}", MESSAGE.len())));
        assert!(!fetch("a", "1 (FLAGS)").contains("BODY"));
    }
}
