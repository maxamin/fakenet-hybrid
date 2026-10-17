//! Redis (RESP). Exposed Redis servers are a common target: attackers write cron jobs or
//! SSH keys with CONFIG SET + SAVE, or load modules, so such commands are flagged as
//! suspicious. Each command is an event (`meta.command`, `meta.arguments`,
//! `meta.suspicious`); a daemon response replaces the RESP reply.

use serde_json::json;

use crate::lines::{preview, Lines};
use crate::session::Session;
use crate::stream::BoxStream;

const MAX_ARGS: usize = 1024;
const MAX_BULK: usize = 16 * 1024 * 1024;
/// Commands used to compromise Redis hosts (writing files, replication & module tricks)
const SUSPICIOUS: &[&str] = &["CONFIG", "SLAVEOF", "REPLICAOF", "MODULE", "EVAL", "EVALSHA", "SCRIPT", "FLUSHALL", "SAVE", "BGSAVE", "DEBUG", "MIGRATE"];

/// One command: a RESP array of bulk strings, or an inline command line
async fn read_command(lines: &mut Lines, session: &Session) -> anyhow::Result<Option<Vec<Vec<u8>>>> {
    let Some(line) = lines.read(session).await? else { return Ok(None) };
    let Some(count) = line.strip_prefix('*') else {
        return Ok(Some(line.split_whitespace().map(|w| w.as_bytes().to_vec()).collect()));
    };
    let count: usize = count.parse()?;
    anyhow::ensure!(count <= MAX_ARGS, "too many arguments");
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        let Some(header) = lines.read(session).await? else { anyhow::bail!("closed mid-command") };
        let length: usize = header.strip_prefix('$').ok_or_else(|| anyhow::anyhow!("expected a bulk string"))?.parse()?;
        anyhow::ensure!(length <= MAX_BULK, "bulk string too large");
        let mut value = lines.read_exact(session, length + 2).await?; // Plus CRLF
        value.truncate(length);
        args.push(value);
    }
    Ok(Some(args))
}

fn bulk(value: &str) -> String {
    format!("${}\r\n{value}\r\n", value.len())
}

pub async fn handle(stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let mut lines = Lines::new(stream);
    loop {
        let args = match read_command(&mut lines, &session).await {
            Ok(Some(args)) if !args.is_empty() => args,
            Ok(Some(_)) => continue,
            Ok(None) => return Ok(()),
            Err(e) => {
                lines.send(&session, format!("-ERR Protocol error: {e}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };
        let command = String::from_utf8_lossy(&args[0]).to_ascii_uppercase();
        let text_args: Vec<String> = args[1..].iter().map(|a| preview(a, 256)).collect();
        let suspicious = SUSPICIOUS.contains(&command.as_str());
        let arg = |i: usize| text_args.get(i).cloned().unwrap_or_default();
        let mut close = false;
        let default = match command.as_str() {
            "PING" if text_args.is_empty() => "+PONG\r\n".into(),
            "PING" | "ECHO" => bulk(&arg(0)),
            "AUTH" => {
                let (username, password) = if text_args.len() >= 2 { (Some(arg(0)), arg(1)) } else { (None, arg(0)) };
                session.log("credentials", json!({ "username": username, "password": password }));
                "+OK\r\n".into()
            }
            "INFO" => bulk("# Server\r\nredis_version:6.0.16\r\nredis_mode:standalone\r\nos:Linux 5.4.0 x86_64\r\n# Replication\r\nrole:master\r\nconnected_slaves:0\r\n"),
            "CONFIG" if arg(0).eq_ignore_ascii_case("GET") => format!("*2\r\n{}{}", bulk(&arg(1)), bulk("")),
            "GET" | "HGET" | "LPOP" | "RPOP" => "$-1\r\n".into(),
            "KEYS" | "SCAN" | "COMMAND" | "SMEMBERS" | "LRANGE" | "HGETALL" => "*0\r\n".into(),
            "DBSIZE" | "EXISTS" | "DEL" | "LLEN" | "INCR" => ":0\r\n".into(),
            "QUIT" => {
                close = true;
                "+OK\r\n".into()
            }
            "SET" | "SELECT" | "CONFIG" | "SLAVEOF" | "REPLICAOF" | "SAVE" | "BGSAVE" | "FLUSHALL" | "FLUSHDB" | "CLIENT"
            | "MODULE" | "HSET" | "LPUSH" | "RPUSH" | "EXPIRE" => "+OK\r\n".into(),
            _ => format!("-ERR unknown command '{}'\r\n", command.to_ascii_lowercase()),
        };
        if suspicious {
            session.log("suspicious_command", json!({ "command": command, "arguments": text_args }));
        }
        let meta = json!({ "command": command, "arguments": text_args, "suspicious": suspicious });
        let payload = args.join(&b' ');
        if !lines.respond(&mut session, &payload, meta, default, close).await? {
            return Ok(());
        }
    }
}
