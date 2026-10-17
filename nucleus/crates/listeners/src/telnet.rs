//! Telnet (RFC 854; ECHO 857, SUPPRESS-GO-AHEAD 858): a honeypot-style login prompt and
//! shell. IoT botnets (Mirai and descendants) brute-force Telnet logins, then probe the
//! shell, so credentials and commands are logged, and the classic busybox probe gets the
//! answer such bots expect. Each shell command is an event (`meta.command`); a daemon
//! response replaces its output.

use serde_json::json;

use crate::lines::Lines;
use crate::session::Session;
use crate::stream::BoxStream;

const IAC: u8 = 255;
const SB: u8 = 250;
const SE: u8 = 240;

/// Removes Telnet commands & option negotiation from a line, leaving its text
pub fn strip_commands(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] != IAC {
            if data[i] != b'\r' && data[i] != 0 {
                out.push(data[i]);
            }
            i += 1;
            continue;
        }
        match data.get(i + 1) {
            Some(&IAC) => {
                out.push(IAC); // An escaped literal 255
                i += 2;
            }
            Some(&SB) => {
                i += 2;
                while i < data.len() && !(data[i] == IAC && data.get(i + 1) == Some(&SE)) {
                    i += 1;
                }
                i += 2;
            }
            Some(251..=254) => i += 3, // WILL/WONT/DO/DONT + option
            _ => i += 2,
        }
    }
    out
}

pub fn shell_response(command: &str) -> String {
    let mut words = command.split_whitespace();
    match words.next().unwrap_or("") {
        "" => String::new(),
        // e.g. "/bin/busybox MIRAI": bots check for this exact error from real busybox
        cmd if cmd.ends_with("busybox") => match words.next() {
            Some(applet) => format!("{applet}: applet not found\r\n"),
            None => "BusyBox v1.30.1 multi-call binary.\r\n".into(),
        },
        "uname" => "Linux fakenet 5.4.0-150-generic #167-Ubuntu SMP x86_64 GNU/Linux\r\n".into(),
        "whoami" => "root\r\n".into(),
        "id" => "uid=0(root) gid=0(root) groups=0(root)\r\n".into(),
        "pwd" => "/root\r\n".into(),
        "echo" => format!("{}\r\n", words.collect::<Vec<_>>().join(" ")),
        "enable" | "system" | "shell" | "sh" | "cd" | "export" => String::new(),
        "ls" => "bin  dev  etc  home  lib  proc  root  tmp  usr  var\r\n".into(),
        other => format!("-sh: {other}: not found\r\n"),
    }
}

pub async fn handle(stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let banner = session.ctx.defaults.telnet.banner.clone();
    let mut lines = Lines::new(stream);
    // IAC WILL SUPPRESS-GO-AHEAD; echo is left to the client, so line-based bots work too
    lines.send(&session, &[IAC, 251, 3]).await?;
    lines.send(&session, format!("\r\n{banner}\r\nlogin: ").as_bytes()).await?;
    let text = |line: Vec<u8>| String::from_utf8_lossy(&strip_commands(&line)).trim().to_string();
    let Some(username) = lines.read_raw(&session).await?.map(text) else { return Ok(()) };
    lines.send(&session, b"Password: ").await?;
    let Some(password) = lines.read_raw(&session).await?.map(text) else { return Ok(()) };
    session.log("credentials", json!({ "username": username, "password": password }));
    lines.send(&session, b"\r\nWelcome!\r\n# ").await?;
    while let Some(line) = lines.read_raw(&session).await?.map(text) {
        // Bots chain commands with ; && ||: answer each part
        let parts: Vec<&str> = line.split([';', '&', '|']).map(str::trim).filter(|c| !c.is_empty()).collect();
        let exit = parts.iter().any(|c| matches!(*c, "exit" | "logout" | "quit"));
        let output: String = if exit { String::new() } else { parts.iter().map(|c| shell_response(c)).collect::<String>() + "# " };
        let meta = json!({ "command": line, "username": username });
        if !lines.respond(&mut session, line.as_bytes(), meta, output, exit).await? {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_negotiation_and_answers_bots() {
        assert_eq!(strip_commands(&[IAC, 253, 1, b'r', b'o', IAC, IAC, b'\r']), b"ro\xff");
        assert_eq!(shell_response("/bin/busybox MIRAI"), "MIRAI: applet not found\r\n");
        assert_eq!(shell_response("wget"), "-sh: wget: not found\r\n");
    }
}
