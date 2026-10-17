//! FTP (RFC 959, EPSV/EPRT per RFC 2428): accepts any login. Each command is an event
//! (`meta.command`, `meta.argument`) whose daemon response replaces the reply, except:
//! - RETR: `meta.file = true`; the response is the file's content (default: the file from
//!   `defaults.ftp.root`, else a default file of the requested type)
//! - STOR/APPE/STOU: the uploaded data is the payload, saved under files/; the response
//!   replaces the final 226 reply.
//! Data connections: passive (on the configured port range) or active, but only to the
//! client's own address (no FTP bounce).

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::http::{default_content, safe_join};
use crate::lines::{preview, split_command, Lines};
use crate::session::Session;
use crate::stream::BoxStream;

const MAX_UPLOAD: usize = 64 * 1024 * 1024;

enum DataChannel {
    None,
    Passive(TcpListener),
    Active(SocketAddr),
}

struct Ftp {
    cwd: String,
    user: Option<String>,
    data: DataChannel,
    rename_from: Option<String>,
    root: Option<PathBuf>,
}

pub async fn handle(stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let defaults = session.ctx.defaults.load().ftp.clone();
    let mut lines = Lines::new(stream);
    lines.send(&session, format!("220 {}\r\n", defaults.banner).as_bytes()).await?;
    let mut ftp = Ftp { cwd: "/".into(), user: None, data: DataChannel::None, rename_from: None, root: defaults.root };

    while let Some(line) = lines.read(&session).await? {
        let (verb, arg) = split_command(&line);
        let meta = json!({ "command": verb, "argument": arg });
        let default = match verb.as_str() {
            "USER" => {
                ftp.user = Some(arg.clone());
                "331 Password required\r\n".to_string()
            }
            "PASS" => {
                session.log("credentials", json!({ "username": ftp.user, "password": arg }));
                "230 Login successful\r\n".into()
            }
            "ACCT" => "230 Account accepted\r\n".into(),
            "SYST" => "215 UNIX Type: L8\r\n".into(),
            "FEAT" => "211-Features:\r\n EPSV\r\n EPRT\r\n PASV\r\n SIZE\r\n MDTM\r\n REST STREAM\r\n UTF8\r\n211 End\r\n".into(),
            "OPTS" | "TYPE" | "MODE" | "STRU" | "ALLO" => "200 OK\r\n".into(),
            "PWD" | "XPWD" => format!("257 \"{}\" is the current directory\r\n", ftp.cwd),
            "CWD" | "XCWD" => {
                ftp.cwd = resolve_virtual(&ftp.cwd, &arg);
                "250 Directory changed\r\n".into()
            }
            "CDUP" | "XCUP" => {
                ftp.cwd = resolve_virtual(&ftp.cwd, "..");
                "250 Directory changed\r\n".into()
            }
            "NOOP" => "200 NOOP ok\r\n".into(),
            "HELP" => "214 Help OK\r\n".into(),
            "STAT" => "211 FTP server status: OK\r\n".into(),
            "SITE" => "200 SITE command ok\r\n".into(),
            "REST" => "350 Restarting\r\n".into(),
            "ABOR" => "226 Abort successful\r\n".into(),
            "REIN" => {
                ftp.user = None;
                "220 Service ready for new user\r\n".into()
            }
            "MKD" | "XMKD" => format!("257 \"{}\" created\r\n", resolve_virtual(&ftp.cwd, &arg)),
            "RMD" | "XRMD" | "DELE" => "250 Requested file action okay\r\n".into(),
            "RNFR" => {
                ftp.rename_from = Some(arg.clone());
                "350 Ready for RNTO\r\n".into()
            }
            "RNTO" => {
                session.log("rename", json!({ "from": ftp.rename_from.take(), "to": arg }));
                "250 Rename successful\r\n".into()
            }
            "SIZE" => format!("213 {}\r\n", ftp.file_contents(&arg).len()),
            "MDTM" => "213 20010101000000\r\n".into(),
            "PASV" => ftp.passive(&session, false).await,
            "EPSV" => ftp.passive(&session, true).await,
            "PORT" => ftp.active(&session, parse_port_argument(&arg)),
            "EPRT" => ftp.active(&session, parse_eprt_argument(&arg)),
            "LIST" | "NLST" | "MLSD" => {
                let listing = ftp.listing(verb == "NLST");
                ftp.transfer_out(&mut lines, &session, listing.as_bytes(), "Directory send OK").await?
            }
            "RETR" => {
                let path = resolve_virtual(&ftp.cwd, &arg);
                let meta = json!({ "command": verb, "argument": arg, "path": path, "file": true });
                let (contents, _) = session.answer(line.as_bytes(), meta, ftp.file_contents(&arg), false).await;
                session.log("download", json!({ "path": path, "size": contents.len() }));
                let reply = ftp.transfer_out(&mut lines, &session, &contents, "Transfer complete").await?;
                lines.send(&session, reply.as_bytes()).await?;
                continue;
            }
            "STOR" | "APPE" | "STOU" => {
                let (reply, upload) = ftp.receive(&mut lines, &session, &arg).await?;
                let Some(upload) = upload else {
                    lines.send(&session, reply.as_bytes()).await?;
                    continue;
                };
                let saved = session.ctx.capture.save_file("ftp", &arg, &upload).ok().map(|p| p.display().to_string());
                session.log("upload", json!({ "name": arg, "size": upload.len(), "saved": saved, "preview": preview(&upload, 256) }));
                let meta = json!({ "command": verb, "argument": arg, "size": upload.len(), "saved": saved });
                if !lines.respond(&mut session, &upload, meta, reply, false).await? {
                    return Ok(());
                }
                continue;
            }
            "QUIT" => {
                lines.respond(&mut session, line.as_bytes(), meta, "221 Goodbye\r\n".into(), true).await?;
                return Ok(());
            }
            _ => "502 Command not implemented\r\n".into(),
        };
        if !lines.respond(&mut session, line.as_bytes(), meta, default, false).await? {
            return Ok(());
        }
    }
    Ok(())
}

impl Ftp {
    async fn passive(&mut self, session: &Session, extended: bool) -> String {
        // Advertise the address the client connected to (the original destination after a
        // REDIRECT; the diverter must send the passive port range back to us unchanged)
        let advertised = session.builder.dst.ip();
        if !extended && !advertised.is_ipv4() {
            return "425 Use EPSV with IPv6\r\n".into();
        }
        let (first, last) = session.ctx.defaults.load().ftp.passive_ports;
        let ports = (first != 0).then(|| first..=last.max(first)).into_iter().flatten().chain(std::iter::once(0));
        let mut listener = None;
        for port in ports {
            if let Ok(bound) = TcpListener::bind(SocketAddr::new(session.local.ip(), port)).await {
                listener = Some(bound);
                break;
            }
        }
        let Some(listener) = listener else { return "425 Can't open data connection\r\n".into() };
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        self.data = DataChannel::Passive(listener);
        match advertised {
            IpAddr::V4(v4) if !extended => {
                let [a, b, c, d] = v4.octets();
                format!("227 Entering Passive Mode ({a},{b},{c},{d},{},{})\r\n", port >> 8, port & 0xff)
            }
            _ => format!("229 Entering Extended Passive Mode (|||{port}|)\r\n"),
        }
    }

    fn active(&mut self, session: &Session, target: Option<SocketAddr>) -> String {
        match target {
            Some(address) if address.ip() == session.builder.src.ip() => {
                self.data = DataChannel::Active(address);
                "200 Active data connection ready\r\n".into()
            }
            Some(_) => "504 Data connections are only allowed to the client's own address\r\n".into(),
            None => "501 Invalid address\r\n".into(),
        }
    }

    async fn open_data(&mut self, session: &Session) -> Option<TcpStream> {
        let timeout = session.ctx.timeout;
        match std::mem::replace(&mut self.data, DataChannel::None) {
            DataChannel::Passive(listener) => tokio::time::timeout(timeout, listener.accept()).await.ok()?.ok().map(|(s, _)| s),
            DataChannel::Active(address) => tokio::time::timeout(timeout, TcpStream::connect(address)).await.ok()?.ok(),
            DataChannel::None => None,
        }
    }

    /// Sends data on the data connection; returns the final control reply
    async fn transfer_out(&mut self, lines: &mut Lines, session: &Session, data: &[u8], done: &str) -> anyhow::Result<String> {
        lines.send(session, b"150 Opening data connection\r\n").await?;
        let Some(mut channel) = self.open_data(session).await else {
            return Ok("425 Can't open data connection\r\n".into());
        };
        channel.write_all(data).await?;
        channel.shutdown().await?;
        Ok(format!("226 {done}\r\n"))
    }

    /// Receives an upload; returns the final control reply and the data (None on failure)
    async fn receive(&mut self, lines: &mut Lines, session: &Session, name: &str) -> anyhow::Result<(String, Option<Vec<u8>>)> {
        lines.send(session, b"150 Ok to send data\r\n").await?;
        let Some(mut channel) = self.open_data(session).await else {
            return Ok(("425 Can't open data connection\r\n".into(), None));
        };
        let mut contents = Vec::new();
        let mut held = session.ctx.limits.hold();
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = match tokio::time::timeout(session.ctx.timeout, channel.read(&mut buffer)).await {
                Err(_) | Ok(Ok(0)) => break,
                Ok(result) => result?,
            };
            if contents.len() + read > MAX_UPLOAD || held.grow(read).is_err() {
                session.log("upload_too_large", json!({ "name": name }));
                return Ok(("552 Upload too large\r\n".into(), None));
            }
            contents.extend_from_slice(&buffer[..read]);
        }
        Ok(("226 Transfer complete\r\n".into(), Some(contents)))
    }

    fn file_contents(&self, name: &str) -> Vec<u8> {
        default_content(&resolve_virtual(&self.cwd, name), self.root.as_deref()).0
    }

    fn listing(&self, names_only: bool) -> String {
        let directory = self.root.as_deref().and_then(|root| safe_join(root, &self.cwd)).filter(|d| d.is_dir());
        let mut entries: Vec<(String, bool, u64)> = match directory {
            Some(directory) => std::fs::read_dir(directory)
                .map(|dir| dir.flatten().map(|e| {
                    let metadata = e.metadata().ok();
                    (e.file_name().to_string_lossy().into_owned(), metadata.as_ref().is_some_and(|m| m.is_dir()), metadata.map(|m| m.len()).unwrap_or(0))
                }).collect())
                .unwrap_or_default(),
            None => vec![("readme.txt".into(), false, 1024)],
        };
        entries.sort();
        entries
            .into_iter()
            .map(|(name, is_dir, size)| {
                if names_only {
                    format!("{name}\r\n")
                } else {
                    format!("{} 1 ftp ftp {size:>12} Jan 01 2001 {name}\r\n", if is_dir { "drwxr-xr-x" } else { "-rw-r--r--" })
                }
            })
            .collect()
    }
}

/// A virtual path (never touches the filesystem): "/a/b" + "../c" -> "/a/c"
pub fn resolve_virtual(cwd: &str, path: &str) -> String {
    let mut parts: Vec<&str> = if path.starts_with('/') { vec![] } else { cwd.split('/').filter(|p| !p.is_empty()).collect() };
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("/{}", parts.join("/"))
}

pub fn parse_port_argument(arg: &str) -> Option<SocketAddr> {
    let numbers: Vec<u8> = arg.split(',').map(|n| n.trim().parse().ok()).collect::<Option<_>>()?;
    let [a, b, c, d, p1, p2] = numbers[..] else { return None };
    Some(SocketAddr::new(IpAddr::from([a, b, c, d]), u16::from(p1) << 8 | u16::from(p2)))
}

pub fn parse_eprt_argument(arg: &str) -> Option<SocketAddr> {
    let delimiter = arg.chars().next()?;
    let fields: Vec<&str> = arg.split(delimiter).collect();
    let [_, protocol, address, port, _] = fields[..] else { return None };
    let ip: IpAddr = address.parse().ok()?;
    match (protocol, ip) {
        ("1", IpAddr::V4(_)) | ("2", IpAddr::V6(_)) => Some(SocketAddr::new(ip, port.parse().ok()?)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_paths_and_data_addresses() {
        assert_eq!(resolve_virtual("/a/b", "../c"), "/a/c");
        assert_eq!(resolve_virtual("/a", "/../../etc"), "/etc");
        assert_eq!(parse_port_argument("192,168,1,2,7,138"), Some("192.168.1.2:1930".parse().unwrap()));
        assert_eq!(parse_eprt_argument("|2|::1|5282|"), Some("[::1]:5282".parse().unwrap()));
        assert_eq!(parse_eprt_argument("|1|::1|5282|"), None);
    }
}
