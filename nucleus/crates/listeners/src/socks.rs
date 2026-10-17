//! SOCKS5 (RFC 1928, username/password auth per RFC 1929) and SOCKS4/4a. Malware tunnels
//! through infected hosts with SOCKS: the request is an event (`meta.target`,
//! `meta.version`; the daemon's close flag refuses it), and an accepted tunnel is sniffed
//! and served like any other connection (HTTP, TLS...), as a new session.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::bail;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::session::Session;
use crate::stream::BoxStream;

pub async fn handle(mut stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let timeout = session.ctx.timeout;
    let mut version = [0u8; 1];
    tokio::time::timeout(timeout, stream.read_exact(&mut version)).await??;
    let request = match version[0] {
        5 => match tokio::time::timeout(timeout, socks5_request(&mut stream, &session)).await?? {
            Some(request) => request,
            None => return Ok(()),
        },
        4 => tokio::time::timeout(timeout, socks4_request(&mut stream, &session)).await??,
        other => bail!("unsupported SOCKS version {other}"),
    };
    let (host, port) = (request.host.clone(), request.port);
    let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    session.client_data(target.as_bytes());
    let meta = json!({ "version": version[0], "target": target, "host": host, "port": port });
    let refused = session.decide(target.as_bytes(), meta).await.is_some_and(|a| a.close);
    let reply = match (version[0], refused) {
        (5, false) => vec![5, 0x00, 0, 1, 0, 0, 0, 0, 0, 0],
        (5, true) => vec![5, 0x02, 0, 1, 0, 0, 0, 0, 0, 0], // Not allowed by ruleset
        (_, false) => [&[0, 0x5a][..], &request.raw4].concat(),
        (_, true) => [&[0, 0x5b][..], &request.raw4].concat(),
    };
    stream.write_all(&reply).await?;
    session.server_data(&reply);
    if refused {
        session.log("socks_refused", json!({ "target": target }));
        return Ok(());
    }
    let ip = host.parse::<IpAddr>().unwrap_or(session.builder.dst.ip());
    crate::dispatch::serve_tunnel(&session, stream, target, SocketAddr::new(ip, port)).await
}

struct Request {
    host: String,
    port: u16,
    /// SOCKS4: port + IP as sent, echoed in the reply
    raw4: Vec<u8>,
}

async fn socks5_request(stream: &mut BoxStream, session: &Session) -> anyhow::Result<Option<Request>> {
    let mut count = [0u8; 1];
    stream.read_exact(&mut count).await?;
    let mut methods = vec![0u8; count[0] as usize];
    stream.read_exact(&mut methods).await?;
    // Prefer no authentication; if the client insists on username/password, capture it
    if methods.contains(&0x00) {
        stream.write_all(&[5, 0x00]).await?;
    } else if methods.contains(&0x02) {
        stream.write_all(&[5, 0x02]).await?;
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;
        let mut username = vec![0u8; header[1] as usize];
        stream.read_exact(&mut username).await?;
        let mut length = [0u8; 1];
        stream.read_exact(&mut length).await?;
        let mut password = vec![0u8; length[0] as usize];
        stream.read_exact(&mut password).await?;
        session.log("credentials", json!({ "username": String::from_utf8_lossy(&username), "password": String::from_utf8_lossy(&password) }));
        stream.write_all(&[1, 0]).await?;
    } else {
        stream.write_all(&[5, 0xff]).await?;
        return Ok(None);
    }
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    let [5, command, _, address_type] = request else { bail!("invalid SOCKS5 request") };
    let host = match address_type {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut name = vec![0u8; length[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            Ipv6Addr::from(ip).to_string()
        }
        other => bail!("invalid SOCKS5 address type {other}"),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    if command != 1 {
        // Only CONNECT: BIND & UDP ASSOCIATE would need real relays
        session.log("unsupported_command", json!({ "command": command, "host": host, "port": port }));
        stream.write_all(&[5, 0x07, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(None);
    }
    Ok(Some(Request { host, port, raw4: Vec::new() }))
}

async fn socks4_request(stream: &mut BoxStream, session: &Session) -> anyhow::Result<Request> {
    let mut header = [0u8; 7];
    stream.read_exact(&mut header).await?;
    let port = u16::from_be_bytes([header[1], header[2]]);
    let user = read_nul_terminated(stream).await?;
    // SOCKS4a: an IP of 0.0.0.x (x != 0) means a hostname follows
    let host = if header[3..6] == [0, 0, 0] && header[6] != 0 {
        read_nul_terminated(stream).await?
    } else {
        Ipv4Addr::new(header[3], header[4], header[5], header[6]).to_string()
    };
    if !user.is_empty() {
        session.log("credentials", json!({ "username": user }));
    }
    Ok(Request { host, port, raw4: header[1..7].to_vec() })
}

async fn read_nul_terminated(stream: &mut BoxStream) -> anyhow::Result<String> {
    let mut value = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        if byte[0] == 0 {
            return Ok(String::from_utf8_lossy(&value).into_owned());
        }
        anyhow::ensure!(value.len() < 255, "SOCKS4 field too long");
        value.push(byte[0]);
    }
}
