//! TFTP (RFC 1350): serves any file and accepts any upload, each transfer on its own port
//! (the TID) as the RFC requires. A read request is an event (`meta.opcode = "RRQ"`,
//! `meta.filename`, `meta.file = true`) whose response is the file's content (default:
//! from `defaults.tftp.root`, else a default file of its type). Uploads are saved under
//! files/ and reported to the daemon (no reply).

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::json;
use tokio::net::UdpSocket;

use crate::http::default_content;
use crate::lines::preview;
use crate::session::Session;

pub const RRQ: u16 = 1;
pub const WRQ: u16 = 2;
pub const DATA: u16 = 3;
pub const ACK: u16 = 4;
pub const ERROR: u16 = 5;

const BLOCK_SIZE: usize = 512;
const RETRIES: u32 = 5;
const RETRY_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_UPLOAD: usize = 32 * 1024 * 1024;

/// (filename, mode) of a RRQ/WRQ
pub fn parse_request(data: &[u8]) -> Option<(String, String)> {
    let mut fields = data.get(2..)?.split(|&b| b == 0);
    let filename = String::from_utf8_lossy(fields.next()?).into_owned();
    let mode = String::from_utf8_lossy(fields.next()?).to_ascii_lowercase();
    if filename.is_empty() || !matches!(mode.as_str(), "netascii" | "octet" | "mail") {
        return None;
    }
    Some((filename, mode))
}

pub fn error_packet(code: u16, message: &str) -> Vec<u8> {
    let mut packet = ERROR.to_be_bytes().to_vec();
    packet.extend(code.to_be_bytes());
    packet.extend(message.as_bytes());
    packet.push(0);
    packet
}

fn packet(opcode: u16, block: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = opcode.to_be_bytes().to_vec();
    packet.extend(block.to_be_bytes());
    packet.extend(data);
    packet
}

/// A datagram to the listener's port: requests start a transfer with `peer` (on a new
/// socket, finished before returning; other clients are served meanwhile). Returns any
/// reply for the listener's socket.
pub async fn handle(data: &[u8], session: &mut Session, peer: SocketAddr) -> Option<Vec<u8>> {
    session.client_data(data);
    let opcode = if data.len() >= 2 { u16::from_be_bytes([data[0], data[1]]) } else { 0 };
    if opcode != RRQ && opcode != WRQ {
        return Some(error_packet(5, "Unknown transfer ID"));
    }
    let Some((filename, mode)) = parse_request(data) else {
        return Some(error_packet(4, "Illegal TFTP operation"));
    };
    let socket = match bind_transfer(session, peer).await {
        Ok(socket) => socket,
        Err(e) => {
            session.log("transfer_failed", json!({ "filename": filename, "error": e.to_string() }));
            return Some(error_packet(0, "Server error"));
        }
    };
    let result = if opcode == RRQ {
        let meta = json!({ "opcode": "RRQ", "filename": filename, "mode": mode, "file": true });
        let default = default_content(&filename.replace('\\', "/"), session.ctx.defaults.tftp.root.as_deref()).0;
        let (contents, _) = session.answer(data, meta, default, false).await;
        session.log("download", json!({ "filename": filename, "mode": mode, "size": contents.len() }));
        send_file(&socket, &contents, session).await
    } else {
        receive_file(&socket, session).await.map(|contents| {
            let saved = session.ctx.capture.save_file("tftp", &filename, &contents).ok().map(|p| p.display().to_string());
            session.log("upload", json!({ "filename": filename, "size": contents.len(), "saved": saved, "preview": preview(&contents, 256) }));
            session.notify(&contents, json!({ "opcode": "WRQ", "filename": filename, "size": contents.len(), "saved": saved }));
        })
    };
    if let Err(e) = result {
        session.log("transfer_failed", json!({ "filename": filename, "error": e.to_string() }));
    }
    None
}

async fn bind_transfer(session: &Session, peer: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddr::new(session.local.ip(), 0)).await?;
    socket.connect(peer).await?;
    Ok(socket)
}

async fn send_file(socket: &UdpSocket, contents: &[u8], session: &Session) -> anyhow::Result<()> {
    let mut chunks: Vec<&[u8]> = contents.chunks(BLOCK_SIZE).collect();
    if contents.len() % BLOCK_SIZE == 0 {
        chunks.push(&[]); // A final short (empty) block marks the end
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let block = (index + 1) as u16; // Wraps for files over 32 MB, as clients expect
        let packet = packet(DATA, block, chunk);
        session.server_data(&packet);
        let mut acknowledged = false;
        for _ in 0..RETRIES {
            socket.send(&packet).await?;
            if wait_for_ack(socket, block).await? {
                acknowledged = true;
                break;
            }
        }
        anyhow::ensure!(acknowledged, "no acknowledgement for block {block}");
    }
    Ok(())
}

async fn wait_for_ack(socket: &UdpSocket, block: u16) -> anyhow::Result<bool> {
    let mut buffer = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + RETRY_TIMEOUT;
    loop {
        let read = match tokio::time::timeout_at(deadline, socket.recv(&mut buffer)).await {
            Err(_) => return Ok(false),
            Ok(result) => result?,
        };
        match &buffer[..read] {
            [0, 4, high, low] if u16::from_be_bytes([*high, *low]) == block => return Ok(true),
            [0, 5, ..] => anyhow::bail!("client aborted the transfer"),
            _ => {} // Duplicate or stale ACKs: keep waiting
        }
    }
}

async fn receive_file(socket: &UdpSocket, session: &Session) -> anyhow::Result<Vec<u8>> {
    let mut contents = Vec::new();
    let mut expected: u16 = 1;
    socket.send(&packet(ACK, 0, &[])).await?;
    let mut buffer = vec![0u8; BLOCK_SIZE + 4];
    let mut retries = 0;
    loop {
        let read = match tokio::time::timeout(RETRY_TIMEOUT, socket.recv(&mut buffer)).await {
            Err(_) => {
                retries += 1;
                anyhow::ensure!(retries < RETRIES, "upload timed out");
                socket.send(&packet(ACK, expected.wrapping_sub(1), &[])).await?; // Re-ACK the last block
                continue;
            }
            Ok(result) => result?,
        };
        retries = 0;
        let received = &buffer[..read];
        if received.len() < 4 || u16::from_be_bytes([received[0], received[1]]) != DATA {
            continue;
        }
        session.client_data(received);
        let block = u16::from_be_bytes([received[2], received[3]]);
        if block != expected {
            socket.send(&packet(ACK, block, &[])).await?; // A duplicate: ACK it again
            continue;
        }
        let data = &received[4..];
        if contents.len() + data.len() > MAX_UPLOAD {
            socket.send(&error_packet(3, "Disk full")).await?;
            anyhow::bail!("upload too large");
        }
        contents.extend_from_slice(data);
        socket.send(&packet(ACK, block, &[])).await?;
        expected = expected.wrapping_add(1);
        if data.len() < BLOCK_SIZE {
            return Ok(contents);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requests() {
        assert_eq!(parse_request(b"\0\x01boot.bin\0octet\0"), Some(("boot.bin".into(), "octet".into())));
        assert_eq!(parse_request(b"\0\x01a\0weird\0"), None);
        assert_eq!(error_packet(1, "x"), b"\0\x05\0\x01x\0");
    }
}
