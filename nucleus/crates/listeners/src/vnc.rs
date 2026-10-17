//! VNC (RFB, RFC 6143) for capture: the client's protocol version, and with VNC
//! authentication its DES response to our challenge, logged as a crackable
//! `$vnc$*CHALLENGE*RESPONSE` line (john's VNC format). Authentication then fails, as with
//! a wrong password.

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::session::Session;
use crate::stream::BoxStream;

const SERVER_VERSION: &[u8] = b"RFB 003.008\n";
const VNC_AUTH: u8 = 2;

pub async fn handle(mut stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    send(&mut stream, &session, SERVER_VERSION).await?;
    let mut version = [0u8; 12];
    if read(&mut stream, &session, &mut version).await?.is_none() {
        return Ok(());
    }
    let client_version = String::from_utf8_lossy(&version).trim_end().to_string();
    let minor = version.get(8..11).and_then(|m| std::str::from_utf8(m).ok()).and_then(|m| m.parse::<u32>().ok()).unwrap_or(3);
    session.log("vnc_client", json!({ "version": client_version }));
    // 3.7+: we offer VNC authentication and the client picks; 3.3: we impose it
    if minor >= 7 {
        send(&mut stream, &session, &[1, VNC_AUTH]).await?;
        let mut chosen = [0u8; 1];
        if read(&mut stream, &session, &mut chosen).await?.is_none() || chosen[0] != VNC_AUTH {
            return Ok(());
        }
    } else {
        send(&mut stream, &session, &u32::from(VNC_AUTH).to_be_bytes()).await?;
    }
    let challenge: [u8; 16] = crate::tls::random_bytes();
    send(&mut stream, &session, &challenge).await?;
    let mut response = [0u8; 16];
    if read(&mut stream, &session, &mut response).await?.is_none() {
        return Ok(());
    }
    let upper_hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02X}")).collect::<String>();
    let hash = format!("$vnc$*{}*{}", upper_hex(&challenge), upper_hex(&response));
    let record = json!({ "mechanism": "VNC", "hash_type": "vnc", "hash": hash });
    session.log("credentials", record.clone());
    session.notify(&response, json!({ "client_version": client_version, "credentials": record }));
    // SecurityResult: failed, with a reason (3.8)
    let mut result = 1u32.to_be_bytes().to_vec();
    if minor >= 8 {
        let reason = b"Authentication failed";
        result.extend_from_slice(&(reason.len() as u32).to_be_bytes());
        result.extend_from_slice(reason);
    }
    send(&mut stream, &session, &result).await?;
    Ok(())
}

async fn send(stream: &mut BoxStream, session: &Session, data: &[u8]) -> std::io::Result<()> {
    stream.write_all(data).await?;
    session.server_data(data);
    Ok(())
}

async fn read(stream: &mut BoxStream, session: &Session, buffer: &mut [u8]) -> anyhow::Result<Option<()>> {
    match tokio::time::timeout(session.ctx.timeout, stream.read_exact(buffer)).await {
        Err(_) => Ok(None),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Ok(Err(e)) => Err(e.into()),
        Ok(Ok(_)) => {
            session.client_data(buffer);
            Ok(Some(()))
        }
    }
}
