//! SSH (RFC 4253): the version exchange and the client's key exchange offer only, which is
//! enough to log the client software and its HASSH fingerprint (MD5 of its offered
//! algorithms, widely used to identify malware SSH clients). One event per connection
//! (`meta.client_version`, `meta.hassh`, `meta.kexinit`); the daemon's close flag ends it.

use md5::{Digest, Md5};
use serde_json::{json, Value};

use crate::lines::Lines;
use crate::session::Session;
use crate::stream::BoxStream;

const SSH_MSG_KEXINIT: u8 = 20;
/// RFC 4253 6.1: packets of at least 35000 bytes must be supported
const MAX_PACKET: usize = 35_000;

/// The algorithm name-lists from a KEXINIT payload (RFC 4253 7.1)
#[derive(Debug, PartialEq, Eq)]
pub struct KexInit {
    pub kex: String,
    pub host_key: String,
    pub encryption_c2s: String,
    pub encryption_s2c: String,
    pub mac_c2s: String,
    pub mac_s2c: String,
    pub compression_c2s: String,
    pub compression_s2c: String,
}

impl KexInit {
    pub fn parse(payload: &[u8]) -> Option<KexInit> {
        if payload.first() != Some(&SSH_MSG_KEXINIT) {
            return None;
        }
        let mut rest = payload.get(17..)?; // Message type + 16-byte cookie
        let mut next = || -> Option<String> {
            let length = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            let value = rest.get(4..4 + length)?;
            rest = &rest[4 + length..];
            Some(String::from_utf8_lossy(value).into_owned())
        };
        Some(KexInit {
            kex: next()?,
            host_key: next()?,
            encryption_c2s: next()?,
            encryption_s2c: next()?,
            mac_c2s: next()?,
            mac_s2c: next()?,
            compression_c2s: next()?,
            compression_s2c: next()?,
        })
    }

    /// HASSH: MD5 of "kex;encryption;mac;compression" (client to server)
    pub fn hassh(&self) -> String {
        let input = format!("{};{};{};{}", self.kex, self.encryption_c2s, self.mac_c2s, self.compression_c2s);
        Md5::digest(input.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
    }

    fn to_json(&self) -> Value {
        json!({
            "kex": self.kex, "host_key": self.host_key, "encryption": self.encryption_c2s,
            "mac": self.mac_c2s, "compression": self.compression_c2s,
        })
    }
}

pub async fn handle(stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let banner = session.ctx.defaults.load().ssh.banner.clone();
    let mut lines = Lines::new(stream);
    lines.send(&session, format!("{banner}\r\n").as_bytes()).await?;
    // Clients may send other lines before their identification string (RFC 4253 4.2)
    let mut client_version = None;
    for _ in 0..10 {
        let Some(line) = lines.read(&session).await? else { break };
        if line.starts_with("SSH-") {
            client_version = Some(line);
            break;
        }
    }
    let Some(client_version) = client_version else {
        session.log("no_version", json!({}));
        return Ok(());
    };
    let kexinit = read_packet(&mut lines, &session).await.ok().flatten().and_then(|p| KexInit::parse(&p));
    let hassh = kexinit.as_ref().map(KexInit::hassh);
    let known = hassh.as_ref().and_then(|h| session.ctx.known_fingerprints.get(h));
    session.log("ssh_client", json!({ "version": client_version, "hassh": hassh, "known": known }));
    let meta = json!({ "client_version": client_version, "hassh": hassh, "kexinit": kexinit.as_ref().map(KexInit::to_json) });
    // Nothing more to say without a real key exchange: let the daemon's response (if any)
    // through, then the client gives up on its own (or the daemon closes)
    lines.respond(&mut session, client_version.as_bytes(), meta, String::new(), false).await?;
    Ok(())
}

/// One unencrypted binary packet (RFC 4253 6): its payload
async fn read_packet(lines: &mut Lines, session: &Session) -> anyhow::Result<Option<Vec<u8>>> {
    let length = lines.read_exact(session, 4).await?;
    let length = u32::from_be_bytes(length[..4].try_into()?) as usize;
    if !(5..=MAX_PACKET).contains(&length) {
        return Ok(None);
    }
    let packet = lines.read_exact(session, length).await?;
    let padding = packet[0] as usize;
    if padding + 1 > length {
        return Ok(None);
    }
    Ok(Some(packet[1..length - padding].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_a_kexinit() {
        let mut payload = vec![SSH_MSG_KEXINIT];
        payload.extend([0u8; 16]);
        for list in ["curve25519-sha256", "ssh-ed25519", "aes128-ctr", "aes128-ctr", "hmac-sha2-256", "hmac-sha2-256", "none", "none"] {
            payload.extend((list.len() as u32).to_be_bytes());
            payload.extend(list.as_bytes());
        }
        let kex = KexInit::parse(&payload).unwrap();
        assert_eq!(kex.kex, "curve25519-sha256");
        let expected: String = Md5::digest(b"curve25519-sha256;aes128-ctr;hmac-sha2-256;none").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(kex.hassh(), expected);
        assert!(KexInit::parse(&[21]).is_none());
    }
}
