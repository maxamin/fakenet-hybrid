//! Decrypting TLS conversations with an NSS key log (what browsers' SSLKEYLOGFILE and the
//! nucleus's `tls-keys.log` write), so encrypted captures yield their HTTP (or other) for
//! learning.
//!
//! - TLS 1.3 (RFC 8446): traffic secrets from the log (`CLIENT_HANDSHAKE_TRAFFIC_SECRET`,
//!   `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`),
//!   keys by HKDF-Expand-Label; suites AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305.
//! - TLS 1.2 (RFC 5246): the master secret (`CLIENT_RANDOM`), keys by the PRF; AEAD suites
//!   only: AES-GCM (RFC 5288) and ChaCha20-Poly1305 (RFC 7905).
//!
//! Sessions without matching secrets, CBC suites, and anything that fails to decrypt are left
//! encrypted (skipped).

use std::collections::HashMap;
use std::path::Path;

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::{hkdf, hmac};

use crate::flows::Conversation;

/// Secrets for one session, by its client random
#[derive(Debug, Clone, Default, PartialEq)]
struct Secrets {
    master: Option<Vec<u8>>,
    client_handshake: Option<Vec<u8>>,
    server_handshake: Option<Vec<u8>>,
    client_application: Option<Vec<u8>>,
    server_application: Option<Vec<u8>>,
}

/// An NSS key log: client random -> secrets
#[derive(Debug, Clone, Default)]
pub struct KeyLog {
    sessions: HashMap<[u8; 32], Secrets>,
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

impl KeyLog {
    /// Lines `LABEL <client random hex> <secret hex>`; comments and unknown labels skipped
    pub fn parse(text: &str) -> KeyLog {
        let mut log = KeyLog::default();
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let (Some(label), Some(random), Some(secret)) = (fields.next(), fields.next(), fields.next()) else { continue };
            let (Some(random), Some(secret)) = (unhex(random), unhex(secret)) else { continue };
            let Ok(random) = <[u8; 32]>::try_from(random) else { continue };
            let entry = log.sessions.entry(random).or_default();
            let slot = match label {
                "CLIENT_RANDOM" => &mut entry.master,
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => &mut entry.client_handshake,
                "SERVER_HANDSHAKE_TRAFFIC_SECRET" => &mut entry.server_handshake,
                "CLIENT_TRAFFIC_SECRET_0" => &mut entry.client_application,
                "SERVER_TRAFFIC_SECRET_0" => &mut entry.server_application,
                _ => continue,
            };
            *slot = Some(secret);
        }
        log
    }

    pub fn load(path: &Path) -> anyhow::Result<KeyLog> {
        Ok(KeyLog::parse(&std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?))
    }

    /// Sessions with secrets
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn merge(&mut self, other: KeyLog) {
        self.sessions.extend(other.sessions);
    }
}

#[derive(Clone, Copy)]
struct Suite {
    aead: &'static aead::Algorithm,
    key_len: usize,
    /// SHA-384 suites (HKDF and the PRF); else SHA-256
    sha384: bool,
    /// TLS 1.2 GCM: a 4-byte salt and an 8-byte explicit nonce per record; ChaCha20 (and all
    /// of TLS 1.3): a 12-byte IV XORed with the sequence number
    explicit_nonce: bool,
}

fn suite(id: u16) -> Option<Suite> {
    let gcm128 = Suite { aead: &aead::AES_128_GCM, key_len: 16, sha384: false, explicit_nonce: true };
    let gcm256 = Suite { aead: &aead::AES_256_GCM, key_len: 32, sha384: true, explicit_nonce: true };
    let chacha = Suite { aead: &aead::CHACHA20_POLY1305, key_len: 32, sha384: false, explicit_nonce: false };
    Some(match id {
        0x1301 => Suite { explicit_nonce: false, ..gcm128 },
        0x1302 => Suite { explicit_nonce: false, ..gcm256 },
        0x1303 => chacha,
        0xc02b | 0xc02f | 0x009c | 0x009e => gcm128,
        0xc02c | 0xc030 | 0x009d | 0x009f => gcm256,
        0xcca8 | 0xcca9 | 0xccaa => chacha,
        _ => return None,
    })
}

/// Record-protection keys for one direction
struct Keys {
    key: LessSafeKey,
    /// 12 bytes (TLS 1.3, ChaCha20) or a 4-byte salt (TLS 1.2 GCM)
    iv: Vec<u8>,
    explicit_nonce: bool,
    seq: u64,
}

impl Keys {
    fn new(suite: Suite, key: &[u8], iv: Vec<u8>) -> Option<Keys> {
        Some(Keys { key: LessSafeKey::new(UnboundKey::new(suite.aead, key).ok()?), iv, explicit_nonce: suite.explicit_nonce, seq: 0 })
    }

    fn sequence_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.iv[..12]);
        for (byte, seq) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *byte ^= seq;
        }
        nonce
    }

    /// TLS 1.3: a record's inner plaintext and its real content type
    fn open13(&mut self, header: &[u8], fragment: &[u8]) -> Option<(u8, Vec<u8>)> {
        let mut buffer = fragment.to_vec();
        let nonce = Nonce::assume_unique_for_key(self.sequence_nonce());
        let plain = self.key.open_in_place(nonce, Aad::from(header), &mut buffer).ok()?;
        self.seq += 1;
        let end = plain.iter().rposition(|&b| b != 0)?;
        Some((plain[end], plain[..end].to_vec()))
    }

    /// TLS 1.2: a record's plaintext
    fn open12(&mut self, content_type: u8, version: [u8; 2], fragment: &[u8]) -> Option<Vec<u8>> {
        let (nonce, ciphertext) = match self.explicit_nonce {
            true => {
                let explicit = fragment.get(..8)?;
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(&self.iv[..4]);
                nonce[4..].copy_from_slice(explicit);
                (nonce, &fragment[8..])
            }
            false => (self.sequence_nonce(), fragment),
        };
        let plain_length = ciphertext.len().checked_sub(self.key.algorithm().tag_len())?;
        let mut aad = self.seq.to_be_bytes().to_vec();
        aad.push(content_type);
        aad.extend(version);
        aad.extend((plain_length as u16).to_be_bytes());
        let mut buffer = ciphertext.to_vec();
        let plain = self.key.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&aad), &mut buffer).ok()?.to_vec();
        self.seq += 1;
        Some(plain)
    }
}

struct OkmLen(usize);

impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand-Label(secret, label, "", length) (RFC 8446 7.1)
fn expand_label(sha384: bool, secret: &[u8], label: &str, length: usize) -> Option<Vec<u8>> {
    let algorithm = if sha384 { hkdf::HKDF_SHA384 } else { hkdf::HKDF_SHA256 };
    let prk = hkdf::Prk::new_less_safe(algorithm, secret);
    let full = format!("tls13 {label}");
    let info = [&(length as u16).to_be_bytes()[..], &[full.len() as u8], full.as_bytes(), &[0u8]];
    let okm = prk.expand(&info, OkmLen(length)).ok()?;
    let mut out = vec![0u8; length];
    okm.fill(&mut out).ok()?;
    Some(out)
}

fn keys13(suite: Suite, secret: &[u8]) -> Option<Keys> {
    let key = expand_label(suite.sha384, secret, "key", suite.key_len)?;
    let iv = expand_label(suite.sha384, secret, "iv", 12)?;
    Keys::new(suite, &key, iv)
}

/// The TLS 1.2 PRF: P_hash(secret, label + seed) (RFC 5246 5)
fn prf12(sha384: bool, secret: &[u8], label: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let key = hmac::Key::new(if sha384 { hmac::HMAC_SHA384 } else { hmac::HMAC_SHA256 }, secret);
    let seed: Vec<u8> = label.iter().chain(seed).copied().collect();
    let mut a = hmac::sign(&key, &seed).as_ref().to_vec();
    let mut out = Vec::new();
    while out.len() < length {
        let mut input = a.clone();
        input.extend(&seed);
        out.extend(hmac::sign(&key, &input).as_ref());
        a = hmac::sign(&key, &a).as_ref().to_vec();
    }
    out.truncate(length);
    out
}

/// TLS 1.2 keys: (client write, server write)
fn keys12(suite: Suite, master: &[u8], client_random: &[u8], server_random: &[u8]) -> Option<(Keys, Keys)> {
    let iv_len = if suite.explicit_nonce { 4 } else { 12 };
    let seed: Vec<u8> = server_random.iter().chain(client_random).copied().collect();
    let block = prf12(suite.sha384, master, b"key expansion", &seed, 2 * suite.key_len + 2 * iv_len);
    let (client_key, rest) = block.split_at(suite.key_len);
    let (server_key, rest) = rest.split_at(suite.key_len);
    let (client_iv, server_iv) = rest.split_at(iv_len);
    Some((Keys::new(suite, client_key, client_iv.to_vec())?, Keys::new(suite, server_key, server_iv.to_vec())?))
}

/// Handshake messages in a buffer: (type, body)
fn handshake_messages(mut data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while data.len() >= 4 {
        let length = (usize::from(data[1]) << 16) | (usize::from(data[2]) << 8) | usize::from(data[3]);
        let Some(body) = data.get(4..4 + length) else { break };
        out.push((data[0], body));
        data = &data[4 + length..];
    }
    out
}

/// ServerHello: (server random, cipher suite, TLS 1.3?)
fn parse_server_hello(body: &[u8]) -> Option<([u8; 32], u16, bool)> {
    let random: [u8; 32] = body.get(2..34)?.try_into().ok()?;
    let session_id = usize::from(*body.get(34)?);
    let at = 35 + session_id;
    let suite = u16::from_be_bytes([*body.get(at)?, *body.get(at + 1)?]);
    // Extensions: supported_versions (43) = 0x0304 means TLS 1.3
    let mut tls13 = false;
    let mut ext = at + 3;
    let end = (ext + 2 + usize::from(u16::from_be_bytes([*body.get(ext)?, *body.get(ext + 1)?]))).min(body.len());
    ext += 2;
    while ext + 4 <= end {
        let (kind, length) = (u16::from_be_bytes([body[ext], body[ext + 1]]), usize::from(u16::from_be_bytes([body[ext + 2], body[ext + 3]])));
        if kind == 43 && body.get(ext + 4..ext + 6) == Some(&[3, 4]) {
            tls13 = true;
        }
        ext += 4 + length;
    }
    Some((random, suite, tls13))
}

#[derive(Default)]
struct Side {
    /// Bytes of an incomplete record carried to the next message
    pending: Vec<u8>,
    keys: Option<Keys>,
    /// TLS 1.3: switched to application keys
    application: bool,
}

/// The conversation's application data, decrypted; None when it isn't TLS, the log has no
/// secrets for it, or nothing decrypts
pub fn decrypt(conversation: &Conversation, log: &KeyLog) -> Option<Conversation> {
    let mut client_random: Option<[u8; 32]> = None;
    let mut session: Option<(Suite, bool, Secrets)> = None;
    let (mut client, mut server) = (Side::default(), Side::default());
    let mut out: Vec<(bool, Vec<u8>)> = Vec::new();
    let mut decrypted_any = false;
    for (from_client, bytes) in &conversation.messages {
        let side = if *from_client { &mut client } else { &mut server };
        side.pending.extend_from_slice(bytes);
        let mut at = 0;
        let buffer = std::mem::take(&mut side.pending);
        while at + 5 <= buffer.len() {
            let (content_type, version, length) = (buffer[at], [buffer[at + 1], buffer[at + 2]], usize::from(u16::from_be_bytes([buffer[at + 3], buffer[at + 4]])));
            if length > 16384 + 2048 {
                return None; // Not TLS (or corrupt)
            }
            let Some(fragment) = buffer.get(at + 5..at + 5 + length) else { break };
            let header = &buffer[at..at + 5];
            at += 5 + length;
            let side = if *from_client { &mut client } else { &mut server };
            match (content_type, &mut session) {
                // Plaintext handshake: ClientHello, ServerHello (and TLS 1.2's certificates...)
                (22, _) if side.keys.is_none() => {
                    for (kind, body) in handshake_messages(fragment) {
                        match kind {
                            1 if *from_client => client_random = body.get(2..34).and_then(|r| r.try_into().ok()),
                            2 if !*from_client => {
                                let (server_random, id, tls13) = parse_server_hello(body)?;
                                let suite = suite(id)?;
                                let secrets = log.sessions.get(&client_random?)?.clone();
                                if tls13 {
                                    client.keys = keys13(suite, secrets.client_handshake.as_deref()?);
                                    server.keys = keys13(suite, secrets.server_handshake.as_deref()?);
                                } else {
                                    let master = secrets.master.as_deref()?;
                                    // Activated by each side's ChangeCipherSpec
                                    let (c, s) = keys12(suite, master, &client_random?, &server_random)?;
                                    session = Some((suite, false, secrets.clone()));
                                    stash12(&mut client, &mut server, c, s);
                                    continue;
                                }
                                session = Some((suite, true, secrets));
                            }
                            _ => {}
                        }
                    }
                }
                // TLS 1.2: the next records of this side are protected
                (20, Some((_, false, _))) => activate12(side),
                (_, Some((suite, true, secrets))) if content_type == 23 => {
                    let Some(keys) = side.keys.as_mut() else { continue };
                    let Some((inner, plain)) = keys.open13(header, fragment) else { continue };
                    match inner {
                        23 => {
                            decrypted_any = true;
                            push(&mut out, *from_client, &plain);
                        }
                        // The side's Finished: application keys from now on
                        22 if !side.application && handshake_messages(&plain).iter().any(|(kind, _)| *kind == 20) => {
                            let secret = if *from_client { secrets.client_application.clone() } else { secrets.server_application.clone() };
                            side.keys = secret.and_then(|s| keys13(*suite, &s));
                            side.application = true;
                        }
                        _ => {}
                    }
                }
                (22 | 23, Some((_, false, _))) if side.application => {
                    let Some(keys) = side.keys.as_mut() else { continue };
                    let Some(plain) = keys.open12(content_type, version, fragment) else { continue };
                    if content_type == 23 {
                        decrypted_any = true;
                        push(&mut out, *from_client, &plain);
                    }
                }
                _ => {}
            }
        }
        let side = if *from_client { &mut client } else { &mut server };
        side.pending.extend_from_slice(buffer.get(at..).unwrap_or_default());
        if side.pending.len() > 64 * 1024 {
            side.pending.clear();
        }
    }
    decrypted_any.then(|| Conversation { transport: conversation.transport, server_port: conversation.server_port, messages: out })
}

/// TLS 1.2 keys wait for each side's ChangeCipherSpec
fn stash12(client: &mut Side, server: &mut Side, c: Keys, s: Keys) {
    client.keys = Some(c);
    server.keys = Some(s);
    client.application = false;
    server.application = false;
}

fn activate12(side: &mut Side) {
    if let Some(keys) = side.keys.as_mut() {
        keys.seq = 0;
        side.application = true;
    }
}

fn push(out: &mut Vec<(bool, Vec<u8>)>, from_client: bool, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    match out.last_mut() {
        Some((direction, bytes)) if *direction == from_client => bytes.extend_from_slice(data),
        _ => out.push((from_client, data.to_vec())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_expand_label_matches_rfc8448() {
        // RFC 8448 (TLS 1.3 traces), "Simple 1-RTT Handshake": the server handshake traffic
        // secret and the key and IV derived from it
        let secret = unhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38").unwrap();
        assert_eq!(expand_label(false, &secret, "key", 16).unwrap(), unhex("3fce516009c21727d0f2e4e86ee403bc").unwrap());
        assert_eq!(expand_label(false, &secret, "iv", 12).unwrap(), unhex("5d313eb2671276ee13000b30").unwrap());
    }

    #[test]
    fn parses_key_logs() {
        let random = "a".repeat(64);
        let log = KeyLog::parse(&format!("# comment\nCLIENT_RANDOM {random} {}\nCLIENT_TRAFFIC_SECRET_0 {random} {}\nbogus line\nUNKNOWN {random} 00\n", "11".repeat(48), "22".repeat(32)));
        assert_eq!(log.len(), 1);
        let secrets = &log.sessions[&[0xaa; 32]];
        assert_eq!(secrets.master.as_ref().unwrap().len(), 48);
        assert_eq!(secrets.client_application.as_ref().unwrap().len(), 32);
    }
}
