//! TLS client fingerprints from a raw ClientHello: JA3 (Salesforce) and JA4 (FoxIO).
//! Malware families and their TLS libraries are recognisable by these even when the SNI
//! and certificate tell nothing.

use md5::{Digest, Md5};

/// What a ClientHello says about the client
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    /// Extension types, in the order sent
    pub extensions: Vec<u16>,
    pub groups: Vec<u16>,
    pub point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub alpn: Vec<Vec<u8>>,
    pub sni: Option<String>,
}

/// GREASE values (RFC 8701): 0x0a0a, 0x1a1a ... 0xfafa; ignored by both fingerprints
pub fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3).map(|b| (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
    /// A length-prefixed vector (1 or 2 length bytes)
    fn vector(&mut self, length_bytes: usize) -> Option<Reader<'a>> {
        let length = match length_bytes {
            1 => self.u8()? as usize,
            _ => self.u16()? as usize,
        };
        self.take(length).map(Reader)
    }
    fn u16s(mut self) -> Vec<u16> {
        let mut values = Vec::new();
        while let Some(value) = self.u16() {
            values.push(value);
        }
        values
    }
}

/// The most a ClientHello may take to read (a 16 KiB record or several smaller ones)
pub const MAX_HELLO: usize = 20 * 1024;

/// Whether more bytes are needed for the whole ClientHello at the start of `data`: false
/// once it's complete, or when it never will be (not a handshake, or past MAX_HELLO)
pub fn hello_wants_more(data: &[u8]) -> bool {
    if data.len() >= MAX_HELLO {
        return false;
    }
    let mut records = Reader(data);
    let mut head: Vec<u8> = Vec::with_capacity(4); // The handshake header, which may straddle records
    let mut handshake = 0usize;
    loop {
        let Some(header) = records.take(5) else { return true };
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[0] != 22 || length == 0 {
            return false;
        }
        let Some(fragment) = records.take(length) else { return true };
        let missing = 4 - head.len();
        head.extend(fragment.iter().take(missing));
        handshake += fragment.len();
        if head.len() == 4 && handshake >= 4 + ((head[1] as usize) << 16 | (head[2] as usize) << 8 | head[3] as usize) {
            return false;
        }
    }
}

impl ClientHello {
    /// Parses the ClientHello from the start of a TLS connection (one or more handshake
    /// records); None if it isn't one or is cut short
    pub fn parse(stream: &[u8]) -> Option<ClientHello> {
        // Reassemble the handshake layer from its records
        let mut handshake = Vec::new();
        let mut records = Reader(stream);
        while let Some(header) = records.take(5) {
            if header[0] != 22 {
                break;
            }
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            let Some(fragment) = records.take(length) else { break };
            handshake.extend_from_slice(fragment);
            if handshake.len() >= 4 && handshake.len() >= 4 + ((handshake[1] as usize) << 16 | (handshake[2] as usize) << 8 | handshake[3] as usize) {
                break;
            }
        }
        let mut message = Reader(&handshake);
        if message.u8()? != 1 {
            return None;
        }
        let length = message.u24()?;
        let mut body = Reader(message.take(length)?);
        let legacy_version = body.u16()?;
        body.take(32)?;
        body.vector(1)?; // Session ID
        let ciphers = body.vector(2)?.u16s();
        body.vector(1)?; // Compression methods
        let mut hello = ClientHello {
            legacy_version,
            ciphers,
            extensions: Vec::new(),
            groups: Vec::new(),
            point_formats: Vec::new(),
            signature_algorithms: Vec::new(),
            supported_versions: Vec::new(),
            alpn: Vec::new(),
            sni: None,
        };
        let Some(mut extensions) = body.vector(2) else { return Some(hello) }; // Extensions are optional
        while let Some(kind) = extensions.u16() {
            let mut data = extensions.vector(2)?;
            hello.extensions.push(kind);
            match kind {
                0 => {
                    let mut names = data.vector(2)?;
                    while let Some(name_type) = names.u8() {
                        let name = names.vector(2)?.0;
                        if name_type == 0 && hello.sni.is_none() {
                            hello.sni = Some(String::from_utf8_lossy(name).into_owned());
                        }
                    }
                }
                10 => hello.groups = data.vector(2)?.u16s(),
                11 => hello.point_formats = data.vector(1)?.0.to_vec(),
                13 => hello.signature_algorithms = data.vector(2)?.u16s(),
                16 => {
                    let mut protocols = data.vector(2)?;
                    while let Some(protocol) = protocols.vector(1) {
                        hello.alpn.push(protocol.0.to_vec());
                    }
                }
                43 => hello.supported_versions = data.vector(1)?.u16s(),
                _ => {}
            }
        }
        Some(hello)
    }

    /// The JA3 string: version,ciphers,extensions,groups,point formats (GREASE removed)
    pub fn ja3_string(&self) -> String {
        let join = |values: &mut dyn Iterator<Item = u16>| values.filter(|v| !is_grease(*v)).map(|v| v.to_string()).collect::<Vec<_>>().join("-");
        format!(
            "{},{},{},{},{}",
            self.legacy_version,
            join(&mut self.ciphers.iter().copied()),
            join(&mut self.extensions.iter().copied()),
            join(&mut self.groups.iter().copied()),
            self.point_formats.iter().map(u8::to_string).collect::<Vec<_>>().join("-"),
        )
    }

    pub fn ja3(&self) -> String {
        hex(&Md5::digest(self.ja3_string().as_bytes()))
    }

    /// JA4 for TLS over TCP (`quic`: over QUIC), e.g. "t13d1516h2_8daaf6152771_e5627efa2ab1"
    pub fn ja4(&self, quic: bool) -> String {
        let version = self.supported_versions.iter().copied().filter(|v| !is_grease(*v)).max().unwrap_or(self.legacy_version);
        let version = match version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            0x0300 => "s3",
            0x0002 => "s2",
            0xfeff => "d1",
            0xfefd => "d2",
            0xfefc => "d3",
            _ => "00",
        };
        let ciphers: Vec<u16> = self.ciphers.iter().copied().filter(|v| !is_grease(*v)).collect();
        let extensions: Vec<u16> = self.extensions.iter().copied().filter(|v| !is_grease(*v)).collect();
        let alpn = match self.alpn.first().filter(|p| !p.is_empty()) {
            None => "00".to_string(),
            Some(first) => {
                let (a, b) = (first[0], first[first.len() - 1]);
                if a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric() {
                    format!("{}{}", a as char, b as char)
                } else {
                    // Non-alphanumeric: the first and last characters of its hex form
                    let h = hex(first);
                    format!("{}{}", &h[..1], &h[h.len() - 1..])
                }
            }
        };
        let a = format!(
            "{}{version}{}{:02}{:02}{alpn}",
            if quic { 'q' } else { 't' },
            if self.extensions.contains(&0) { 'd' } else { 'i' },
            ciphers.len().min(99),
            extensions.len().min(99),
        );
        let mut sorted_ciphers: Vec<String> = ciphers.iter().map(|v| format!("{v:04x}")).collect();
        sorted_ciphers.sort();
        let mut sorted_extensions: Vec<String> = extensions.iter().filter(|v| **v != 0 && **v != 16).map(|v| format!("{v:04x}")).collect();
        sorted_extensions.sort();
        let mut c = sorted_extensions.join(",");
        let algorithms: Vec<String> = self.signature_algorithms.iter().filter(|v| !is_grease(**v)).map(|v| format!("{v:04x}")).collect();
        if !algorithms.is_empty() {
            c = format!("{c}_{}", algorithms.join(","));
        }
        let b = if ciphers.is_empty() { "000000000000".to_string() } else { truncated_sha256(&sorted_ciphers.join(",")) };
        let c = if extensions.is_empty() { "000000000000".to_string() } else { truncated_sha256(&c) };
        format!("{a}_{b}_{c}")
    }
}

fn truncated_sha256(text: &str) -> String {
    hex(&ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref()[..6])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Known fingerprints (JA3 MD5, JA4 or HASSH) from CSV text: the first field is the
/// fingerprint, the last its label; `#` lines are comments. abuse.ch SSLBL's
/// ja3_fingerprints.csv reads as is. A match is a lead, not an attribution: fingerprints
/// change with library versions and options, and are shared by everything using a library.
pub fn parse_known(text: &str) -> std::collections::HashMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            let (fingerprint, label) = (fields.first()?, fields.last()?);
            (!fingerprint.is_empty() && fields.len() >= 2).then(|| (fingerprint.to_ascii_lowercase(), label.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_values() {
        assert!(is_grease(0x0a0a) && is_grease(0xfafa) && is_grease(0x3a3a));
        assert!(!is_grease(0x0a1a) && !is_grease(0x1301) && !is_grease(0x000a));
    }

    #[test]
    fn parses_fingerprint_lists() {
        let known = parse_known("# ja3_md5,Firstseen,Lastseen,Listingreason\nB386946A5A44D1DDCC843BC75336DFCE,2017-07-14,2019-07-27,Dridex\n\nt13d1516h2_8daaf6152771_e5627efa2ab1,Chrome\nlonely\n");
        assert_eq!(known.len(), 2);
        assert_eq!(known["b386946a5a44d1ddcc843bc75336dfce"], "Dridex");
        assert_eq!(known["t13d1516h2_8daaf6152771_e5627efa2ab1"], "Chrome");
    }

    #[test]
    fn knows_when_a_hello_is_complete() {
        let hello = [22, 3, 1, 0, 8, 1, 0, 0, 4, 3, 3, 0, 0];
        assert!(hello_wants_more(&[]));
        assert!(hello_wants_more(&hello[..4]));
        assert!(hello_wants_more(&hello[..12]));
        assert!(!hello_wants_more(&hello));
        assert!(!hello_wants_more(b"GET / HTTP/1.1"));
        // Split across two records
        let split = [22, 3, 1, 0, 2, 1, 0, 22, 3, 1, 0, 6, 0, 4, 3, 3, 0, 0];
        assert!(hello_wants_more(&split[..7]));
        assert!(!hello_wants_more(&split));
    }

    #[test]
    fn rejects_non_hellos_and_truncation() {
        assert_eq!(ClientHello::parse(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(ClientHello::parse(&[22, 3, 1, 0, 10, 1, 0, 0, 6, 3, 3]), None);
        assert_eq!(ClientHello::parse(&[]), None);
    }
}
