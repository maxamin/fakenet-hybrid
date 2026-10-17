//! NTLM authentication capture (MS-NLMP), shared by SMB and LDAP: answer a client's
//! NEGOTIATE with a CHALLENGE, then turn its AUTHENTICATE into the user, domain, workstation
//! and a crackable hash line (hashcat 5600 / john netntlmv2 for NTLMv2, 5500 / netntlm for
//! NTLMv1). Also the minimal SPNEGO (RFC 4178) wrapping SMB uses around NTLM tokens.

use serde_json::{json, Value};

pub const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
const REQUEST_TARGET: u32 = 0x0000_0004;
const NEGOTIATE_NTLM: u32 = 0x0000_0200;
const ALWAYS_SIGN: u32 = 0x0000_8000;
const TARGET_TYPE_DOMAIN: u32 = 0x0001_0000;
const EXTENDED_SESSION_SECURITY: u32 = 0x0008_0000;
const TARGET_INFO: u32 = 0x0080_0000;
const NEGOTIATE_VERSION: u32 = 0x0200_0000;
const NEGOTIATE_128: u32 = 0x2000_0000;
const KEY_EXCHANGE: u32 = 0x4000_0000;
const NEGOTIATE_56: u32 = 0x8000_0000;

/// The domain and host the fake server claims to be
pub const DOMAIN: &str = "FAKENET";
pub const COMPUTER: &str = "FILESRV01";
pub const DNS_DOMAIN: &str = "fakenet.local";

/// The NTLMSSP message inside `data` (an SPNEGO token, a SASL buffer...), if there is one
pub fn find(data: &[u8]) -> Option<&[u8]> {
    data.windows(SIGNATURE.len()).position(|w| w == SIGNATURE).map(|start| &data[start..])
}

/// 1 NEGOTIATE, 2 CHALLENGE, 3 AUTHENTICATE
pub fn message_type(message: &[u8]) -> Option<u32> {
    message.starts_with(SIGNATURE).then(|| u32_at(message, 8)).flatten()
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A CHALLENGE answering `negotiate` (the client's NEGOTIATE; its flags shape ours)
pub fn challenge(negotiate: &[u8], server_challenge: [u8; 8]) -> Vec<u8> {
    let requested = u32_at(negotiate, 12).unwrap_or(NEGOTIATE_UNICODE | NEGOTIATE_NTLM);
    let flags = (requested & (NEGOTIATE_UNICODE | NEGOTIATE_NTLM | ALWAYS_SIGN | EXTENDED_SESSION_SECURITY | NEGOTIATE_VERSION | NEGOTIATE_128 | KEY_EXCHANGE | NEGOTIATE_56))
        | NEGOTIATE_UNICODE
        | NEGOTIATE_NTLM
        | REQUEST_TARGET
        | TARGET_TYPE_DOMAIN
        | TARGET_INFO;
    let target_name = utf16(DOMAIN);
    let mut target_info = Vec::new();
    let mut pair = |id: u16, value: &[u8]| {
        target_info.extend_from_slice(&id.to_le_bytes());
        target_info.extend_from_slice(&(value.len() as u16).to_le_bytes());
        target_info.extend_from_slice(value);
    };
    pair(2, &utf16(DOMAIN));
    pair(1, &utf16(COMPUTER));
    pair(4, &utf16(DNS_DOMAIN));
    pair(3, &utf16(&format!("{}.{DNS_DOMAIN}", COMPUTER.to_ascii_lowercase())));
    pair(5, &utf16(DNS_DOMAIN));
    pair(7, &filetime_now().to_le_bytes()); // MsvAvTimestamp: NTLMv2 clients expect one
    pair(0, &[]);
    let header = 56u32;
    let mut message = Vec::with_capacity(header as usize + target_name.len() + target_info.len());
    message.extend_from_slice(SIGNATURE);
    message.extend_from_slice(&2u32.to_le_bytes());
    message.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    message.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    message.extend_from_slice(&header.to_le_bytes());
    message.extend_from_slice(&flags.to_le_bytes());
    message.extend_from_slice(&server_challenge);
    message.extend_from_slice(&[0; 8]);
    message.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    message.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    message.extend_from_slice(&(header + target_name.len() as u32).to_le_bytes());
    message.extend_from_slice(&[10, 0, 0x7c, 0x4f, 0, 0, 0, 15]); // Version: Windows 10.0 build 20348, NTLM revision 15
    message.extend_from_slice(&target_name);
    message.extend_from_slice(&target_info);
    message
}

/// Now, as a Windows FILETIME (100 ns since 1601)
pub fn filetime_now() -> u64 {
    let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() / 100).unwrap_or(0);
    (unix as u64).saturating_add(116_444_736_000_000_000)
}

/// What an AUTHENTICATE message gave away
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticate {
    pub user: String,
    pub domain: String,
    pub workstation: String,
    pub lm_response: Vec<u8>,
    pub nt_response: Vec<u8>,
}

impl Authenticate {
    pub fn parse(message: &[u8]) -> Option<Authenticate> {
        if message_type(message)? != 3 {
            return None;
        }
        let flags = u32_at(message, 60).unwrap_or(NEGOTIATE_UNICODE);
        let field = |at: usize| -> Option<&[u8]> {
            let length = usize::from(u16_at(message, at)?);
            let offset = u32_at(message, at + 4)? as usize;
            message.get(offset..offset.checked_add(length)?)
        };
        let text = |bytes: &[u8]| -> String {
            if flags & NEGOTIATE_UNICODE != 0 {
                let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                String::from_utf16_lossy(&units)
            } else {
                String::from_utf8_lossy(bytes).into_owned()
            }
        };
        Some(Authenticate {
            lm_response: field(12)?.to_vec(),
            nt_response: field(20)?.to_vec(),
            domain: text(field(28)?),
            user: text(field(36)?),
            workstation: text(field(44)?),
        })
    }

    pub fn anonymous(&self) -> bool {
        self.user.is_empty() && self.nt_response.is_empty()
    }

    /// The hashcat / john line for this response to `server_challenge`: NTLMv2
    /// ("user::domain:challenge:ntproofstr:blob", hashcat 5600) or NTLMv1
    /// ("user::domain:lm:nt:challenge", hashcat 5500); None for anonymous logons
    pub fn hash(&self, server_challenge: &[u8; 8]) -> Option<(String, &'static str)> {
        let challenge = hex(server_challenge);
        match self.nt_response.len() {
            0 => None,
            24 => Some((format!("{}::{}:{}:{}:{challenge}", self.user, self.domain, hex(&self.lm_response), hex(&self.nt_response)), "netntlmv1")),
            n if n > 24 => Some((format!("{}::{}:{challenge}:{}:{}", self.user, self.domain, hex(&self.nt_response[..16]), hex(&self.nt_response[16..])), "netntlmv2")),
            _ => None,
        }
    }

    /// The credentials record: who, from where, and the crackable hash
    pub fn record(&self, server_challenge: &[u8; 8]) -> Value {
        let hash = self.hash(server_challenge);
        json!({
            "mechanism": "NTLM",
            "username": self.user,
            "domain": self.domain,
            "workstation": self.workstation,
            "anonymous": self.anonymous(),
            "hash_type": hash.as_ref().map(|(_, kind)| *kind),
            "hash": hash.map(|(line, _)| line),
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A DER tag-length-value
pub fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match contents.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend_from_slice(&[0x81, n as u8]),
        n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(contents);
    out
}

/// 1.3.6.1.4.1.311.2.2.10
const NTLMSSP_OID: &[u8] = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
/// 1.3.6.1.5.5.2
const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// The server's initial SPNEGO token (in the SMB2 NEGOTIATE response): NTLM is on offer
pub fn spnego_init() -> Vec<u8> {
    let mech_types = der(0xa0, &der(0x30, NTLMSSP_OID));
    let init = der(0xa0, &der(0x30, &mech_types));
    der(0x60, &[SPNEGO_OID, &init].concat())
}

/// A SPNEGO NegTokenResp: state 1 (accept-incomplete) naming NTLM as the mechanism (with
/// our CHALLENGE, or without a token to turn down a Kerberos-first client, which then
/// starts over with NTLM), or 2 (reject)
pub fn spnego_response(state: u8, token: Option<&[u8]>) -> Vec<u8> {
    let mut fields = der(0xa0, &der(0x0a, &[state]));
    if state == 1 {
        fields.extend(der(0xa1, NTLMSSP_OID));
    }
    if let Some(token) = token {
        fields.extend(der(0xa2, &der(0x04, token)));
    }
    der(0xa1, &der(0x30, &fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(message: &mut Vec<u8>, at: usize, value: &[u8]) {
        let offset = message.len() as u32;
        message[at..at + 2].copy_from_slice(&(value.len() as u16).to_le_bytes());
        message[at + 2..at + 4].copy_from_slice(&(value.len() as u16).to_le_bytes());
        message[at + 4..at + 8].copy_from_slice(&offset.to_le_bytes());
        message.extend_from_slice(value);
    }

    fn authenticate(nt: &[u8]) -> Vec<u8> {
        let mut message = vec![0u8; 64];
        message[..8].copy_from_slice(SIGNATURE);
        message[8] = 3;
        message[60..64].copy_from_slice(&NEGOTIATE_UNICODE.to_le_bytes());
        field(&mut message, 12, &[0xaa; 24]);
        field(&mut message, 20, nt);
        field(&mut message, 28, &utf16("CORP"));
        field(&mut message, 36, &utf16("alice"));
        field(&mut message, 44, &utf16("WS01"));
        message
    }

    #[test]
    fn challenges_carry_target_info_and_echo_flags() {
        let negotiate = [SIGNATURE.as_slice(), &1u32.to_le_bytes(), &(NEGOTIATE_UNICODE | EXTENDED_SESSION_SECURITY | NEGOTIATE_128).to_le_bytes()].concat();
        let message = challenge(&negotiate, *b"\x01\x23\x45\x67\x89\xab\xcd\xef");
        assert_eq!(message_type(&message), Some(2));
        assert_eq!(&message[24..32], b"\x01\x23\x45\x67\x89\xab\xcd\xef");
        let flags = u32_at(&message, 20).unwrap();
        assert!(flags & EXTENDED_SESSION_SECURITY != 0 && flags & TARGET_INFO != 0 && flags & NEGOTIATE_128 != 0);
        let info_offset = u32_at(&message, 44).unwrap() as usize;
        let info = &message[info_offset..];
        assert_eq!(u16_at(info, 0), Some(2)); // MsvAvNbDomainName first
        assert!(message.len() == info_offset + usize::from(u16_at(&message, 40).unwrap()));
    }

    #[test]
    fn hashes_in_hashcat_format() {
        let challenge = *b"\x11\x22\x33\x44\x55\x66\x77\x88";
        let v2 = Authenticate::parse(&authenticate(&[[0xbb; 16].as_slice(), &[0xcc; 12]].concat())).unwrap();
        assert_eq!((v2.user.as_str(), v2.domain.as_str(), v2.workstation.as_str()), ("alice", "CORP", "WS01"));
        let (line, kind) = v2.hash(&challenge).unwrap();
        assert_eq!(kind, "netntlmv2");
        assert_eq!(line, format!("alice::CORP:1122334455667788:{}:{}", "bb".repeat(16), "cc".repeat(12)));
        let v1 = Authenticate::parse(&authenticate(&[0xdd; 24])).unwrap();
        assert_eq!(v1.hash(&challenge).unwrap().0, format!("alice::CORP:{}:{}:1122334455667788", "aa".repeat(24), "dd".repeat(24)));
        let anonymous = Authenticate { user: String::new(), domain: String::new(), workstation: String::new(), lm_response: vec![0], nt_response: Vec::new() };
        assert!(anonymous.anonymous() && anonymous.hash(&challenge).is_none());
    }

    #[test]
    fn hostile_messages_dont_panic() {
        let good = authenticate(&[0xbb; 40]);
        for length in 0..good.len() {
            let _ = Authenticate::parse(&good[..length]);
        }
        let mut huge_offset = good.clone();
        huge_offset[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(Authenticate::parse(&huge_offset), None);
        assert_eq!(find(b"xxNTLMSSP\0\x03"), Some(&b"NTLMSSP\0\x03"[..]));
    }

    #[test]
    fn spnego_tokens_are_well_formed_der() {
        let token = spnego_response(1, Some(&[0x42; 300]));
        assert_eq!(&token[..4], &[0xa1, 0x82, 0x01, 0x4b]); // a1, then a 2-byte length: 331
        assert_eq!(token.len(), 4 + 331);
        assert_eq!(spnego_response(1, None).len(), 2 + 2 + 5 + 14);
        assert_eq!(spnego_response(2, None), [0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x02]);
        assert_eq!(spnego_init()[0], 0x60);
    }
}
