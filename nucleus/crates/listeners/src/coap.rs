//! CoAP (RFC 7252), the IoT web: each request is an event (method, URI path & query,
//! content format), answered with the daemon's payload or an empty success: 2.05 Content
//! for GET (`/.well-known/core` lists a few plausible resources), 2.04 Changed for
//! POST/PUT, 2.02 Deleted for DELETE. Confirmable requests get piggybacked ACKs; pings
//! get resets.

use serde_json::json;

use crate::session::Session;

#[derive(Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub kind: u8,
    pub code: u8,
    pub message_id: u16,
    pub token: &'a [u8],
    pub host: Option<String>,
    pub path: String,
    pub query: Vec<String>,
    pub content_format: Option<u16>,
    pub payload: &'a [u8],
}

impl<'a> Request<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Request<'a>> {
        let [first, code, high, low, rest @ ..] = data else { return None };
        let token_length = usize::from(first & 0x0f);
        if first >> 6 != 1 || token_length > 8 || rest.len() < token_length {
            return None;
        }
        let mut request = Request {
            kind: (first >> 4) & 3,
            code: *code,
            message_id: u16::from_be_bytes([*high, *low]),
            token: &rest[..token_length],
            host: None,
            path: String::new(),
            query: Vec::new(),
            content_format: None,
            payload: &[],
        };
        let mut options = &rest[token_length..];
        let mut number = 0u32;
        while let Some((&byte, after)) = options.split_first() {
            if byte == 0xff {
                request.payload = after;
                break;
            }
            let mut cursor = after;
            let mut extended = |nibble: u8| -> Option<u32> {
                match nibble {
                    13 => {
                        let (&b, rest) = cursor.split_first()?;
                        cursor = rest;
                        Some(u32::from(b) + 13)
                    }
                    14 => {
                        let (bytes, rest) = cursor.split_at_checked(2)?;
                        cursor = rest;
                        Some(u32::from(u16::from_be_bytes([bytes[0], bytes[1]])) + 269)
                    }
                    15 => None,
                    n => Some(u32::from(n)),
                }
            };
            let delta = extended(byte >> 4)?;
            let length = extended(byte & 0x0f)? as usize;
            let (value, rest) = cursor.split_at_checked(length)?;
            number += delta;
            let text = || String::from_utf8_lossy(value).into_owned();
            match number {
                3 => request.host = Some(text()),
                11 => {
                    request.path.push('/');
                    request.path.push_str(&text());
                }
                12 => request.content_format = Some(value.iter().fold(0u16, |n, b| (n << 8) | u16::from(*b))),
                15 => request.query.push(text()),
                _ => {}
            }
            options = rest;
        }
        if request.path.is_empty() {
            request.path.push('/');
        }
        Some(request)
    }

    pub fn method(&self) -> &'static str {
        match self.code {
            1 => "GET",
            2 => "POST",
            3 => "PUT",
            4 => "DELETE",
            5 => "FETCH",
            6 => "PATCH",
            7 => "iPATCH",
            _ => "?",
        }
    }
}

/// A response to `request`: ACK for confirmable requests (piggybacked), NON otherwise
fn response(request: &Request<'_>, code: u8, content_format: Option<u16>, payload: &[u8]) -> Vec<u8> {
    let kind = if request.kind == 0 { 2 } else { 1 };
    let message_id = if request.kind == 0 { request.message_id } else { request.message_id.wrapping_add(0x5a5a) };
    let mut out = vec![0x40 | (kind << 4) | request.token.len() as u8, code];
    out.extend_from_slice(&message_id.to_be_bytes());
    out.extend_from_slice(request.token);
    if let Some(format) = content_format {
        // Content-Format (12): delta 12 from option 0
        match format {
            0 => out.push(0xc0),
            f if f < 256 => out.extend_from_slice(&[0xc1, f as u8]),
            f => out.extend_from_slice(&[[0xc2].as_slice(), &f.to_be_bytes()].concat()),
        }
    }
    if !payload.is_empty() {
        out.push(0xff);
        out.extend_from_slice(payload);
    }
    out
}

const WELL_KNOWN_CORE: &[u8] = b"</sensors/temp>;rt=\"temperature-c\";if=\"sensor\",</sensors/light>;rt=\"light-lux\";if=\"sensor\",</firmware>;rt=\"firmware\",</config>;ct=50";

pub async fn handle(data: &[u8], session: &mut Session) -> Option<Vec<u8>> {
    let request = Request::parse(data)?;
    // An empty confirmable message is a ping: reset
    if request.code == 0 {
        return (request.kind == 0).then(|| vec![0x70, 0, data[2], data[3]]);
    }
    // Responses and unknown classes aren't requests
    if request.code >> 5 != 0 {
        return None;
    }
    let meta = json!({
        "method": request.method(), "path": request.path, "query": request.query, "host": request.host,
        "content_format": request.content_format, "confirmable": request.kind == 0,
    });
    session.log("coap_request", meta.clone());
    let (code, format, default): (u8, Option<u16>, &[u8]) = match request.code {
        1 if request.path == "/.well-known/core" => (0x45, Some(40), WELL_KNOWN_CORE),
        1 | 5 => (0x45, Some(0), b""),
        2 | 3 | 6 | 7 => (0x44, None, b""),
        4 => (0x42, None, b""),
        _ => (0x85, None, b""), // 4.05 Method Not Allowed
    };
    let (payload, _) = session.answer(request.payload, meta, default.to_vec(), false).await;
    Some(response(&request, code, if payload.is_empty() { None } else { format.or(Some(0)) }, &payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requests() {
        // CON POST, token ab cd, Uri-Host, Uri-Path api/v1, Content-Format 50 (JSON), Uri-Query, payload
        let data = b"\x42\x02\x12\x34\xab\xcd\x3a10.0.0.5:5\x83api\x02v1\x11\x32\x34id=7\xff{\"t\":1}";
        let request = Request::parse(data).unwrap();
        assert_eq!(request.method(), "POST");
        assert_eq!(request.token, b"\xab\xcd");
        assert_eq!(request.host.as_deref(), Some("10.0.0.5:5"));
        assert_eq!(request.path, "/api/v1");
        assert_eq!(request.content_format, Some(50));
        assert_eq!(request.query, ["id=7"]);
        assert_eq!(request.payload, b"{\"t\":1}");
    }

    #[test]
    fn piggybacks_acks() {
        let request = Request::parse(b"\x41\x01\x00\x07\x99\xb4temp").unwrap();
        assert_eq!(response(&request, 0x45, Some(0), b"21.5"), b"\x61\x45\x00\x07\x99\xc0\xff21.5");
        // Non-confirmable: a NON response with its own message ID
        let request = Request::parse(b"\x50\x01\x00\x07").unwrap();
        assert_eq!(&response(&request, 0x45, None, b"")[..2], &[0x50, 0x45]);
    }

    #[test]
    fn rejects_truncated_options() {
        assert_eq!(Request::parse(b"\x40\x01\x00\x01\xb6sta"), None);
        assert_eq!(Request::parse(b"\x40\x01\x00\x01\xdd"), None);
        assert_eq!(Request::parse(b"\x40\x01\x00\x01\xf0"), None);
    }
}
