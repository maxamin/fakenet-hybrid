//! MQTT 3.1 / 3.1.1 / 5 broker (IoT and C2 channels): CONNECT (credentials and client ID
//! captured), SUBSCRIBE, PUBLISH (QoS 0-2), UNSUBSCRIBE, PING. SUBSCRIBE and PUBLISH are
//! events: a non-empty response from the daemon (or the explorer) is a message payload,
//! delivered to the client as a PUBLISH on its first subscribed topic without wildcards
//! (else the topic it published on). That's how a rule tasks a bot over MQTT.

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::lines::preview;
use crate::session::Session;
use crate::stream::BoxStream;

const MAX_PACKET: usize = 1 << 20;

/// One MQTT control packet: (first byte, contents)
async fn read_packet(stream: &mut BoxStream, session: &Session) -> anyhow::Result<Option<(u8, Vec<u8>)>> {
    let mut first = [0u8; 1];
    match tokio::time::timeout(session.ctx.timeout * 4, stream.read_exact(&mut first)).await {
        Err(_) => return Ok(None), // Past several keep-alives without a ping
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Ok(result) => result?,
    };
    let mut length = 0usize;
    for shift in [0, 7, 14, 21] {
        let mut byte = [0u8; 1];
        tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut byte)).await??;
        length |= usize::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            anyhow::ensure!(length <= MAX_PACKET, "MQTT packet too large");
            let mut contents = vec![0u8; length];
            tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut contents)).await??;
            return Ok(Some((first[0], contents)));
        }
    }
    anyhow::bail!("bad MQTT remaining length")
}

/// A packet with its remaining length
fn packet(first: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![first];
    let mut length = contents.len();
    loop {
        let mut byte = (length & 0x7f) as u8;
        length >>= 7;
        if length > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if length == 0 {
            break;
        }
    }
    out.extend_from_slice(contents);
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        (self.0.len() >= n).then(|| {
            let (head, rest) = self.0.split_at(n);
            self.0 = rest;
            head
        })
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn binary(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }
    fn string(&mut self) -> Option<String> {
        self.binary().map(|b| String::from_utf8_lossy(b).into_owned())
    }
    fn varint(&mut self) -> Option<usize> {
        let mut value = 0usize;
        for shift in [0, 7, 14, 21] {
            let byte = self.u8()?;
            value |= usize::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }
    /// MQTT 5 properties: skipped
    fn properties(&mut self, v5: bool) -> Option<()> {
        if v5 {
            let length = self.varint()?;
            self.take(length)?;
        }
        Some(())
    }
}

fn encode_string(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let bytes = &bytes[..bytes.len().min(u16::MAX as usize)];
    [(bytes.len() as u16).to_be_bytes().as_slice(), bytes].concat()
}

/// A PUBLISH (QoS 0) of `payload` on `topic`
fn publish(topic: &str, payload: &[u8], v5: bool) -> Vec<u8> {
    let mut contents = encode_string(topic);
    if v5 {
        contents.push(0); // No properties
    }
    contents.extend_from_slice(payload);
    packet(0x30, &contents)
}

pub async fn handle(mut stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let mut v5 = false;
    let mut subscriptions: Vec<String> = Vec::new();
    loop {
        let Some((first, contents)) = read_packet(&mut stream, &session).await? else { return Ok(()) };
        session.client_data(&packet(first, &contents));
        let mut reader = Reader(&contents);
        let mut replies: Vec<Vec<u8>> = Vec::new();
        match first >> 4 {
            // CONNECT
            1 => {
                let protocol = reader.string().unwrap_or_default();
                let level = reader.u8().unwrap_or(4);
                v5 = level == 5;
                let flags = reader.u8().unwrap_or(0);
                let keep_alive = reader.u16().unwrap_or(0);
                reader.properties(v5);
                let client_id = reader.string().unwrap_or_default();
                let (mut will_topic, mut will_message) = (None, None);
                if flags & 0x04 != 0 {
                    reader.properties(v5);
                    will_topic = reader.string();
                    will_message = reader.binary().map(|m| preview(m, 256));
                }
                let username = (flags & 0x80 != 0).then(|| reader.string()).flatten();
                let password = (flags & 0x40 != 0).then(|| reader.binary().map(|p| preview(p, 256))).flatten();
                if username.is_some() || password.is_some() {
                    session.log("credentials", json!({ "mechanism": "MQTT", "username": username, "password": password }));
                }
                let meta = json!({ "packet": "CONNECT", "protocol": protocol, "level": level, "client_id": client_id, "keep_alive": keep_alive, "will_topic": will_topic, "will_message": will_message, "username": username });
                session.log("mqtt_connect", meta.clone());
                session.notify(&contents, meta);
                replies.push(if v5 { packet(0x20, &[0, 0, 0]) } else { packet(0x20, &[0, 0]) });
            }
            // PUBLISH
            3 => {
                let qos = (first >> 1) & 3;
                let topic = reader.string().unwrap_or_default();
                let id = if qos > 0 { reader.u16() } else { None };
                reader.properties(v5);
                let payload = reader.0;
                let meta = json!({ "packet": "PUBLISH", "topic": topic, "qos": qos, "retain": first & 1 == 1, "message": preview(payload, 512), "message_bytes": payload.len() });
                session.log("mqtt_publish", meta.clone());
                match (qos, id) {
                    (1, Some(id)) => replies.push(packet(0x40, &id.to_be_bytes())),
                    (2, Some(id)) => replies.push(packet(0x50, &id.to_be_bytes())),
                    _ => {}
                }
                let (response, close) = session.answer(payload, meta, Vec::new(), false).await;
                if !response.is_empty() {
                    let target = subscriptions.iter().find(|t| !t.contains(['+', '#'])).cloned().unwrap_or(topic);
                    replies.push(publish(&target, &response, v5));
                }
                if close {
                    send(&mut stream, &session, &replies).await?;
                    return Ok(());
                }
            }
            // PUBREL -> PUBCOMP
            6 => replies.push(packet(0x70, reader.take(2).unwrap_or(&[0, 0]))),
            // SUBSCRIBE
            8 => {
                let id = reader.u16().unwrap_or(0);
                reader.properties(v5);
                let mut topics = Vec::new();
                while let (Some(topic), Some(options)) = (reader.string(), reader.u8()) {
                    topics.push((topic, options & 3));
                }
                let names: Vec<&str> = topics.iter().map(|(t, _)| t.as_str()).collect();
                let meta = json!({ "packet": "SUBSCRIBE", "topics": names });
                session.log("mqtt_subscribe", meta.clone());
                subscriptions.extend(topics.iter().map(|(t, _)| t.clone()));
                let mut ack = id.to_be_bytes().to_vec();
                if v5 {
                    ack.push(0);
                }
                ack.extend(topics.iter().map(|(_, qos)| *qos));
                replies.push(packet(0x90, &ack));
                // A rule (or the explorer) may answer with a message for the new subscriber
                let (response, close) = session.answer(&contents, meta, Vec::new(), false).await;
                if let Some(topic) = topics.iter().map(|(t, _)| t).find(|t| !t.contains(['+', '#'])).filter(|_| !response.is_empty()) {
                    replies.push(publish(topic, &response, v5));
                }
                if close {
                    send(&mut stream, &session, &replies).await?;
                    return Ok(());
                }
            }
            // UNSUBSCRIBE
            10 => {
                let id = reader.u16().unwrap_or(0);
                reader.properties(v5);
                let mut count = 0;
                while let Some(topic) = reader.string() {
                    subscriptions.retain(|t| *t != topic);
                    count += 1;
                }
                let mut ack = id.to_be_bytes().to_vec();
                if v5 {
                    ack.push(0);
                    ack.extend(std::iter::repeat_n(0u8, count));
                }
                replies.push(packet(0xb0, &ack));
            }
            12 => replies.push(packet(0xd0, &[])),
            14 => return Ok(()),
            _ => {}
        }
        send(&mut stream, &session, &replies).await?;
    }
}

async fn send(stream: &mut BoxStream, session: &Session, replies: &[Vec<u8>]) -> std::io::Result<()> {
    for reply in replies {
        stream.write_all(reply).await?;
        session.server_data(reply);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_remaining_lengths() {
        assert_eq!(packet(0xd0, &[]), [0xd0, 0]);
        assert_eq!(&packet(0x30, &[0; 200])[..3], &[0x30, 0xc8, 0x01]);
        assert_eq!(&packet(0x30, &[0; 16384])[..4], &[0x30, 0x80, 0x80, 0x01]);
    }

    #[test]
    fn publishes_for_both_versions() {
        assert_eq!(publish("bot/1/cmd", b"run", false), b"\x30\x0e\x00\x09bot/1/cmdrun");
        assert_eq!(publish("t", b"x", true), b"\x30\x05\x00\x01t\x00x");
    }

    #[test]
    fn readers_stop_at_truncation() {
        let mut reader = Reader(b"\x00\x05ab");
        assert_eq!(reader.string(), None);
        let mut reader = Reader(&[0xff, 0xff, 0xff, 0xff, 0x01]);
        assert_eq!(reader.varint(), None);
    }
}
