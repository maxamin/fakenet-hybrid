//! NTP (RFC 5905) / SNTP (RFC 4330): answers time requests. Each request is an event
//! (`meta.version`); the daemon may answer with a time offset in seconds as text ("+86400",
//! "-3600") to shift the time served, or with a complete 48-byte reply. Default: the
//! configured `defaults.ntp.time_offset`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::session::Session;

const NTP_EPOCH_OFFSET: i64 = 2_208_988_800; // Seconds from 1900 to 1970
const MODE_SERVER: u8 = 4;

/// A 64-bit NTP timestamp: seconds since 1900 and the fraction in 1/2^32ths
pub fn ntp_timestamp(time: SystemTime, offset_seconds: i64) -> [u8; 8] {
    let since_unix = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = (since_unix.as_secs() as i64 + NTP_EPOCH_OFFSET + offset_seconds) as u64;
    let fraction = ((u64::from(since_unix.subsec_nanos()) << 32) / 1_000_000_000) as u32;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&(seconds as u32).to_be_bytes());
    out[4..].copy_from_slice(&fraction.to_be_bytes());
    out
}

pub fn reply(request: &[u8], offset: i64, now: SystemTime) -> Vec<u8> {
    let version = (request[0] >> 3) & 0x07;
    let timestamp = ntp_timestamp(now, offset);
    let mut reply = vec![0u8; 48];
    reply[0] = version << 3 | MODE_SERVER; // LI = 0
    reply[1] = 2; // Stratum: secondary server
    reply[2] = request[2]; // Poll interval, as asked
    reply[3] = 0xec; // Precision: 2^-20 s
    reply[4..8].copy_from_slice(&[0, 0, 0, 0x10]); // Root delay
    reply[8..12].copy_from_slice(&[0, 0, 0, 0x20]); // Root dispersion
    reply[12..16].copy_from_slice(&[127, 127, 1, 0]); // Reference ID
    reply[16..24].copy_from_slice(&ntp_timestamp(now - Duration::from_secs(60), offset)); // Reference
    reply[24..32].copy_from_slice(&request[40..48]); // Origin: the client's transmit time
    reply[32..40].copy_from_slice(&timestamp); // Receive
    reply[40..48].copy_from_slice(&timestamp); // Transmit
    reply
}

pub async fn handle(data: &[u8], session: &mut Session) -> Option<Vec<u8>> {
    session.client_data(data);
    if !fakenet_sniffer::is_ntp(data) {
        session.log("malformed", json!({ "bytes": data.len() }));
        return None;
    }
    let version = (data[0] >> 3) & 0x07;
    let mut offset = session.ctx.defaults.load().ntp.time_offset;
    let answer = session.decide(data, json!({ "version": version, "default_offset": offset })).await.and_then(|a| a.response);
    let packet = match answer {
        Some(bytes) if bytes.len() == 48 => bytes,
        Some(text) => {
            match String::from_utf8_lossy(&text).trim().trim_start_matches('+').parse::<i64>() {
                Ok(daemon_offset) => offset = daemon_offset,
                Err(_) => session.log("invalid_answer", json!({ "error": "expected a time offset or a 48-byte reply" })),
            }
            reply(data, offset, SystemTime::now())
        }
        None => reply(data, offset, SystemTime::now()),
    };
    session.log("time_request", json!({ "version": version, "time_offset": offset }));
    session.server_data(&packet);
    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_shifted_time() {
        let mut request = vec![0u8; 48];
        request[0] = 0x23;
        request[40..48].copy_from_slice(b"origin!!");
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let answer = reply(&request, 86_400, now);
        assert_eq!(answer[0], 0x24); // v4, server
        assert_eq!(&answer[24..32], b"origin!!");
        let seconds = u32::from_be_bytes(answer[40..44].try_into().unwrap()) as i64;
        assert_eq!(seconds, 1_700_000_000 + NTP_EPOCH_OFFSET + 86_400);
    }
}
