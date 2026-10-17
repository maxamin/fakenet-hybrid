//! DNS (hickory-proto) over UDP and TCP. Each query is an event, with `meta.qname` &
//! `meta.qtype`. The daemon may answer with text lines ("A 10.6.6.6", "AAAA ::1",
//! "MX 10 mail.example", "TXT text", "CNAME/NS/PTR name", "NXDOMAIN", "SERVFAIL"), else the
//! configured defaults apply.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::DnsDefaults;
use crate::session::Session;
use crate::stream::BoxStream;

/// The answer to a query, as records or a response code
#[derive(Debug, PartialEq)]
pub enum Answer {
    Records(Vec<RData>),
    Code(ResponseCode),
}

/// Names Windows checks to decide it's online (NCSI): answered with the real addresses
const NCSI: &[(&str, RecordType, &str)] = &[
    ("dns.msftncsi.com", RecordType::A, "131.107.255.255"),
    ("dns.msftncsi.com", RecordType::AAAA, "fd3e:4f5a:5b81::1"),
];

/// Per-domain addresses handed out, for PTR answers
static REVERSE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<Ipv4Addr, String>>> = std::sync::OnceLock::new();

/// A stable address for `name` inside `pool` (CIDR); None if the pool is malformed
pub fn pool_address(name: &str, pool: &str) -> Option<Ipv4Addr> {
    let (base, bits) = pool.split_once('/')?;
    let base: Ipv4Addr = base.parse().ok()?;
    let bits: u32 = bits.parse().ok().filter(|b| *b <= 30)?;
    let size = 1u64 << (32 - bits);
    // FNV-1a: stable across runs, so the same name always gets the same address
    let hash = name.trim_end_matches('.').to_ascii_lowercase().bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3));
    let offset = 1 + hash % (size - 2); // Not the network or broadcast address
    let network = u32::from(base) & !((size - 1) as u32);
    Some(Ipv4Addr::from(network + offset as u32))
}

/// Random-looking labels, as domain generation algorithms produce ("xkqjzwvbtrnp")
pub fn looks_random(name: &str) -> bool {
    let label = name.trim_end_matches('.').split('.').next().unwrap_or("").to_ascii_lowercase();
    if label.len() < 10 || !label.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let letters: Vec<char> = label.chars().filter(char::is_ascii_alphabetic).collect();
    let vowels = letters.iter().filter(|c| "aeiouy".contains(**c)).count();
    let digits = label.len() - letters.len();
    let mut run = 0;
    let mut longest_consonants = 0;
    for c in label.chars() {
        if c.is_ascii_alphabetic() && !"aeiouy".contains(c) {
            run += 1;
            longest_consonants = longest_consonants.max(run);
        } else {
            run = 0;
        }
    }
    let vowel_ratio = vowels as f64 / letters.len().max(1) as f64;
    longest_consonants >= 5 || vowel_ratio < 0.2 || (digits >= 3 && letters.len() >= 5 && digits * 4 >= label.len())
}

/// The configured default answer for a query
pub fn default_answer_for(qname: &str, qtype: RecordType, defaults: &DnsDefaults) -> Answer {
    let name = qname.trim_end_matches('.').to_ascii_lowercase();
    if let Some((_, _, address)) = NCSI.iter().find(|(n, t, _)| *n == name && *t == qtype) {
        return match address.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(v4)) => Answer::Records(vec![RData::A(A(v4))]),
            Ok(std::net::IpAddr::V6(v6)) => Answer::Records(vec![RData::AAAA(AAAA(v6))]),
            Err(_) => Answer::Records(vec![]),
        };
    }
    if defaults.nxdomain_random && looks_random(&name) {
        return Answer::Code(ResponseCode::NXDomain);
    }
    if qtype == RecordType::PTR && defaults.per_domain {
        let octets: Vec<u8> = name.strip_suffix(".in-addr.arpa").map(|r| r.split('.').filter_map(|o| o.parse().ok()).collect()).unwrap_or_default();
        if let [d, c, b, a] = octets[..] {
            let ip = Ipv4Addr::new(a, b, c, d);
            let known = REVERSE.get().and_then(|m| m.lock().ok()?.get(&ip).cloned());
            if let Some(known) = known.and_then(|n| Name::from_ascii(format!("{n}.")).ok()) {
                return Answer::Records(vec![RData::PTR(PTR(known))]);
            }
        }
    }
    if defaults.per_domain && matches!(qtype, RecordType::A | RecordType::ANY) {
        if let Some(ip) = pool_address(&name, &defaults.pool) {
            let reverse = REVERSE.get_or_init(Default::default);
            if let Ok(mut reverse) = reverse.lock() {
                if reverse.len() < 100_000 {
                    reverse.insert(ip, name.clone());
                }
            }
            return Answer::Records(vec![RData::A(A(ip))]);
        }
    }
    default_answer(qtype, defaults)
}

/// The configured default answer for a query type
pub fn default_answer(qtype: RecordType, defaults: &DnsDefaults) -> Answer {
    let records = match qtype {
        RecordType::A | RecordType::ANY => vec![RData::A(A(defaults.a))],
        RecordType::AAAA => defaults.aaaa.map(|ip| vec![RData::AAAA(AAAA(ip))]).unwrap_or_default(),
        RecordType::MX => Name::from_ascii(&defaults.mx).map(|n| vec![RData::MX(MX::new(10, n))]).unwrap_or_default(),
        RecordType::TXT => vec![RData::TXT(TXT::new(vec![defaults.txt.clone()]))],
        _ => vec![], // NODATA: no records, no error
    };
    Answer::Records(records)
}

/// Parses the daemon's text answer. Unparseable lines are skipped (and reported).
pub fn parse_answer(text: &str) -> (Answer, Vec<String>) {
    let mut records = Vec::new();
    let mut errors = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (kind, value) = line.split_once(char::is_whitespace).map(|(k, v)| (k, v.trim())).unwrap_or((line, ""));
        let name = || Name::from_ascii(value).map_err(|e| e.to_string());
        let record = match kind.to_ascii_uppercase().as_str() {
            "NXDOMAIN" => return (Answer::Code(ResponseCode::NXDomain), errors),
            "SERVFAIL" => return (Answer::Code(ResponseCode::ServFail), errors),
            "REFUSED" => return (Answer::Code(ResponseCode::Refused), errors),
            "A" => value.parse::<Ipv4Addr>().map(|ip| RData::A(A(ip))).map_err(|e| e.to_string()),
            "AAAA" => value.parse::<Ipv6Addr>().map(|ip| RData::AAAA(AAAA(ip))).map_err(|e| e.to_string()),
            "TXT" => Ok(RData::TXT(TXT::new(vec![value.to_string()]))),
            "MX" => {
                let (preference, exchange) = match value.split_once(char::is_whitespace) {
                    Some((p, e)) if p.parse::<u16>().is_ok() => (p.parse().unwrap(), e.trim()),
                    _ => (10, value),
                };
                Name::from_ascii(exchange).map(|n| RData::MX(MX::new(preference, n))).map_err(|e| e.to_string())
            }
            "CNAME" => name().map(|n| RData::CNAME(CNAME(n))),
            "NS" => name().map(|n| RData::NS(NS(n))),
            "PTR" => name().map(|n| RData::PTR(PTR(n))),
            other => Err(format!("unknown record type {other}")),
        };
        match record {
            Ok(record) => records.push(record),
            Err(e) => errors.push(format!("{line}: {e}")),
        }
    }
    (Answer::Records(records), errors)
}

/// Answers one DNS message. None for things that aren't queries (never answer responses:
/// that could make the nucleus a reflector).
pub async fn answer(message: &[u8], session: &mut Session) -> Option<Vec<u8>> {
    let request = match Message::from_vec(message) {
        Ok(request) if request.metadata.message_type == MessageType::Query && !request.queries.is_empty() => request,
        _ => {
            session.log("malformed", json!({ "bytes": message.len() }));
            return None;
        }
    };
    let query = request.queries[0].clone();
    let qname = query.name().to_ascii();
    let qtype = query.query_type();
    session.client_data(message);

    let defaults = session.ctx.defaults.dns.clone();
    let meta = json!({ "qname": qname.trim_end_matches('.'), "qtype": qtype.to_string() });
    let action = session.decide(message, meta).await;
    let answer = match action.and_then(|a| a.response) {
        Some(text) => {
            let (answer, errors) = parse_answer(&String::from_utf8_lossy(&text));
            if !errors.is_empty() {
                session.log("invalid_answer", json!({ "errors": errors }));
            }
            answer
        }
        None => default_answer_for(&qname, qtype, &defaults),
    };

    let mut response = Message::new(request.metadata.id, MessageType::Response, request.metadata.op_code);
    response.metadata.authoritative = true;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.add_query(query.clone());
    match answer {
        Answer::Code(code) => response.metadata.response_code = code,
        Answer::Records(records) => {
            for rdata in records {
                response.add_answer(Record::from_rdata(query.name().clone(), defaults.ttl, rdata));
            }
        }
    }
    let bytes = response.to_vec().ok()?;
    session.server_data(&bytes);
    Some(bytes)
}

/// DNS over TCP: 2-byte length-prefixed messages, several per connection (RFC 7766)
pub async fn handle_tcp(mut stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    loop {
        let mut length = [0u8; 2];
        match tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut length)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()),
        }
        let mut message = vec![0u8; u16::from_be_bytes(length) as usize];
        tokio::time::timeout(session.ctx.timeout, stream.read_exact(&mut message)).await??;
        if let Some(reply) = answer(&message, &mut session).await {
            stream.write_all(&(reply.len() as u16).to_be_bytes()).await?;
            stream.write_all(&reply).await?;
            stream.flush().await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_daemon_answers() {
        let (answer, errors) = parse_answer("A 10.6.6.6\nAAAA 2001:db8::6\nMX 5 mail.c2.example\nTXT hello world\nbogus line\n");
        let Answer::Records(records) = answer else { panic!() };
        assert_eq!(records.len(), 4);
        assert_eq!(records[0], RData::A(A("10.6.6.6".parse().unwrap())));
        assert!(matches!(&records[2], RData::MX(mx) if mx.preference == 5));
        assert_eq!(errors.len(), 1);
        assert_eq!(parse_answer("NXDOMAIN").0, Answer::Code(ResponseCode::NXDomain));
        assert_eq!(parse_answer("").0, Answer::Records(vec![]));
    }

    #[test]
    fn realistic_answers() {
        let defaults = DnsDefaults { per_domain: true, nxdomain_random: true, ..DnsDefaults::default() };
        let a = |name: &str| match default_answer_for(name, RecordType::A, &defaults) {
            Answer::Records(r) => match r.first() { Some(RData::A(a)) => Some(a.0), _ => None },
            Answer::Code(_) => None,
        };
        let c2 = a("c2.evil.example").unwrap();
        assert_eq!(a("C2.Evil.Example.").unwrap(), c2); // Stable, case-insensitive
        assert_ne!(a("other.example").unwrap(), c2);
        assert!((u32::from(c2) & 0xfffe_0000) == u32::from(Ipv4Addr::new(198, 18, 0, 0)));
        let reverse = format!("{}.{}.{}.{}.in-addr.arpa", c2.octets()[3], c2.octets()[2], c2.octets()[1], c2.octets()[0]);
        assert!(matches!(default_answer_for(&reverse, RecordType::PTR, &defaults), Answer::Records(r) if r.len() == 1));
        assert_eq!(default_answer_for("xkqjzwvbtrnpl.com", RecordType::A, &defaults), Answer::Code(ResponseCode::NXDomain));
        assert_eq!(a("dns.msftncsi.com").unwrap(), Ipv4Addr::new(131, 107, 255, 255));
        for normal in ["update-service.example", "microsoftonline.com", "connectivitycheck.gstatic.com", "cdn.example"] {
            assert!(!looks_random(normal), "{normal}");
        }
        assert!(looks_random("a8f3k2m9x7q1z.net"));
    }

    #[test]
    fn answers_defaults_by_type() {
        let defaults = DnsDefaults::default();
        assert_eq!(default_answer(RecordType::A, &defaults), Answer::Records(vec![RData::A(A(defaults.a))]));
        assert_eq!(default_answer(RecordType::AAAA, &defaults), Answer::Records(vec![])); // None configured
        assert_eq!(default_answer(RecordType::SRV, &defaults), Answer::Records(vec![]));
    }
}
