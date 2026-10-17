//! Works out a connection's protocol from its first bytes and destination port, like
//! FakeNet-NG's `taste()`: each protocol scores the data (+2 for a recognizable first
//! message) and the port (+1 for its usual ports); the highest score wins, ties go to the
//! earlier candidate, and raw is the fallback.
//!
//! One deliberate difference: FakeNet-NG scores FTP commands +1, so FTP on port 80 ties with
//! HTTP's port score. Here every recognizable message scores +2, so content beats port.

use fakenet_schema::{Protocol, Transport};

/// Candidates in tie-break order. FTP precedes POP3, so a bare "USER x" on a port that's
/// neither 21 nor 110 is treated as FTP (FTP on odd ports is far more common).
pub const DEFAULT_ORDER: &[Protocol] = &[
    Protocol::Http, Protocol::Dns, Protocol::Tftp, Protocol::Ntp, Protocol::Ssh, Protocol::Redis, Protocol::Telnet,
    Protocol::Socks, Protocol::Syslog, Protocol::Smtp, Protocol::Ftp, Protocol::Pop3, Protocol::Imap, Protocol::Irc,
    // Port-only services (nothing to recognize in their requests)
    Protocol::Echo, Protocol::Discard, Protocol::Daytime, Protocol::Chargen, Protocol::Time, Protocol::Qotd, Protocol::Finger,
    Protocol::Whois, Protocol::Raw,
];

pub fn supports(protocol: Protocol, transport: Transport) -> bool {
    match transport {
        Transport::Tcp => !matches!(protocol, Protocol::Tftp | Protocol::Ntp),
        Transport::Udp => matches!(
            protocol,
            Protocol::Dns | Protocol::Tftp | Protocol::Ntp | Protocol::Syslog | Protocol::Echo | Protocol::Discard
                | Protocol::Daytime | Protocol::Chargen | Protocol::Time | Protocol::Qotd | Protocol::Raw
        ),
    }
}

pub fn default_ports(protocol: Protocol) -> &'static [u16] {
    match protocol {
        Protocol::Http => &[80, 443, 8000, 8080, 8443],
        Protocol::Dns => &[53],
        Protocol::Smtp => &[25, 465, 587],
        Protocol::Pop3 => &[110, 995],
        Protocol::Ftp => &[21],
        Protocol::Tftp => &[69],
        Protocol::Irc => &[194, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6697],
        Protocol::Imap => &[143, 993],
        Protocol::Ssh => &[22, 2222],
        Protocol::Telnet => &[23, 2323],
        Protocol::Redis => &[6379],
        Protocol::Ntp => &[123],
        Protocol::Socks => &[1080],
        Protocol::Syslog => &[514, 601],
        Protocol::Echo => &[7],
        Protocol::Discard => &[9],
        Protocol::Daytime => &[13],
        Protocol::Chargen => &[19],
        Protocol::Time => &[37],
        Protocol::Qotd => &[17],
        Protocol::Finger => &[79],
        Protocol::Whois => &[43],
        Protocol::Raw => &[],
    }
}

/// Protocols where the server speaks first: a silent client on their port awaits our greeting
pub fn server_speaks_first(protocol: Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Smtp | Protocol::Pop3 | Protocol::Ftp | Protocol::Imap | Protocol::Ssh | Protocol::Telnet | Protocol::Daytime
            | Protocol::Chargen | Protocol::Time | Protocol::Qotd
    )
}

fn trim_start(data: &[u8]) -> &[u8] {
    &data[data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(data.len())..]
}

fn starts_with_any(data: &[u8], prefixes: &[&[u8]]) -> bool {
    let data = trim_start(data);
    prefixes.iter().any(|p| data.len() >= p.len() && data[..p.len()].eq_ignore_ascii_case(p))
}

/// HTTP/1.x request methods, and the HTTP/2 connection preface (after TLS with ALPN "h2",
/// or prior-knowledge cleartext h2c)
const HTTP_METHODS: &[&[u8]] = &[
    b"GET ", b"HEAD ", b"POST ", b"PUT ", b"DELETE ", b"TRACE ", b"OPTIONS ", b"CONNECT ", b"PATCH ", b"PRI * HTTP/2.0",
];
const SMTP_COMMANDS: &[&[u8]] = &[b"HELO ", b"EHLO ", b"MAIL FROM", b"RCPT TO", b"STARTTLS", b"AUTH "];
const POP3_COMMANDS: &[&[u8]] = &[b"USER ", b"PASS ", b"APOP ", b"STAT", b"LIST", b"RETR ", b"CAPA", b"STLS", b"UIDL"];
const FTP_COMMANDS: &[&[u8]] = &[
    b"USER ", b"PASS ", b"SYST", b"FEAT", b"PWD", b"CWD ", b"PASV", b"EPSV", b"PORT ", b"EPRT ", b"TYPE ",
    b"RETR ", b"STOR ", b"LIST", b"NLST", b"AUTH TLS", b"OPTS ",
];
const IRC_COMMANDS: &[&[u8]] = &[b"NICK ", b"USER ", b"PASS ", b"JOIN ", b"PRIVMSG ", b"CAP LS", b"PING "];

/// FTP and POP3 share USER/PASS/LIST/RETR; FTP-only commands score higher, so FTP sessions
/// opening with them aren't mistaken for POP3 (and vice versa).
const FTP_ONLY: &[&[u8]] = &[b"SYST", b"FEAT", b"PWD", b"CWD ", b"PASV", b"EPSV", b"PORT ", b"EPRT ", b"TYPE ", b"AUTH TLS", b"OPTS "];
const POP3_ONLY: &[&[u8]] = &[b"APOP ", b"STAT", b"CAPA", b"STLS", b"UIDL"];

pub fn is_dns_query(data: &[u8]) -> bool {
    if data.len() < 17 {
        return false;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let questions = u16::from_be_bytes([data[4], data[5]]);
    let is_query = flags & 0x8000 == 0 && (flags >> 11) & 0xf == 0;
    if !is_query || questions == 0 {
        return false;
    }
    // A plausible first QNAME: labels of 1-63 bytes ending with a zero byte
    let mut i = 12;
    while i < data.len() {
        let length = data[i] as usize;
        if length == 0 {
            return i + 5 <= data.len();
        }
        if length > 63 || length & 0xc0 != 0 {
            return false;
        }
        i += length + 1;
    }
    false
}

/// "a1 LOGIN ..." style: a tag, then a known IMAP command
pub fn is_imap(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    let mut words = text.split_whitespace();
    let (Some(tag), Some(command)) = (words.next(), words.next()) else { return false };
    const KNOWN: &[&str] = &["CAPABILITY", "LOGIN", "AUTHENTICATE", "STARTTLS", "SELECT", "EXAMINE", "LIST", "LOGOUT", "NOOP", "ID"];
    tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '.') && KNOWN.contains(&command.to_ascii_uppercase().as_str())
}

/// A RESP array of bulk strings ("*2\r\n$4\r\nAUTH...")
pub fn is_redis(data: &[u8]) -> bool {
    data.first() == Some(&b'*') && data.get(1).is_some_and(u8::is_ascii_digit) && data.windows(3).any(|w| w == b"\r\n$")
}

/// Telnet clients usually open with option negotiation (IAC WILL/WONT/DO/DONT)
pub fn is_telnet(data: &[u8]) -> bool {
    data.len() >= 3 && data[0] == 255 && (251..=254).contains(&data[1])
}

/// An NTP client request (mode 3, version 1-4)
pub fn is_ntp(data: &[u8]) -> bool {
    data.len() >= 48 && data[0] & 0x07 == 3 && (1..=4).contains(&((data[0] >> 3) & 0x07))
}

/// A SOCKS5 greeting, or a SOCKS4/4a CONNECT/BIND
pub fn is_socks(data: &[u8]) -> bool {
    match data {
        [5, n, methods @ ..] => *n as usize == methods.len() && *n > 0,
        [4, 1 | 2, ..] => data.len() >= 9 && data.last() == Some(&0),
        _ => false,
    }
}

/// "<PRI>..." with PRI 0-191 (RFC 3164/5424), optionally octet-counted (RFC 6587)
pub fn is_syslog(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    let text = match text.split_once(' ') {
        Some((count, rest)) if !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit()) => rest,
        _ => &text,
    };
    syslog_priority(text).is_some()
}

/// "<PRI>rest" -> (facility, severity, rest)
pub fn syslog_priority(message: &str) -> Option<(u8, u8, &str)> {
    let (pri, rest) = message.strip_prefix('<')?.split_once('>')?;
    if pri.is_empty() || pri.len() > 3 || !pri.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let pri: u8 = pri.parse().ok().filter(|p| *p <= 191)?;
    Some((pri / 8, pri % 8, rest))
}

/// TFTP request/data/ack/error packets (RFC 1350)
pub fn is_tftp(data: &[u8]) -> bool {
    match data {
        [0, 1 | 2, rest @ ..] => {
            let mut fields = rest.split(|&b| b == 0);
            let (Some(name), Some(mode)) = (fields.next(), fields.next()) else { return false };
            !name.is_empty() && matches!(mode.to_ascii_lowercase().as_slice(), b"netascii" | b"octet" | b"mail")
        }
        [0, 3, _, _, rest @ ..] => rest.len() <= 512,
        [0, 4, _, _] => true,
        [0, 5, _, _, .., 0] => true,
        _ => false,
    }
}

/// Whether the first bytes look like a TLS ClientHello record
pub fn looks_like_tls(data: &[u8]) -> bool {
    data.len() >= 3 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04
}

/// How well `data` (a connection's first bytes) and `port` fit `protocol`
pub fn score(protocol: Protocol, data: &[u8], port: u16, transport: Transport) -> u32 {
    if !supports(protocol, transport) {
        return 0;
    }
    if protocol == Protocol::Raw {
        return 1;
    }
    let port_score = u32::from(default_ports(protocol).contains(&port));
    let content_score = match protocol {
        Protocol::Http => 2 * u32::from(starts_with_any(data, HTTP_METHODS)),
        Protocol::Dns => {
            let message = match transport {
                Transport::Udp => data,
                // DNS over TCP: a 2-byte length prefix
                Transport::Tcp if data.len() > 2 && u16::from_be_bytes([data[0], data[1]]) as usize == data.len() - 2 => &data[2..],
                Transport::Tcp => &[],
            };
            2 * u32::from(is_dns_query(message))
        }
        Protocol::Tftp => 2 * u32::from(is_tftp(data)),
        Protocol::Smtp => 2 * u32::from(starts_with_any(data, SMTP_COMMANDS)),
        Protocol::Pop3 => 2 * u32::from(starts_with_any(data, POP3_COMMANDS)) + u32::from(starts_with_any(data, POP3_ONLY)),
        Protocol::Ftp => 2 * u32::from(starts_with_any(data, FTP_COMMANDS)) + u32::from(starts_with_any(data, FTP_ONLY)),
        Protocol::Irc => 2 * u32::from(starts_with_any(data, IRC_COMMANDS)),
        Protocol::Imap => 2 * u32::from(is_imap(data)),
        Protocol::Ssh => 2 * u32::from(data.starts_with(b"SSH-")),
        Protocol::Telnet => 2 * u32::from(is_telnet(data)),
        Protocol::Redis => 2 * u32::from(is_redis(data)),
        Protocol::Ntp => 2 * u32::from(is_ntp(data)),
        Protocol::Socks => 2 * u32::from(is_socks(data)),
        Protocol::Syslog => 2 * u32::from(is_syslog(data)),
        // Recognized by port alone (a port match scores 1, like raw: the earlier wins)
        Protocol::Echo | Protocol::Discard | Protocol::Daytime | Protocol::Chargen | Protocol::Time | Protocol::Qotd
        | Protocol::Finger | Protocol::Whois => 0,
        Protocol::Raw => unreachable!(),
    };
    port_score + content_score
}

/// The best protocol for a connection's first bytes. `candidates` are in tie-break order.
pub fn sniff(candidates: &[Protocol], data: &[u8], port: u16, transport: Transport) -> Protocol {
    let mut best = (0, Protocol::Raw);
    for &candidate in candidates {
        let s = score(candidate, data, port, transport);
        if s > best.0 {
            best = (s, candidate);
        }
    }
    best.1
}

/// For a client that sent nothing: the server-speaks-first protocol for its port, else raw
pub fn sniff_silent(candidates: &[Protocol], port: u16) -> Protocol {
    candidates
        .iter()
        .copied()
        .find(|p| server_speaks_first(*p) && default_ports(*p).contains(&port))
        .unwrap_or(Protocol::Raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_the_ported_protocols_anywhere() {
        let tcp = |data: &[u8]| sniff(DEFAULT_ORDER, data, 4444, Transport::Tcp);
        assert_eq!(tcp(b"a1 LOGIN bob pw\r\n"), Protocol::Imap);
        assert_eq!(tcp(b"SSH-2.0-libssh_0.9.6\r\n"), Protocol::Ssh);
        assert_eq!(tcp(b"*2\r\n$4\r\nAUTH\r\n$2\r\npw\r\n"), Protocol::Redis);
        assert_eq!(tcp(&[255, 253, 3, 255, 251, 24]), Protocol::Telnet);
        let mut ntp = vec![0u8; 48];
        ntp[0] = 0x23; // v4, client
        assert_eq!(sniff(DEFAULT_ORDER, &ntp, 4444, Transport::Udp), Protocol::Ntp);
        assert_eq!(sniff(DEFAULT_ORDER, &ntp, 4444, Transport::Tcp), Protocol::Raw);
        assert_eq!(sniff_silent(DEFAULT_ORDER, 23), Protocol::Telnet);
        assert_eq!(sniff_silent(DEFAULT_ORDER, 143), Protocol::Imap);
        assert_eq!(tcp(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), Protocol::Http);
        assert_eq!(tcp(&[5, 1, 0]), Protocol::Socks);
        assert_eq!(tcp(b"<34>Oct 11 22:14:15 host su: fail"), Protocol::Syslog);
        assert_eq!(tcp(b"37 <34>1 2026-10-16T00:00:00Z h a - - - x"), Protocol::Syslog);
        assert_eq!(sniff(DEFAULT_ORDER, b"root\r\n", 79, Transport::Tcp), Protocol::Finger);
        assert_eq!(sniff_silent(DEFAULT_ORDER, 13), Protocol::Daytime);
    }
    use Protocol::*;

    fn tcp(data: &[u8], port: u16) -> Protocol {
        sniff(DEFAULT_ORDER, data, port, Transport::Tcp)
    }

    fn udp(data: &[u8], port: u16) -> Protocol {
        sniff(DEFAULT_ORDER, data, port, Transport::Udp)
    }

    fn dns_query(name: &str) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend(label.as_bytes());
        }
        packet.extend([0, 0, 1, 0, 1]);
        packet
    }

    #[test]
    fn detects_protocols_on_their_usual_ports() {
        assert_eq!(tcp(b"GET / HTTP/1.1\r\n", 80), Http);
        assert_eq!(tcp(b"EHLO bot\r\n", 25), Smtp);
        assert_eq!(tcp(b"USER bob\r\n", 110), Pop3);
        assert_eq!(tcp(b"USER anonymous\r\n", 21), Ftp);
        assert_eq!(tcp(b"NICK bot\r\n", 6667), Irc);
        assert_eq!(udp(&dns_query("evil.example"), 53), Dns);
        assert_eq!(udp(b"\x00\x01boot.bin\x00octet\x00", 69), Tftp);
    }

    #[test]
    fn detects_protocols_on_non_standard_ports() {
        // The brief's examples: HTTP on 81, FTP on 80
        assert_eq!(tcp(b"GET /beacon HTTP/1.1\r\nHost: c2\r\n\r\n", 81), Http);
        assert_eq!(tcp(b"USER anonymous\r\n", 80), Ftp);
        assert_eq!(tcp(b"SYST\r\n", 80), Ftp);
        assert_eq!(tcp(b"POST /gate HTTP/1.1\r\n", 4444), Http);
        assert_eq!(tcp(b"EHLO x\r\n", 8080), Smtp);
        assert_eq!(udp(&dns_query("a.b"), 5353), Dns);
        // DNS over TCP, length-prefixed
        let query = dns_query("evil.example");
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend(&query);
        assert_eq!(tcp(&framed, 9999), Dns);
    }

    #[test]
    fn breaks_ftp_and_pop3_ambiguity_sensibly() {
        // USER is valid in both: the port decides
        assert_eq!(tcp(b"USER x\r\n", 21), Ftp);
        assert_eq!(tcp(b"USER x\r\n", 110), Pop3);
        // Protocol-specific commands decide anywhere
        assert_eq!(tcp(b"CAPA\r\n", 21), Pop3);
        assert_eq!(tcp(b"PASV\r\n", 110), Ftp);
        // IRC registration starting with USER on an IRC port
        assert_eq!(tcp(b"NICK bot\r\nUSER bot 0 * :x\r\n", 6667), Irc);
    }

    #[test]
    fn falls_back_to_raw() {
        assert_eq!(tcp(b"\x00\x01\x02binary", 4444), Raw);
        assert_eq!(tcp(b"", 4444), Raw);
        assert_eq!(tcp(b"GETTING / HTTP/1.1", 80), Http); // Port only: still HTTP on 80
        assert_eq!(tcp(b"GETTING / HTTP/1.1", 81), Raw);
        assert_eq!(udp(b"hello", 9999), Raw);
        assert_eq!(udp(b"GET / HTTP/1.1", 80), Raw); // HTTP isn't a UDP protocol here
    }

    #[test]
    fn respects_the_candidate_list() {
        // Without HTTP as a candidate, an HTTP request is raw
        assert_eq!(sniff(&[Smtp, Raw], b"GET / HTTP/1.1", 80, Transport::Tcp), Raw);
        // Ties go to the earlier candidate
        assert_eq!(sniff(&[Pop3, Ftp, Raw], b"USER x", 80, Transport::Tcp), Pop3);
        assert_eq!(sniff(&[Ftp, Pop3, Raw], b"USER x", 80, Transport::Tcp), Ftp);
    }

    #[test]
    fn greets_silent_clients_by_port() {
        assert_eq!(sniff_silent(DEFAULT_ORDER, 21), Ftp);
        assert_eq!(sniff_silent(DEFAULT_ORDER, 25), Smtp);
        assert_eq!(sniff_silent(DEFAULT_ORDER, 110), Pop3);
        assert_eq!(sniff_silent(DEFAULT_ORDER, 80), Raw); // HTTP clients speak first
        assert_eq!(sniff_silent(&[Raw], 21), Raw);
    }

    #[test]
    fn recognizes_tls_and_rejects_lookalikes() {
        assert!(looks_like_tls(&[0x16, 0x03, 0x01, 0x00, 0xf4]));
        assert!(!looks_like_tls(b"GET /"));
        assert!(!is_dns_query(b"\x00\x00\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x00\x00\x01\x00\x01")); // A response
        assert!(!is_dns_query(&[0u8; 30]));
        assert!(!is_tftp(b"\x00\x01name\x00weird\x00"));
        assert!(is_tftp(&[0, 4, 0, 1]));
    }
}
