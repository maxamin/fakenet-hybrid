//! For `cargo fuzz` (feature "fuzzing"): runs a protocol handler with arbitrary client
//! bytes over an in-memory connection, exactly as the dispatcher would, with the daemon
//! link off, tight timeouts and a throwaway capture folder.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use fakenet_capture::{Capture, Limits};
use fakenet_link::{Link, LinkConfig};
use fakenet_schema::{Protocol, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{AutoKeyword, Defaults, ListenerProtocol};
use crate::session::{Context, Session};
use crate::tls::TlsAuthority;

/// The protocols a fuzz input can select (TCP), plus "auto" (sniffing)
pub const TCP: &[Option<Protocol>] = &[
    None, Some(Protocol::Http), Some(Protocol::Dns), Some(Protocol::Raw), Some(Protocol::Smtp), Some(Protocol::Pop3),
    Some(Protocol::Ftp), Some(Protocol::Irc), Some(Protocol::Imap), Some(Protocol::Ssh), Some(Protocol::Telnet),
    Some(Protocol::Redis), Some(Protocol::Socks), Some(Protocol::Syslog), Some(Protocol::Echo), Some(Protocol::Discard),
    Some(Protocol::Daytime), Some(Protocol::Chargen), Some(Protocol::Time), Some(Protocol::Qotd), Some(Protocol::Finger),
    Some(Protocol::Whois), Some(Protocol::Smb), Some(Protocol::Ldap), Some(Protocol::Rdp), Some(Protocol::Vnc), Some(Protocol::Mqtt),
];
pub const UDP: &[Protocol] = &[Protocol::Dns, Protocol::Tftp, Protocol::Ntp, Protocol::Syslog, Protocol::Coap, Protocol::Raw, Protocol::Echo, Protocol::Daytime];

struct Harness {
    runtime: tokio::runtime::Runtime,
    ctx: Arc<Context>,
    socket: tokio::net::UdpSocket,
}

fn harness() -> &'static Harness {
    static HARNESS: OnceLock<Harness> = OnceLock::new();
    HARNESS.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        let dir = std::env::temp_dir().join(format!("fakenet-fuzz-{}", std::process::id()));
        let limits = Limits { max_events_bytes: 32 << 20, max_pcap_bytes: 32 << 20, max_files_bytes: 32 << 20, keep: 1 };
        let (ctx, socket) = runtime.block_on(async {
            let ctx = Arc::new(Context {
                link: Link::start(LinkConfig::default()),
                capture: Capture::open_with(&dir, limits).expect("capture"),
                defaults: Defaults::default(),
                tls: Arc::new(TlsAuthority::generate().expect("CA")),
                timeout: Duration::from_millis(100),
                first_data_timeout: Duration::from_millis(20),
                original: None,
                explorer: None,
                limits: Default::default(),
                known_fingerprints: Default::default(),
            });
            (ctx, tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("socket"))
        });
        Harness { runtime, ctx, socket }
    })
}

const CLIENT: &str = "10.13.37.2:49152";
const SERVER: &str = "10.13.37.1:8080";

/// Runs one TCP connection: the handler for `protocol` (None: sniffing) gets `input` as the
/// client's bytes; whatever it answers is read and discarded
pub fn tcp(protocol: Option<Protocol>, input: &[u8]) {
    let h = harness();
    h.runtime.block_on(async {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let listener = protocol.map(ListenerProtocol::Fixed).unwrap_or(ListenerProtocol::Auto(AutoKeyword::Auto));
        let initial = protocol.unwrap_or(Protocol::Raw);
        let session = Session::new(h.ctx.clone(), "fuzz", initial, Transport::Tcp, CLIENT.parse().unwrap(), SERVER.parse().unwrap(), None);
        let handler = crate::dispatch::serve(session, Box::new(server), listener, false);
        let input = input.to_vec();
        let client_side = async move {
            let _ = client.write_all(&input).await;
            let _ = client.shutdown().await;
            let mut sink = vec![0u8; 1 << 16];
            while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(200), client.read(&mut sink)).await {
                if n == 0 {
                    break;
                }
            }
        };
        let _ = tokio::time::timeout(Duration::from_millis(500), async { tokio::join!(handler, client_side) }).await;
    });
}

/// Runs one UDP datagram through `protocol`'s handler
pub fn udp(protocol: Protocol, input: &[u8]) {
    let h = harness();
    h.runtime.block_on(async {
        let peer: SocketAddr = CLIENT.parse().unwrap();
        let mut session = Session::new(h.ctx.clone(), "fuzz", protocol, Transport::Udp, peer, SERVER.parse().unwrap(), None);
        let _ = tokio::time::timeout(Duration::from_millis(300), crate::dispatch::handle_udp(&mut session, input, peer, &h.socket)).await;
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn runs_every_handler() {
        for protocol in super::TCP {
            super::tcp(*protocol, b"GET / HTTP/1.1\r\nHost: x\r\n\r\nUSER a\r\nQUIT\r\n");
        }
        for protocol in super::UDP {
            super::udp(*protocol, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x00\x00\x01\x00\x01");
        }
    }
}
