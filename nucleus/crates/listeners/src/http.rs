//! HTTP/1.1 (and HTTPS, after TLS termination) with hyper. Each request is an event; the
//! daemon may answer with a complete raw HTTP response, else the default applies: the
//! requested file from the webroot, or a default file of the requested type (FakeNet-NG's
//! behaviour, so e.g. any .exe download gets an executable).

use std::convert::Infallible;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::sync::Mutex;

use fakenet_schema::Protocol;

use crate::custom::{replace_date, HttpResponse};
use crate::session::Session;
use crate::stream::BoxStream;

const DEFAULT_PAGE: &str = "<html><head><title>FakeNet</title></head><body><h1>FakeNet</h1></body></html>";

/// HTTP/1.1 and HTTP/2 (by ALPN or the h2 preface) on one connection
pub async fn handle(stream: BoxStream, session: Session) -> anyhow::Result<()> {
    let session = Arc::new(Mutex::new(session));
    let service = hyper::service::service_fn(move |request| {
        let session = session.clone();
        async move { Ok::<_, Infallible>(respond(request, &session).await) }
    });
    hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// CONNECT host:port (a proxy-aware client): an event; a daemon response refuses the
/// tunnel, else it's accepted and its contents served as a new, sniffed session
async fn connect(mut request: Request<Incoming>, session: &mut Session) -> Response<Full<Bytes>> {
    let defaults = session.ctx.defaults.http.clone();
    let target = request.uri().authority().map(|a| a.to_string()).unwrap_or_default();
    let line = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
    session.client_data(line.as_bytes());
    session.log("proxy_connect", json!({ "target": target }));
    let meta = json!({ "method": "CONNECT", "path": target, "host": target, "proxy": true });
    if let Some(action) = session.decide(line.as_bytes(), meta).await {
        if let Some(response) = action.response {
            return from_raw(&response, &defaults.server_header, true);
        }
    }
    let port = target.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(443);
    let ip = target.rsplit_once(':').and_then(|(h, _)| h.trim_matches(['[', ']']).parse().ok()).unwrap_or(session.builder.dst.ip());
    let upgrade = hyper::upgrade::on(&mut request);
    let tunnel = crate::dispatch::serve_tunnel(session, Box::new(PendingUpgrade(Some(upgrade), None)), target, std::net::SocketAddr::new(ip, port));
    tokio::spawn(async move {
        if let Err(e) = tunnel.await {
            tracing::debug!("proxy tunnel: {e:#}");
        }
    });
    let response = build(StatusCode::OK, &[], Bytes::new(), &defaults.server_header, false);
    session.server_data(b"HTTP/1.1 200 Connection established\r\n\r\n");
    response
}

async fn respond(request: Request<Incoming>, session: &Mutex<Session>) -> Response<Full<Bytes>> {
    let mut session = session.lock().await;
    if request.method() == hyper::Method::CONNECT {
        return connect(request, &mut session).await;
    }
    if crate::websocket::is_upgrade(&request) {
        return crate::websocket::accept(request, &mut session).await;
    }
    let defaults = session.ctx.defaults.http.clone();
    let (parts, body) = request.into_parts();
    let mut held = session.ctx.limits.hold();
    let body = match read_body(body, defaults.max_body_bytes, &mut held).await {
        Ok(body) => body,
        Err(e) => {
            session.log("bad_request", json!({ "error": format!("{e:#}") }));
            return build(StatusCode::PAYLOAD_TOO_LARGE, &[], Bytes::new(), &defaults.server_header, true);
        }
    };
    answer(&mut session, parts, body).await
}

/// The whole request body, within `max` bytes and the memory budget
async fn read_body(mut body: Incoming, max: usize, held: &mut crate::limits::Held) -> anyhow::Result<Bytes> {
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            anyhow::ensure!(collected.len() + data.len() <= max, "body larger than max_body_bytes");
            held.grow(data.len())?;
            collected.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(collected))
}

/// A DNS-over-HTTPS query (RFC 8484): POST with an application/dns-message body, or GET
/// with the message base64url-encoded in `dns`
fn doh_query(parts: &hyper::http::request::Parts, body: &Bytes) -> Option<Vec<u8>> {
    if parts.uri.path() != "/dns-query" {
        return None;
    }
    let content_type = parts.headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
    if parts.method == hyper::Method::POST && content_type.eq_ignore_ascii_case("application/dns-message") {
        return Some(body.to_vec());
    }
    let encoded = parts.uri.query()?.split('&').find_map(|pair| pair.strip_prefix("dns="))?;
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded.trim_end_matches('=')).ok()
}

/// Answers a DoH query with the DNS handler (logged and decided as DNS)
async fn doh(session: &mut Session, parts: &hyper::http::request::Parts, query: &[u8]) -> Response<Full<Bytes>> {
    let server = session.ctx.defaults.http.server_header.clone();
    let host = parts.headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or_default().to_string();
    session.log("doh", json!({ "method": parts.method.as_str(), "host": host }));
    session.client_data(query);
    let http = session.builder.protocol;
    session.builder.protocol = Protocol::Dns;
    let reply = crate::dns::answer(query, session).await;
    session.builder.protocol = http;
    match reply {
        Some(reply) => {
            session.server_data(&reply);
            let mut response = Response::new(Full::new(Bytes::from(reply)));
            let headers = response.headers_mut();
            headers.insert("content-type", hyper::header::HeaderValue::from_static("application/dns-message"));
            headers.insert("cache-control", hyper::header::HeaderValue::from_static("max-age=60"));
            if let Ok(value) = hyper::header::HeaderValue::from_str(&server) {
                headers.insert("server", value);
            }
            response
        }
        None => build(StatusCode::BAD_REQUEST, &[], Bytes::new(), &server, false),
    }
}

/// One HTTP request (any version: HTTP/1.1, HTTP/2, HTTP/3), read in full: the event, the
/// daemon's decision or the default, and the capture. Returns the response to send.
pub(crate) async fn answer(session: &mut Session, parts: hyper::http::request::Parts, body: Bytes) -> Response<Full<Bytes>> {
    let defaults = session.ctx.defaults.http.clone();
    if let Some(query) = doh_query(&parts, &body) {
        return doh(session, &parts, &query).await;
    }
    // The request as it was on the wire, for the event & the pcap
    let mut raw = format!("{} {} {:?}\r\n", parts.method, parts.uri, parts.version).into_bytes();
    for (name, value) in &parts.headers {
        raw.extend_from_slice(name.as_str().as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(value.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(&body);
    session.client_data(&raw);

    let host = parts.headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("").to_string();
    let headers: serde_json::Map<String, serde_json::Value> = parts.headers.iter()
        .map(|(n, v)| (n.as_str().to_string(), json!(String::from_utf8_lossy(v.as_bytes()))))
        .collect();
    let mut saved = None;
    if defaults.save_bodies && !body.is_empty() {
        saved = session.ctx.capture.save_file("http_body", parts.uri.path(), &body).ok().map(|p| p.display().to_string());
    }
    // Absolute-form HTTP/1.x targets ("GET http://host/path") come from clients using us as a
    // proxy. HTTP/2 & HTTP/3 always carry scheme + authority: that's not a proxy request.
    let http1 = parts.version <= hyper::Version::HTTP_11;
    let proxy = http1 && parts.uri.scheme().is_some();
    let host = if host.is_empty() { parts.uri.authority().map(|a| a.to_string()).unwrap_or_default() } else { host };
    let path = match proxy {
        true => parts.uri.to_string(),
        false => parts.uri.path_and_query().map(|p| p.to_string()).unwrap_or_else(|| "/".into()),
    };
    let meta = json!({
        "method": parts.method.as_str(), "path": path, "host": host, "proxy": proxy, "version": format!("{:?}", parts.version),
        "headers": headers, "body_bytes": body.len(), "saved_body": saved,
    });

    let action = session.decide(&raw, meta).await;
    let response = match action {
        Some(action) if action.response.is_some() => {
            let close = action.close;
            from_raw(action.response.as_deref().unwrap_or_default(), &defaults.server_header, close)
        }
        other => {
            let close = other.is_some_and(|a| a.close);
            let check = defaults.connectivity_checks.then(|| connectivity_check(&host, parts.uri.path())).flatten();
            match custom_response(session, &parts, &host, &body).await {
                Some(response) => response,
                None if check.is_some() => {
                    let (status, content_type, content) = check.unwrap_or_default();
                    session.log("connectivity_check", json!({ "host": host, "path": parts.uri.path() }));
                    build(StatusCode::from_u16(status).unwrap_or(StatusCode::OK), &[("content-type", content_type)], Bytes::from_static(content.as_bytes()), &server_for(&defaults.server_header, &host), close)
                }
                None => {
                    let (content, content_type) = default_content(parts.uri.path(), defaults.webroot.as_deref());
                    build(StatusCode::OK, &[("content-type", content_type)], Bytes::from(content), &server_for(&defaults.server_header, &host), close)
                }
            }
        }
    };
    session.server_data(&serialize(&response));
    response
}

/// The listener's matching FakeNet-NG Custom Response, if any
async fn custom_response(session: &Session, parts: &hyper::http::request::Parts, host: &str, body: &[u8]) -> Option<Response<Full<Bytes>>> {
    let custom = session.custom.as_deref()?.match_http(host, &parts.uri.to_string())?;
    let server = &session.ctx.defaults.http.server_header;
    session.log("custom_response", json!({ "section": custom.name }));
    Some(match &custom.response {
        HttpResponse::Raw(raw) => from_raw(&replace_date(raw), server, false),
        HttpResponse::Static { text, content_type } => {
            let body = Bytes::from(replace_date(text.as_bytes()));
            build(StatusCode::OK, &[("content-type", content_type.as_deref().unwrap_or("text/html"))], body, server, false)
        }
        HttpResponse::Dynamic(provider) => {
            let headers: Vec<(String, String)> = parts.headers.iter().map(|(n, v)| (n.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
            let target = parts.uri.path_and_query().map(|p| p.to_string()).unwrap_or_else(|| "/".into());
            match crate::custom::run_http_provider(provider, parts.method.as_str(), &target, &headers, body, session.builder.src).await {
                Ok(raw) => from_raw(&raw, server, false),
                Err(e) => {
                    session.log("custom_failed", json!({ "section": custom.name, "error": e.to_string() }));
                    return None;
                }
            }
        }
    })
}

/// OS & browser connectivity checks, answered exactly as the real services do:
/// (status, content type, body)
pub fn connectivity_check(host: &str, path: &str) -> Option<(u16, &'static str, &'static str)> {
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    Some(match (host.as_str(), path) {
        ("www.msftncsi.com", "/ncsi.txt") => (200, "text/plain", "Microsoft NCSI"),
        ("www.msftconnecttest.com", "/connecttest.txt") => (200, "text/plain", "Microsoft Connect Test"),
        ("www.msftconnecttest.com", "/redirect") => (200, "text/html", ""),
        ("connectivitycheck.gstatic.com" | "clients3.google.com" | "www.gstatic.com" | "connectivitycheck.android.com", "/generate_204") => (204, "text/plain", ""),
        ("captive.apple.com", "/hotspot-detect.html" | "/") | ("www.apple.com", "/library/test/success.html") => {
            (200, "text/html", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")
        }
        ("detectportal.firefox.com", "/success.txt") => (200, "text/plain", "success\n"),
        ("connectivity-check.ubuntu.com" | "nmcheck.gnome.org", _) => (204, "text/plain", ""),
        _ => return None,
    })
}

/// "auto": the server software a host would plausibly run, else the configured header
pub fn server_for(configured: &str, host: &str) -> String {
    if configured != "auto" {
        return configured.to_string();
    }
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    let suffix = |s: &str| host == s || host.ends_with(&format!(".{s}"));
    if ["microsoft.com", "msftncsi.com", "msftconnecttest.com", "live.com", "office.com", "windows.com", "windowsupdate.com", "azure.com"].iter().any(|s| suffix(s)) {
        "Microsoft-IIS/10.0"
    } else if ["google.com", "gstatic.com", "googleapis.com", "youtube.com"].iter().any(|s| suffix(s)) {
        "gws"
    } else if ["apple.com", "icloud.com"].iter().any(|s| suffix(s)) {
        "Apache"
    } else if ["cloudflare.com"].iter().any(|s| suffix(s)) {
        "cloudflare"
    } else if ["amazonaws.com", "amazon.com"].iter().any(|s| suffix(s)) {
        "AmazonS3"
    } else {
        "nginx"
    }
    .to_string()
}

fn build(status: StatusCode, headers: &[(&str, &str)], body: Bytes, server: &str, close: bool) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(status).header("server", server);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    if close {
        builder = builder.header("connection", "close");
    }
    builder.body(Full::new(body)).expect("valid static response")
}

/// A daemon-scripted raw HTTP response, parsed into a hyper response (hyper recomputes the
/// framing headers). Unparseable responses are served as a 200 body, so a malformed script
/// still answers the malware.
pub fn from_raw(raw: &[u8], server: &str, close: bool) -> Response<Full<Bytes>> {
    let mut header_storage = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut header_storage);
    let Ok(httparse::Status::Complete(length)) = parsed.parse(raw) else {
        return build(StatusCode::OK, &[("content-type", "text/html")], Bytes::copy_from_slice(raw), server, close);
    };
    let status = parsed.code.and_then(|c| StatusCode::from_u16(c).ok()).unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status);
    let mut has_server = false;
    for header in parsed.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        // Framing is hyper's job: a scripted Content-Length could desynchronize the client
        if matches!(name.as_str(), "content-length" | "transfer-encoding" | "connection") {
            continue;
        }
        has_server |= name == "server";
        builder = builder.header(header.name, header.value);
    }
    if !has_server {
        builder = builder.header("server", server);
    }
    if close {
        builder = builder.header("connection", "close");
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(&raw[length..])))
        .unwrap_or_else(|_| build(StatusCode::OK, &[], Bytes::copy_from_slice(&raw[length..]), server, close))
}

/// For the pcap: the response as it goes on the wire (approximately: hyper adds the date)
fn serialize(response: &Response<Full<Bytes>>) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {}\r\n", response.status()).into_bytes();
    for (name, value) in response.headers() {
        out.extend_from_slice(format!("{}: {}\r\n", name, String::from_utf8_lossy(value.as_bytes())).as_bytes());
    }
    let body = futures_body(response);
    out.extend_from_slice(format!("content-length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(&body);
    out
}

fn futures_body(response: &Response<Full<Bytes>>) -> Bytes {
    // Full<Bytes> holds its data directly; clone it out without polling
    use hyper::body::Body as _;
    let mut body = response.body().clone();
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match std::pin::Pin::new(&mut body).poll_frame(&mut cx) {
        std::task::Poll::Ready(Some(Ok(frame))) => frame.into_data().unwrap_or_default(),
        _ => Bytes::new(),
    }
}

/// The webroot file for a request path, else the default file for its type, else a page
pub fn default_content(path: &str, webroot: Option<&Path>) -> (Vec<u8>, &'static str) {
    let path = path.split(['?', '#']).next().unwrap_or("/");
    let content_type = mime_type(path);
    if let Some(root) = webroot {
        let requested = if path.ends_with('/') { format!("{path}index.html") } else { path.to_string() };
        let candidates = [safe_join(root, &requested), Some(root.join(default_file(content_type)))];
        for candidate in candidates.into_iter().flatten() {
            if let Ok(content) = std::fs::read(candidate) {
                return (content, content_type);
            }
        }
    }
    (DEFAULT_PAGE.as_bytes().to_vec(), content_type)
}

/// Joins a request path onto a root, refusing anything that would escape it
pub fn safe_join(root: &Path, request_path: &str) -> Option<PathBuf> {
    let mut joined = root.to_path_buf();
    for component in Path::new(request_path.trim_start_matches('/')).components() {
        match component {
            Component::Normal(part) => joined.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(joined)
}

pub fn mime_type(path: &str) -> &'static str {
    let extension = Path::new(path).extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    match extension.as_str() {
        "" | "html" | "htm" => "text/html",
        "txt" => "text/plain",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/ico",
        "pdf" => "application/pdf",
        "json" => "application/json",
        "js" => "application/javascript",
        "css" => "text/css",
        "xml" => "application/xml",
        "exe" | "dll" | "scr" | "msi" => "application/x-msdownload",
        _ => "application/octet-stream",
    }
}

/// FakeNet-NG's MIME_FILE_RESPONSE table
pub fn default_file(content_type: &str) -> &'static str {
    match content_type {
        "image/png" => "FakeNet.png",
        "image/ico" => "FakeNet.ico",
        "image/jpeg" => "FakeNet.jpg",
        "image/gif" => "FakeNet.gif",
        "text/plain" => "FakeNet.txt",
        "application/pdf" => "FakeNet.pdf",
        "application/octet-stream" | "application/x-msdownload" => "FakeNetMini.exe",
        _ => "FakeNet.html",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scripted_responses() {
        let response = from_raw(b"HTTP/1.1 404 Not Found\r\nX-C2: yes\r\nContent-Length: 999\r\n\r\nnope", "S", false);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["x-c2"], "yes");
        assert!(response.headers().get("content-length").is_none()); // hyper recomputes it
        assert_eq!(futures_body(&response), "nope");

        let unparseable = from_raw(b"just text", "S", true);
        assert_eq!(unparseable.status(), StatusCode::OK);
        assert_eq!(futures_body(&unparseable), "just text");
        assert_eq!(unparseable.headers()["connection"], "close");
    }

    #[test]
    fn answers_connectivity_checks_like_the_real_services() {
        assert_eq!(connectivity_check("www.msftncsi.com", "/ncsi.txt"), Some((200, "text/plain", "Microsoft NCSI")));
        assert_eq!(connectivity_check("connectivitycheck.gstatic.com:80", "/generate_204").map(|c| c.0), Some(204));
        assert!(connectivity_check("c2.evil.example", "/ncsi.txt").is_none());
        assert_eq!(server_for("auto", "login.microsoft.com"), "Microsoft-IIS/10.0");
        assert_eq!(server_for("auto", "evil.example"), "nginx");
        assert_eq!(server_for("Apache/2.4", "www.google.com"), "Apache/2.4");
    }

    #[test]
    fn serves_defaults_safely() {
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/default-files"));
        let (exe, content_type) = default_content("/a/b/payload.exe?x=1", Some(root));
        assert_eq!(content_type, "application/x-msdownload");
        assert_eq!(exe, std::fs::read(root.join("FakeNetMini.exe")).unwrap());
        assert_eq!(safe_join(Path::new("/srv"), "/../etc/passwd"), None);
        assert_eq!(default_content("/x", None).0, DEFAULT_PAGE.as_bytes());
    }
}

/// The upgraded connection, once hyper has sent the 200 (it's only available after the
/// response): reads/writes wait for it
pub(crate) struct PendingUpgrade(Option<hyper::upgrade::OnUpgrade>, Option<TokioIo<hyper::upgrade::Upgraded>>);

impl PendingUpgrade {
    pub(crate) fn new(upgrade: hyper::upgrade::OnUpgrade) -> PendingUpgrade {
        PendingUpgrade(Some(upgrade), None)
    }

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<&mut TokioIo<hyper::upgrade::Upgraded>>> {
        use std::future::Future;
        if self.1.is_none() {
            let Some(pending) = self.0.as_mut() else { return std::task::Poll::Ready(Err(std::io::ErrorKind::NotConnected.into())) };
            match std::pin::Pin::new(pending).poll(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(std::io::Error::other(e))),
                std::task::Poll::Ready(Ok(upgraded)) => {
                    self.0 = None;
                    self.1 = Some(TokioIo::new(upgraded));
                }
            }
        }
        std::task::Poll::Ready(Ok(self.1.as_mut().expect("set above")))
    }
}

impl tokio::io::AsyncRead for PendingUpgrade {
    fn poll_read(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_ready(cx) {
            std::task::Poll::Ready(Ok(io)) => std::pin::Pin::new(io).poll_read(cx, buf),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for PendingUpgrade {
    fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, data: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_ready(cx) {
            std::task::Poll::Ready(Ok(io)) => std::pin::Pin::new(io).poll_write(cx, data),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.1.as_mut() {
            Some(io) => std::pin::Pin::new(io).poll_flush(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.1.as_mut() {
            Some(io) => std::pin::Pin::new(io).poll_shutdown(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}
