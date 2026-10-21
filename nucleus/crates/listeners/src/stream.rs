//! Stream helpers: one type for plain/TLS/replayed streams, bounded line reads, and
//! replaying bytes already read during protocol detection.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;

pub const MAX_LINE: usize = 8192;

/// One line (without CRLF/LF), bounded in size and idle time. Ok(None) at EOF or on idle.
pub async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R, idle: Duration) -> io::Result<Option<String>> {
    Ok(read_raw_line(reader, idle).await?.map(decode))
}

/// One line's raw bytes (without its LF; a CR is kept), bounded like `read_line`
pub async fn read_raw_line<R: AsyncBufRead + Unpin>(reader: &mut R, idle: Duration) -> io::Result<Option<Vec<u8>>> {
    read_raw_line_max(reader, idle, MAX_LINE).await
}

/// One line's raw bytes, at most `max` of them (for bulk data such as SMTP DATA)
pub async fn read_raw_line_max<R: AsyncBufRead + Unpin>(reader: &mut R, idle: Duration, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = match tokio::time::timeout(idle, reader.fill_buf()).await {
            Err(_) => return Ok(None),
            Ok(result) => result?,
        };
        if available.is_empty() {
            return Ok(if line.is_empty() { None } else { Some(line) });
        }
        if let Some(end) = available.iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&available[..end]);
            reader.consume(end + 1);
            return if line.len() > max { Err(too_long()) } else { Ok(Some(line)) };
        }
        let length = available.len();
        line.extend_from_slice(available);
        reader.consume(length);
        if line.len() > max {
            return Err(too_long());
        }
    }
}

fn too_long() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "line too long")
}

fn decode(mut line: Vec<u8>) -> String {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8_lossy(&line).into_owned()
}

/// Write & flush (TLS streams buffer until flushed)
pub async fn send<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    writer.write_all(data).await?;
    writer.flush().await
}

/// A stream that first yields bytes already read from it
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    position: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        PrefixedStream { prefix, position: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.position < self.prefix.len() {
            let remaining = &self.prefix[self.position..];
            let count = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..count]);
            self.position += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, BufReader};

    #[tokio::test]
    async fn reads_bounded_lines_and_replays_prefixes() {
        let mut reader = BufReader::new(&b"one\r\ntwo\nlast"[..]);
        let t = Duration::from_secs(1);
        assert_eq!(read_line(&mut reader, t).await.unwrap().as_deref(), Some("one"));
        assert_eq!(read_line(&mut reader, t).await.unwrap().as_deref(), Some("two"));
        assert_eq!(read_line(&mut reader, t).await.unwrap().as_deref(), Some("last"));
        assert_eq!(read_line(&mut reader, t).await.unwrap(), None);
        let long = vec![b'x'; MAX_LINE + 2];
        assert!(read_line(&mut BufReader::new(&long[..]), t).await.is_err());

        let (client, server) = tokio::io::duplex(64);
        drop(client);
        let mut stream = PrefixedStream::new(b"peeked".to_vec(), server);
        let mut all = String::new();
        stream.read_to_string(&mut all).await.unwrap();
        assert_eq!(all, "peeked");
    }
}
