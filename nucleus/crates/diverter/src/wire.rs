//! A real packet capture (every IP packet the host sends or receives), alongside the
//! listeners' synthesized one: what actually crossed the wire, including traffic that was
//! never diverted. Linux: an AF_PACKET socket; Windows: a WinDivert sniff handle (observes,
//! never diverts). Needs root/Administrator.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Receives each captured packet (starting at its IP header)
pub type Sink = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// A running capture; stops when dropped (Linux; on Windows at process exit)
pub struct WireCapture {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl WireCapture {
    pub fn start(sink: Sink) -> anyhow::Result<WireCapture> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread = platform::start(sink, stop.clone())?;
        Ok(WireCapture { stop, thread: Some(thread) })
    }
}

impl Drop for WireCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            // Linux's reader wakes every 200 ms to check; WinDivert's blocks until a packet
            if cfg!(target_os = "linux") {
                let _ = thread.join();
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;

    use super::Sink;

    const ARPHRD_LOOPBACK: u16 = 772;
    const PACKET_OUTGOING: u8 = 4;

    /// Thin FFI: an AF_PACKET/SOCK_DGRAM socket (IP packets without link headers) with a
    /// receive timeout, read with recvfrom into buffers whose sizes we pass. The fd is owned
    /// (closed on drop).
    fn open_socket() -> std::io::Result<OwnedFd> {
        let protocol = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
        // SAFETY: plain socket(2) call; the result is checked before use
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, protocol) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fd is a fresh, valid descriptor we exclusively own
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let timeout = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
        // SAFETY: timeout is a valid timeval of the size passed
        let result = unsafe {
            libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&timeout as *const libc::timeval).cast(), std::mem::size_of::<libc::timeval>() as libc::socklen_t)
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(socket)
    }

    pub fn start(sink: Sink, stop: Arc<AtomicBool>) -> anyhow::Result<JoinHandle<()>> {
        let socket = open_socket().map_err(|e| anyhow::anyhow!("opening a packet socket (needs root/CAP_NET_RAW): {e}"))?;
        Ok(std::thread::Builder::new().name("fakenet-wire".into()).spawn(move || {
            let mut buffer = vec![0u8; 65536];
            while !stop.load(Ordering::Relaxed) {
                // SAFETY: zeroed sockaddr_ll is valid; recvfrom writes at most buffer.len()
                // bytes and at most `length` bytes of address
                let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
                let mut length = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
                let read = unsafe {
                    libc::recvfrom(socket.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0, (&mut address as *mut libc::sockaddr_ll).cast(), &mut length)
                };
                if read < 0 {
                    let error = std::io::Error::last_os_error();
                    if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) {
                        continue;
                    }
                    tracing::warn!("Wire capture stopped: {error}");
                    return;
                }
                let ip = u16::from_be(address.sll_protocol);
                if ip != libc::ETH_P_IP as u16 && ip != libc::ETH_P_IPV6 as u16 {
                    continue;
                }
                // Loopback shows every packet twice (sent & received): keep one
                if address.sll_hatype == ARPHRD_LOOPBACK && address.sll_pkttype == PACKET_OUTGOING {
                    continue;
                }
                sink(&buffer[..read as usize]);
            }
        })?)
    }
}

#[cfg(windows)]
mod platform {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;

    use windivert::prelude::*;

    use super::Sink;

    pub fn start(sink: Sink, stop: Arc<AtomicBool>) -> anyhow::Result<JoinHandle<()>> {
        // Sniff: copies of packets, never diverted; low priority so the diverter sees them first
        let handle = WinDivert::network("true", -1000, WinDivertFlags::new().set_sniff().set_recv_only())
            .map_err(|e| anyhow::anyhow!("opening a WinDivert sniff handle (run as Administrator): {e}"))?;
        Ok(std::thread::Builder::new().name("fakenet-wire".into()).spawn(move || {
            let mut buffer = vec![0u8; 65535];
            while !stop.load(Ordering::Relaxed) {
                match handle.recv(Some(&mut buffer)) {
                    Ok(packet) => sink(&packet.data),
                    Err(e) => {
                        tracing::warn!("Wire capture stopped: {e}");
                        return;
                    }
                }
            }
        })?)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    pub fn start(_sink: super::Sink, _stop: std::sync::Arc<std::sync::atomic::AtomicBool>) -> anyhow::Result<std::thread::JoinHandle<()>> {
        anyhow::bail!("wire capture is only supported on Linux and Windows")
    }
}
