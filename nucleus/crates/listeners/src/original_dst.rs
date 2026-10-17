//! The destination a TCP connection had before an iptables REDIRECT sent it to us (Linux's
//! SO_ORIGINAL_DST), so sniffing and events use the port the malware really connected to.
//! Also the UDP equivalent (IP_RECVORIGDSTADDR via recvmsg). These thin wrappers hold the
//! crate's networking `unsafe`, each block with its safety argument.

use std::net::SocketAddr;

use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
pub fn original_destination(stream: &TcpStream) -> Option<SocketAddr> {
    use std::os::fd::AsRawFd;
    // linux/netfilter_ipv4.h & netfilter_ipv6/ip6_tables.h (same value for both)
    const SO_ORIGINAL_DST: libc::c_int = 80;
    let fd = stream.as_raw_fd();
    let local = stream.local_addr().ok()?;
    if local.is_ipv4() {
        // SAFETY: addr is a valid, writable sockaddr_in and len is its size; the kernel
        // writes at most len bytes. fd is open for the lifetime of `stream`.
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(fd, libc::SOL_IP, SO_ORIGINAL_DST, (&mut addr as *mut libc::sockaddr_in).cast(), &mut len)
        };
        (result == 0).then(|| SocketAddr::new(std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)).into(), u16::from_be(addr.sin_port)))
    } else {
        // SAFETY: as above, with sockaddr_in6
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(fd, libc::SOL_IPV6, SO_ORIGINAL_DST, (&mut addr as *mut libc::sockaddr_in6).cast(), &mut len)
        };
        (result == 0).then(|| SocketAddr::new(std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr).into(), u16::from_be(addr.sin6_port)))
    }
}

/// Elsewhere (Windows) the diverter rewrites packets so the listener sees the original
/// destination port directly; nothing to recover.
#[cfg(not(target_os = "linux"))]
pub fn original_destination(_stream: &TcpStream) -> Option<SocketAddr> {
    None
}

/// Asks the kernel to report each UDP datagram's original destination (before a REDIRECT)
#[cfg(target_os = "linux")]
pub fn enable_udp_original_destination(socket: &tokio::net::UdpSocket) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let on: libc::c_int = 1;
    let (level, option) = match socket.local_addr()? {
        SocketAddr::V4(_) => (libc::SOL_IP, libc::IP_RECVORIGDSTADDR),
        SocketAddr::V6(_) => (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR),
    };
    // SAFETY: `on` is a valid c_int of the size passed; the fd is open for the socket's life
    let result = unsafe { libc::setsockopt(socket.as_raw_fd(), level, option, (&on as *const libc::c_int).cast(), std::mem::size_of::<libc::c_int>() as libc::socklen_t) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enable_udp_original_destination(_socket: &tokio::net::UdpSocket) -> std::io::Result<()> {
    Ok(())
}

/// One datagram, its sender, and (Linux, after `enable_udp_original_destination`) its
/// original destination
#[cfg(target_os = "linux")]
pub async fn recv_with_original(socket: &tokio::net::UdpSocket, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    use std::os::fd::AsRawFd;
    loop {
        socket.readable().await?;
        let fd = socket.as_raw_fd();
        let result = socket.try_io(tokio::io::Interest::READABLE, || {
            // SAFETY: every pointer in msghdr refers to a live local buffer with its true
            // length; recvmsg writes within those lengths. Control messages are read only
            // through the CMSG_* macros, bounded by msg_controllen as the kernel set it.
            unsafe {
                let mut source: libc::sockaddr_storage = std::mem::zeroed();
                let mut control = [0u8; 128];
                let mut iov = libc::iovec { iov_base: buffer.as_mut_ptr().cast(), iov_len: buffer.len() };
                let mut message: libc::msghdr = std::mem::zeroed();
                message.msg_name = (&mut source as *mut libc::sockaddr_storage).cast();
                message.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                message.msg_iov = &mut iov;
                message.msg_iovlen = 1;
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen = control.len() as _;
                let read = libc::recvmsg(fd, &mut message, 0);
                if read < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let peer = socket_address(&source).ok_or_else(|| std::io::Error::other("unknown sender address family"))?;
                let mut original = None;
                let mut cmsg = libc::CMSG_FIRSTHDR(&message);
                while !cmsg.is_null() {
                    let header = &*cmsg;
                    let is_v4 = header.cmsg_level == libc::SOL_IP && header.cmsg_type == libc::IP_ORIGDSTADDR;
                    let is_v6 = header.cmsg_level == libc::SOL_IPV6 && header.cmsg_type == libc::IPV6_ORIGDSTADDR;
                    if is_v4 || is_v6 {
                        let mut storage: libc::sockaddr_storage = std::mem::zeroed();
                        let data = libc::CMSG_DATA(cmsg);
                        let length = (header.cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize).min(std::mem::size_of::<libc::sockaddr_storage>());
                        std::ptr::copy_nonoverlapping(data, (&mut storage as *mut libc::sockaddr_storage).cast(), length);
                        original = socket_address(&storage);
                    }
                    cmsg = libc::CMSG_NXTHDR(&message, cmsg);
                }
                Ok((read as usize, peer, original))
            }
        });
        match result {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            other => return other,
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn recv_with_original(socket: &tokio::net::UdpSocket, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    let (length, peer) = socket.recv_from(buffer).await?;
    Ok((length, peer, None))
}

#[cfg(target_os = "linux")]
fn socket_address(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    // SAFETY: the family field says which sockaddr type the storage holds
    unsafe {
        match storage.ss_family as libc::c_int {
            libc::AF_INET => {
                let v4 = &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>();
                Some(SocketAddr::new(std::net::Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr)).into(), u16::from_be(v4.sin_port)))
            }
            libc::AF_INET6 => {
                let v6 = &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
                Some(SocketAddr::new(std::net::Ipv6Addr::from(v6.sin6_addr.s6_addr).into(), u16::from_be(v6.sin6_port)))
            }
            _ => None,
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reports_where_each_datagram_was_sent() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        enable_udp_original_destination(&socket).unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"ping", socket.local_addr().unwrap()).await.unwrap();
        let mut buffer = [0u8; 16];
        let (length, peer, original) = recv_with_original(&socket, &mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"ping");
        assert_eq!(peer, client.local_addr().unwrap());
        // No REDIRECT here, so the original destination is simply our own address
        assert_eq!(original, Some(socket.local_addr().unwrap()));
    }
}
