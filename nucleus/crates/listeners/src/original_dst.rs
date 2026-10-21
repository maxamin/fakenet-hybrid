//! The destination a connection had before an iptables REDIRECT sent it to us, so sniffing
//! and events use the address the malware really contacted:
//! - TCP: Linux's SO_ORIGINAL_DST.
//! - UDP (and QUIC): IP_ORIGDSTADDR only reports where a datagram arrived (after the NAT,
//!   e.g. 127.0.0.1), so the original destination comes from the connection-tracking table
//!   over netlink (`conntrack_original`).
//! Replies to REDIRECTed UDP must leave from the address the datagram arrived at, or the
//! kernel can't match them to the NAT entry and the client gets them from the wrong address:
//! `send_from` sets that source explicitly. These thin wrappers hold the crate's networking
//! `unsafe`, each block with its safety argument.

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

/// A UDP socket bound to `ip` even when it isn't one of ours (IP_TRANSPARENT, which needs
/// CAP_NET_ADMIN): a new flow, such as a TFTP transfer, then comes from the address the
/// client REDIRECTed to us thought it was talking to
#[cfg(target_os = "linux")]
pub fn bind_transparent(ip: std::net::IpAddr) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Socket, Type};
    use std::os::fd::AsRawFd;
    let (domain, level, option) = match ip {
        std::net::IpAddr::V4(_) => (Domain::IPV4, libc::SOL_IP, libc::IP_TRANSPARENT),
        std::net::IpAddr::V6(_) => (Domain::IPV6, libc::SOL_IPV6, libc::IPV6_TRANSPARENT),
    };
    let socket = Socket::new(domain, Type::DGRAM, None)?;
    let on: libc::c_int = 1;
    // SAFETY: `on` is a valid c_int of the size passed; the fd is open for the socket's life
    if unsafe { libc::setsockopt(socket.as_raw_fd(), level, option, (&on as *const libc::c_int).cast(), std::mem::size_of::<libc::c_int>() as libc::socklen_t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    socket.bind(&SocketAddr::new(ip, 0).into())?;
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket.into())
}

#[cfg(not(target_os = "linux"))]
pub fn bind_transparent(_ip: std::net::IpAddr) -> std::io::Result<tokio::net::UdpSocket> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// One datagram, its sender, and (Linux, after `enable_udp_original_destination`) the local
/// address it arrived at (after any NAT: see `conntrack_original` for the address before)
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
                // cmsghdr needs its natural alignment
                #[repr(C, align(8))]
                struct Control([u8; 128]);
                let mut control = Control([0; 128]);
                let mut iov = libc::iovec { iov_base: buffer.as_mut_ptr().cast(), iov_len: buffer.len() };
                let mut message: libc::msghdr = std::mem::zeroed();
                message.msg_name = (&mut source as *mut libc::sockaddr_storage).cast();
                message.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                message.msg_iov = &mut iov;
                message.msg_iovlen = 1;
                message.msg_control = control.0.as_mut_ptr().cast();
                message.msg_controllen = control.0.len() as _;
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

/// Sends a datagram to `to` from the local address `from` (where the request arrived), so the
/// kernel matches the reply to a REDIRECT's NAT entry and rewrites its source back to the
/// address the client contacted. Without `from` (or across address families) it's a plain
/// `send_to`.
#[cfg(target_os = "linux")]
pub async fn send_from(socket: &tokio::net::UdpSocket, data: &[u8], from: Option<std::net::IpAddr>, to: SocketAddr) -> std::io::Result<usize> {
    use std::net::IpAddr;
    use std::os::fd::AsRawFd;
    let local_v4 = socket.local_addr()?.is_ipv4();
    let source = match (from, to) {
        (Some(IpAddr::V4(ip)), SocketAddr::V4(_)) if local_v4 && !ip.is_unspecified() => IpAddr::V4(ip),
        (Some(IpAddr::V6(ip)), SocketAddr::V6(_)) if !local_v4 && !ip.is_unspecified() => IpAddr::V6(ip),
        _ => return socket.send_to(data, to).await,
    };
    loop {
        socket.writable().await?;
        let fd = socket.as_raw_fd();
        let result = socket.try_io(tokio::io::Interest::WRITABLE, || {
            // SAFETY: every pointer in msghdr refers to a live local value with its true length.
            // The control buffer is sized with CMSG_SPACE for the one pktinfo it holds, and the
            // pktinfo is written through CMSG_DATA of the first header, within that space.
            unsafe {
                let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
                let mut message: libc::msghdr = std::mem::zeroed();
                // cmsghdr needs its natural alignment
                #[repr(C, align(8))]
                struct Control([u8; 64]);
                let mut control = Control([0; 64]);
                let (mut v4, mut v6): (libc::sockaddr_in, libc::sockaddr_in6) = (std::mem::zeroed(), std::mem::zeroed());
                match to {
                    SocketAddr::V4(to) => {
                        v4.sin_family = libc::AF_INET as libc::sa_family_t;
                        v4.sin_port = to.port().to_be();
                        v4.sin_addr.s_addr = u32::from(*to.ip()).to_be();
                        message.msg_name = (&mut v4 as *mut libc::sockaddr_in).cast();
                        message.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                    }
                    SocketAddr::V6(to) => {
                        v6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                        v6.sin6_port = to.port().to_be();
                        v6.sin6_addr.s6_addr = to.ip().octets();
                        v6.sin6_scope_id = to.scope_id();
                        message.msg_name = (&mut v6 as *mut libc::sockaddr_in6).cast();
                        message.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
                    }
                }
                message.msg_iov = &mut iov;
                message.msg_iovlen = 1;
                message.msg_control = control.0.as_mut_ptr().cast();
                let (level, kind, length) = match source {
                    IpAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_PKTINFO, std::mem::size_of::<libc::in_pktinfo>()),
                    IpAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, std::mem::size_of::<libc::in6_pktinfo>()),
                };
                message.msg_controllen = libc::CMSG_SPACE(length as u32) as _;
                let cmsg = libc::CMSG_FIRSTHDR(&message);
                (*cmsg).cmsg_level = level;
                (*cmsg).cmsg_type = kind;
                (*cmsg).cmsg_len = libc::CMSG_LEN(length as u32) as _;
                match source {
                    IpAddr::V4(ip) => {
                        let mut info: libc::in_pktinfo = std::mem::zeroed();
                        info.ipi_spec_dst.s_addr = u32::from(ip).to_be();
                        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in_pktinfo>(), info);
                    }
                    IpAddr::V6(ip) => {
                        let mut info: libc::in6_pktinfo = std::mem::zeroed();
                        info.ipi6_addr.s6_addr = ip.octets();
                        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in6_pktinfo>(), info);
                    }
                }
                let sent = libc::sendmsg(fd, &message, 0);
                if sent < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(sent as usize)
            }
        });
        match result {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            other => return other,
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn send_from(socket: &tokio::net::UdpSocket, data: &[u8], _from: Option<std::net::IpAddr>, to: SocketAddr) -> std::io::Result<usize> {
    socket.send_to(data, to).await
}

/// The destination a NATed flow originally had, from the kernel's connection tracking
/// (ctnetlink): the flow is found by its reply direction, `local` (where its packets arrived
/// after a REDIRECT) to `peer`. `protocol` is the IP protocol number (6 TCP, 17 UDP). None
/// when there's no such flow, no ctnetlink, or no CAP_NET_ADMIN.
#[cfg(target_os = "linux")]
pub fn conntrack_original(protocol: u8, local: SocketAddr, peer: SocketAddr) -> Option<SocketAddr> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let request = conntrack::request(protocol, local, peer)?;
    // SAFETY: plain socket creation; the fd is owned (and closed) by `socket` from here on
    let socket = unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_NETFILTER);
        if fd < 0 {
            return None;
        }
        OwnedFd::from_raw_fd(fd)
    };
    let fd = socket.as_raw_fd();
    let timeout = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
    // SAFETY: sockaddr_nl is plain data; all-zero is valid (pid 0: the kernel)
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let mut reply = vec![0u8; 8192];
    // SAFETY: each call gets a pointer to a live value or buffer with its true size
    let received = unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&timeout as *const libc::timeval).cast(), std::mem::size_of::<libc::timeval>() as libc::socklen_t);
        let sent = libc::sendto(fd, request.as_ptr().cast(), request.len(), 0, (&kernel as *const libc::sockaddr_nl).cast(), std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t);
        if sent < 0 {
            return None;
        }
        libc::recv(fd, reply.as_mut_ptr().cast(), reply.len(), 0)
    };
    if received <= 0 {
        return None;
    }
    reply.truncate(received as usize);
    conntrack::original_destination(&reply)
}

#[cfg(not(target_os = "linux"))]
pub fn conntrack_original(_protocol: u8, _local: SocketAddr, _peer: SocketAddr) -> Option<SocketAddr> {
    None
}

/// ctnetlink messages (linux/netfilter/nfnetlink_conntrack.h), built and parsed without I/O
#[cfg(target_os = "linux")]
mod conntrack {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    const NFNL_SUBSYS_CTNETLINK: u16 = 1;
    const IPCTNL_MSG_CT_GET: u16 = 1;
    const NLM_F_REQUEST: u16 = 1;
    const NLMSG_ERROR: u16 = 2;
    const NLA_F_NESTED: u16 = 0x8000;
    const NLA_TYPE_MASK: u16 = 0x3fff;
    const CTA_TUPLE_ORIG: u16 = 1;
    const CTA_TUPLE_REPLY: u16 = 2;
    const CTA_TUPLE_IP: u16 = 1;
    const CTA_TUPLE_PROTO: u16 = 2;
    const CTA_IP_V4_SRC: u16 = 1;
    const CTA_IP_V4_DST: u16 = 2;
    const CTA_IP_V6_SRC: u16 = 3;
    const CTA_IP_V6_DST: u16 = 4;
    const CTA_PROTO_NUM: u16 = 1;
    const CTA_PROTO_SRC_PORT: u16 = 2;
    const CTA_PROTO_DST_PORT: u16 = 3;

    fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + payload.len() + 3);
        out.extend(((4 + payload.len()) as u16).to_ne_bytes());
        out.extend(kind.to_ne_bytes());
        out.extend(payload);
        out.resize(out.len().next_multiple_of(4), 0);
        out
    }

    /// An IPCTNL_MSG_CT_GET for the flow whose reply direction is `src` -> `dst`
    pub(super) fn request(protocol: u8, src: SocketAddr, dst: SocketAddr) -> Option<Vec<u8>> {
        let (family, addresses) = match (src.ip().to_canonical(), dst.ip().to_canonical()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => (libc::AF_INET as u8, [attribute(CTA_IP_V4_SRC, &s.octets()), attribute(CTA_IP_V4_DST, &d.octets())].concat()),
            (IpAddr::V6(s), IpAddr::V6(d)) => (libc::AF_INET6 as u8, [attribute(CTA_IP_V6_SRC, &s.octets()), attribute(CTA_IP_V6_DST, &d.octets())].concat()),
            _ => return None,
        };
        let ports = [attribute(CTA_PROTO_NUM, &[protocol]), attribute(CTA_PROTO_SRC_PORT, &src.port().to_be_bytes()), attribute(CTA_PROTO_DST_PORT, &dst.port().to_be_bytes())].concat();
        let tuple = [attribute(CTA_TUPLE_IP | NLA_F_NESTED, &addresses), attribute(CTA_TUPLE_PROTO | NLA_F_NESTED, &ports)].concat();
        let mut body = vec![family, 0, 0, 0]; // nfgenmsg: family, version 0, resource id 0
        body.extend(attribute(CTA_TUPLE_REPLY | NLA_F_NESTED, &tuple));
        let mut message = Vec::with_capacity(16 + body.len());
        message.extend(((16 + body.len()) as u32).to_ne_bytes());
        message.extend((NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_GET).to_ne_bytes());
        message.extend(NLM_F_REQUEST.to_ne_bytes());
        message.extend(1u32.to_ne_bytes()); // Sequence number
        message.extend(0u32.to_ne_bytes()); // Port id: the kernel assigns ours
        message.extend(body);
        Some(message)
    }

    /// (type without flags, payload) for each attribute in `data`; stops at malformed ones
    fn attributes(mut data: &[u8]) -> Vec<(u16, &[u8])> {
        let mut out = Vec::new();
        while data.len() >= 4 {
            let length = usize::from(u16::from_ne_bytes([data[0], data[1]]));
            let kind = u16::from_ne_bytes([data[2], data[3]]) & NLA_TYPE_MASK;
            if length < 4 || length > data.len() {
                break;
            }
            out.push((kind, &data[4..length]));
            data = &data[length.next_multiple_of(4).min(data.len())..];
        }
        out
    }

    fn find(data: &[u8], kind: u16) -> Option<&[u8]> {
        attributes(data).into_iter().find(|(k, _)| *k == kind).map(|(_, payload)| payload)
    }

    /// The original-direction destination in a ctnetlink reply
    pub(super) fn original_destination(reply: &[u8]) -> Option<SocketAddr> {
        let header = reply.get(..16)?;
        let length = u32::from_ne_bytes(header[..4].try_into().ok()?) as usize;
        if u16::from_ne_bytes([header[4], header[5]]) == NLMSG_ERROR || length > reply.len() || length < 20 {
            return None;
        }
        let tuple = find(&reply[20..length], CTA_TUPLE_ORIG)?;
        let addresses = find(tuple, CTA_TUPLE_IP)?;
        let ip = match (find(addresses, CTA_IP_V4_DST), find(addresses, CTA_IP_V6_DST)) {
            (Some(v4), _) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(v4).ok()?)),
            (None, Some(v6)) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(v6).ok()?)),
            _ => return None,
        };
        let port = find(find(tuple, CTA_TUPLE_PROTO)?, CTA_PROTO_DST_PORT)?;
        Some(SocketAddr::new(ip, u16::from_be_bytes(port.try_into().ok()?)))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn builds_requests_and_parses_replies() {
            let (local, peer): (SocketAddr, SocketAddr) = ("127.0.0.1:53".parse().unwrap(), "10.0.0.5:40000".parse().unwrap());
            let message = request(17, local, peer).unwrap();
            assert_eq!(u32::from_ne_bytes(message[..4].try_into().unwrap()) as usize, message.len());
            assert_eq!(u16::from_ne_bytes([message[4], message[5]]), 0x0101);
            assert_eq!(message[16], libc::AF_INET as u8);
            let tuple = find(&message[20..], CTA_TUPLE_REPLY).unwrap();
            assert_eq!(find(find(tuple, CTA_TUPLE_IP).unwrap(), CTA_IP_V4_SRC).unwrap(), [127, 0, 0, 1]);
            assert_eq!(find(find(tuple, CTA_TUPLE_PROTO).unwrap(), CTA_PROTO_DST_PORT).unwrap(), 40000u16.to_be_bytes());
            assert!(request(17, local, "[2001:db8::1]:1".parse().unwrap()).is_none());

            // A kernel reply: the original direction 10.0.0.5:40000 -> 198.51.100.53:53
            let addresses = [attribute(CTA_IP_V4_SRC, &[10, 0, 0, 5]), attribute(CTA_IP_V4_DST, &[198, 51, 100, 53])].concat();
            let ports = [attribute(CTA_PROTO_NUM, &[17]), attribute(CTA_PROTO_SRC_PORT, &40000u16.to_be_bytes()), attribute(CTA_PROTO_DST_PORT, &53u16.to_be_bytes())].concat();
            let original = [attribute(CTA_TUPLE_IP | NLA_F_NESTED, &addresses), attribute(CTA_TUPLE_PROTO | NLA_F_NESTED, &ports)].concat();
            let mut body = vec![libc::AF_INET as u8, 0, 0, 0];
            body.extend(attribute(CTA_TUPLE_ORIG | NLA_F_NESTED, &original));
            let mut reply = ((16 + body.len()) as u32).to_ne_bytes().to_vec();
            reply.extend([0x01, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
            reply.extend(body);
            assert_eq!(original_destination(&reply), Some("198.51.100.53:53".parse().unwrap()));
            assert_eq!(original_destination(&reply[..18]), None);
            let mut error = reply.clone();
            error[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
            assert_eq!(original_destination(&error), None);
        }
    }
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
    async fn transparent_binds_need_privilege_or_work() {
        // Root (CAP_NET_ADMIN) may bind a foreign address; anyone else gets an error, which
        // the TFTP handler answers by replying from its own address
        let result = bind_transparent("192.0.2.1".parse().unwrap());
        // SAFETY: geteuid has no preconditions
        match unsafe { libc::geteuid() } {
            0 => assert_eq!(result.unwrap().local_addr().unwrap().ip(), "192.0.2.1".parse::<std::net::IpAddr>().unwrap()),
            _ => assert!(result.is_err()),
        }
    }

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
