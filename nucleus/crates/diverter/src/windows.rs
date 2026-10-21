//! Windows: WinDivert diversion (see `reflect`). Single host: one thread reflects outbound
//! TCP/UDP to the local listeners (and their replies back) and answers pings; gateway: a
//! forward-layer handle catches forwarded traffic and a network-layer one the listeners'
//! replies. A socket-layer sniffer learns which process owns each local port, for process
//! exclusion & attribution. Optionally (FakeNet-NG's ModifyLocalDNS / FixGateway) the DNS
//! servers and a default route are changed while running and restored on stop.
//!
//! Diversion lasts as long as the WinDivert handles, which Windows closes when the process
//! exits, even if it crashes; the DNS/route changes are restored by `stop()` (routes live in
//! the ActiveStore, so they're gone after a reboot at worst).
//!
//! Containment (`block_undiverted`, `block_after_stop`): while running, the reflector drops
//! every outbound packet it doesn't divert. When the nucleus stops, and when it dies (a guard
//! process waits for it: `guard_exit`), a Windows Firewall block takes over until
//! `--restore-network`. The next start lifts a leftover block once WinDivert is in place.

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _};
use fakenet_listeners::{Original, OriginalLookup};
use fakenet_schema::{ProcessInfo, Transport};
use windivert::prelude::*;

use crate::host_settings::{self, DnsSetting, PrimaryAddress};
use crate::packet;
use crate::reflect::{self, Reflector, Verdict};
use crate::{DiverterConfig, Mode, Plan};

type Owners = Arc<Mutex<HashMap<(Transport, u16), (u32, Instant)>>>;

pub struct Active {
    reflector: Arc<Mutex<Reflector>>,
    dns_backup: Option<Vec<DnsSetting>>,
    added_route: Option<PrimaryAddress>,
    /// Install the firewall block when stopping (cleared once done)
    block_after_stop: bool,
}

/// Blocks outbound traffic to everything but loopback with Windows Firewall
pub fn install_block() -> anyhow::Result<()> {
    powershell(&host_settings::install_block_script()).map(|_| ())
}

/// Lifts `install_block`, restoring the firewall and forwarding settings it changed
pub fn release_block() -> anyhow::Result<()> {
    powershell(&host_settings::release_block_script()).map(|_| ())
}

/// Waits for process `pid` to end, however it ends, then installs the block: run from a
/// separate guard process, so a crash or kill of the nucleus can't leave the network open
pub fn guard_exit(pid: u32) -> anyhow::Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_FAILED};
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE};
    // SAFETY: OpenProcess with a plain access mask; the handle is checked, waited on, closed
    unsafe {
        let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if !handle.is_null() {
            let waited = WaitForSingleObject(handle, INFINITE);
            CloseHandle(handle);
            if waited == WAIT_FAILED {
                bail!("waiting for process {pid}: {}", std::io::Error::last_os_error());
            }
        }
    }
    install_block()?;
    tracing::warn!("The nucleus (pid {pid}) exited: outbound traffic is blocked until `fakenet-nucleus --restore-network`");
    Ok(())
}

fn powershell(script: &str) -> anyhow::Result<String> {
    let output = Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", script]).output().context("running PowerShell")?;
    if !output.status.success() {
        bail!("PowerShell failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

impl Active {
    pub fn start(config: &DiverterConfig, plan: Plan) -> anyhow::Result<Active> {
        let mode = match config.mode {
            Mode::SingleHost => reflect::Mode::SingleHost,
            Mode::Gateway => {
                let v4 = config.gateway_address.iter().copied().find(IpAddr::is_ipv4);
                let v6 = config.gateway_address.iter().copied().find(IpAddr::is_ipv6);
                if v4.is_none() && v6.is_none() {
                    bail!("gateway mode on Windows needs [diverter] gateway_address (this host's address on the analysis network)");
                }
                reflect::Mode::Gateway { v4, v6 }
            }
        };
        let reflector = Arc::new(Mutex::new(Reflector::new(plan, mode)));
        let owners: Owners = Arc::default();
        let ping = config.answer_ping;
        let icmp = if ping { " or icmp or icmpv6" } else { "" };
        // With the block, every outbound packet goes through the reflector, so what isn't
        // diverted (other IP protocols, unlisted ports, flows that predate the start) is dropped
        let block = config.block_undiverted;

        // Open every handle before changing anything, so a missing driver or privilege fails
        // startup cleanly
        let sockets = WinDivert::socket("tcp or udp", 0, WinDivertFlags::new().set_sniff())
            .context("opening the WinDivert socket layer (run as Administrator, with WinDivert64.sys next to the executable)")?;
        let filter = match mode {
            reflect::Mode::SingleHost if block => "outbound and !loopback".to_string(),
            reflect::Mode::SingleHost => format!("outbound and !loopback and (tcp or udp{icmp})"),
            // The gateway's own traffic isn't the sample's: only listener replies are handled
            reflect::Mode::Gateway { .. } => "outbound and !loopback and (tcp or udp)".to_string(),
        };
        let network = Arc::new(WinDivert::network(filter, 0, WinDivertFlags::new()).context("opening the WinDivert network layer")?);
        let forward = match mode {
            reflect::Mode::Gateway { .. } => {
                let filter = if block { "true".to_string() } else { format!("tcp or udp{icmp}") };
                Some(WinDivert::forward(filter, 0, WinDivertFlags::new()).context("opening the WinDivert forward layer (is IP forwarding on?)")?)
            }
            reflect::Mode::SingleHost => None,
        };

        let mut active = Active { reflector: reflector.clone(), dns_backup: None, added_route: None, block_after_stop: config.block_after_stop };
        if config.fix_gateway {
            let routes: u32 = powershell(host_settings::QUERY_DEFAULT_ROUTES)?.trim().parse().unwrap_or(0);
            if routes == 0 {
                let primary: PrimaryAddress = serde_json::from_str(powershell(host_settings::QUERY_PRIMARY)?.trim()).context("finding this host's address for a default route")?;
                powershell(&host_settings::add_route_script(&primary))?;
                tracing::info!("Added a default route via {} (FixGateway)", primary.address);
                active.added_route = Some(primary);
            }
        }
        if config.fix_dns {
            let backup = host_settings::parse_dns(&powershell(host_settings::QUERY_DNS)?)?;
            if let Err(e) = powershell(&host_settings::set_dns_script(&backup, config.fix_dns_server)) {
                active.restore_host_settings();
                return Err(e);
            }
            tracing::info!("DNS servers set to {} (ModifyLocalDNS)", config.fix_dns_server);
            active.dns_backup = Some(backup);
        }

        let socket_owners = owners.clone();
        std::thread::Builder::new().name("fakenet-windivert-sockets".into()).spawn(move || track_owners(sockets, socket_owners))?;
        let excluded = config.excluded_processes.clone();
        let (net, refl, own) = (network.clone(), reflector.clone(), owners.clone());
        // Single host: the host's outbound traffic is the sample's, so the block applies to it
        let outbound_block = block && matches!(mode, reflect::Mode::SingleHost);
        std::thread::Builder::new().name("fakenet-windivert".into()).spawn(move || reflect_outbound(net, refl, own, excluded, ping, outbound_block))?;
        if let Some(forward) = forward {
            let (net, refl) = (network.clone(), reflector.clone());
            std::thread::Builder::new().name("fakenet-windivert-forward".into()).spawn(move || reflect_forwarded(forward, net, refl, ping, block))?;
        }
        tracing::info!("Diverting traffic with WinDivert ({:?})", config.mode);
        // A block left by the previous stop would stop connections before WinDivert sees
        // them; lifted only now, with the reflector (and its own block) running
        if let Err(e) = release_block() {
            tracing::warn!("Could not lift the previous run's firewall block: {e:#}");
        }
        Ok(active)
    }

    pub fn original_lookup(&self) -> OriginalLookup {
        let reflector = self.reflector.clone();
        Arc::new(move |transport, peer, local| -> Option<Original> { reflector.lock().ok()?.original(transport, peer, local) })
    }

    fn restore_host_settings(&mut self) {
        if let Some(backup) = self.dns_backup.take() {
            match powershell(&host_settings::restore_dns_script(&backup)) {
                Ok(_) => tracing::info!("DNS servers restored"),
                Err(e) => tracing::error!("Restoring DNS servers failed: {e:#}"),
            }
        }
        if let Some(route) = self.added_route.take() {
            match powershell(&host_settings::remove_route_script(&route)) {
                Ok(_) => tracing::info!("Default route removed"),
                Err(e) => tracing::error!("Removing the default route failed: {e:#}"),
            }
        }
    }

    pub fn stop(mut self) -> anyhow::Result<()> {
        self.restore_host_settings();
        self.block_if_asked()?;
        // The handles live in their threads and close when the process exits
        tracing::info!("WinDivert diversion ends when the nucleus exits");
        Ok(())
    }

    fn block_if_asked(&mut self) -> anyhow::Result<()> {
        if std::mem::take(&mut self.block_after_stop) {
            install_block().context("installing the firewall block (block_after_stop)")?;
            tracing::warn!("Diversion stopping; outbound traffic stays blocked. Run `fakenet-nucleus --restore-network` to release it");
        }
        Ok(())
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.restore_host_settings();
        if let Err(e) = self.block_if_asked() {
            tracing::error!("{e:#}");
        }
    }
}

/// Socket layer: local port -> owning process, from bind() and connect() events
fn track_owners(handle: WinDivert<SocketLayer>, owners: Owners) {
    loop {
        let event = match handle.recv(None) {
            Ok(event) => event,
            Err(e) => {
                tracing::warn!("WinDivert socket layer: {e}");
                return;
            }
        };
        let address = &event.address;
        if !matches!(address.event(), WinDivertEvent::SocketBind | WinDivertEvent::SocketConnect) {
            continue;
        }
        let transport = match address.protocol() {
            6 => Transport::Tcp,
            17 => Transport::Udp,
            _ => continue,
        };
        let Ok(mut owners) = owners.lock() else { return };
        let now = Instant::now();
        if owners.len() > 65536 {
            owners.retain(|_, (_, seen)| now.duration_since(*seen) < Duration::from_secs(600));
        }
        owners.insert((transport, address.local_port()), (address.process_id(), now));
    }
}

/// Rewrites a packet's addresses; false if it couldn't be
fn rewrite(data: &mut Vec<u8>, src: std::net::SocketAddr, dst: std::net::SocketAddr) -> bool {
    packet::rewrite(data, src, dst)
}

/// Single host: outbound client packets & listener replies. Gateway: listener replies.
fn reflect_outbound(handle: Arc<WinDivert<NetworkLayer>>, reflector: Arc<Mutex<Reflector>>, owners: Owners, excluded: Vec<String>, ping: bool, block: bool) {
    let own_pid = std::process::id();
    let mut buffer = vec![0u8; 65535];
    loop {
        let packet = match handle.recv(Some(&mut buffer)) {
            Ok(packet) => packet,
            Err(e) => {
                tracing::error!("WinDivert network layer stopped: {e}");
                return;
            }
        };
        let mut packet = packet.into_owned();
        if ping {
            if let Some(reply) = packet::echo_reply(&packet.data) {
                // Answer the ping ourselves: the request goes no further
                packet.data = reply.into();
                packet.address.set_outbound(false);
                if let Err(e) = handle.send(&packet) {
                    tracing::debug!("WinDivert send (ping): {e}");
                }
                continue;
            }
        }
        let mut verdict = None;
        if let Some(flow) = packet::parse(&packet.data) {
            let owner = || {
                let lookup = || owners.lock().ok().and_then(|o| o.get(&(flow.transport, flow.src.port())).map(|(pid, _)| *pid));
                let mut pid = lookup();
                // The socket event for a brand-new connection can trail its first packet by
                // a moment; wait briefly when it matters (exclusions)
                for _ in 0..10 {
                    if pid.is_some() || excluded.is_empty() {
                        break;
                    }
                    std::thread::sleep(Duration::from_micros(200));
                    pid = lookup();
                }
                pid.map(process_info)
            };
            let is_excluded = |process: &Option<ProcessInfo>| process.as_ref().is_some_and(|p| p.pid == own_pid || crate::is_excluded_process(p, &excluded));
            let decided = reflector.lock().map(|mut r| r.handle(&flow, Instant::now(), owner, is_excluded)).unwrap_or(Verdict::Pass);
            if let Verdict::Reflect { src, dst } = decided {
                let gateway_reply = reflector.lock().map(|r| r.is_gateway()).unwrap_or(false);
                if rewrite(packet.data.to_mut(), src, dst) {
                    // Single host: deliver to the local stack. Gateway: replies leave as they are.
                    if !gateway_reply {
                        packet.address.set_outbound(false);
                    }
                    packet.address.set_ip_checksum(true);
                    packet.address.set_tcp_checksum(true);
                    packet.address.set_udp_checksum(true);
                }
            }
            verdict = Some(decided);
        }
        if reflect::drops(verdict.as_ref(), block, packet::is_link_local_control(&packet.data)) {
            continue; // Not re-injected: the packet never leaves
        }
        if let Err(e) = handle.send(&packet) {
            tracing::debug!("WinDivert send: {e}");
        }
    }
}

/// Gateway: forwarded client packets go to the local listeners (re-injected inbound on the
/// network layer); forwarded pings are answered
fn reflect_forwarded(handle: WinDivert<ForwardLayer>, network: Arc<WinDivert<NetworkLayer>>, reflector: Arc<Mutex<Reflector>>, ping: bool, block: bool) {
    let mut buffer = vec![0u8; 65535];
    loop {
        let packet = match handle.recv(Some(&mut buffer)) {
            Ok(packet) => packet,
            Err(e) => {
                tracing::error!("WinDivert forward layer stopped: {e}");
                return;
            }
        };
        let mut packet = packet.into_owned();
        if ping {
            if let Some(reply) = packet::echo_reply(&packet.data) {
                packet.data = reply.into();
                if let Err(e) = handle.send(&packet) {
                    tracing::debug!("WinDivert send (forwarded ping): {e}");
                }
                continue;
            }
        }
        let verdict = packet::parse(&packet.data).map(|flow| reflector.lock().map(|mut r| r.handle(&flow, Instant::now(), || None, |_| false)).unwrap_or(Verdict::Pass));
        if reflect::drops(verdict.as_ref(), block, packet::is_link_local_control(&packet.data)) {
            continue; // Not forwarded
        }
        match verdict.unwrap_or(Verdict::Pass) {
            Verdict::Reflect { src, dst } => {
                let mut data = packet.data.into_owned();
                if !rewrite(&mut data, src, dst) {
                    continue;
                }
                // SAFETY (crate contract): the address starts zeroed; we fill in direction and
                // interface before sending, as WinDivert requires for injected packets
                let mut local = unsafe { WinDivertPacket::<NetworkLayer>::new(data) };
                local.address.set_outbound(false);
                local.address.set_interface_index(packet.address.interface_index());
                local.address.set_subinterface_index(packet.address.subinterface_index());
                local.address.set_ip_checksum(true);
                local.address.set_tcp_checksum(true);
                local.address.set_udp_checksum(true);
                if let Err(e) = network.send(&local) {
                    tracing::debug!("WinDivert inject: {e}");
                }
            }
            Verdict::Pass | Verdict::Undiverted => {
                if let Err(e) = handle.send(&packet) {
                    tracing::debug!("WinDivert forward: {e}");
                }
            }
        }
    }
}

fn process_info(pid: u32) -> ProcessInfo {
    let exe = image_path(pid);
    let name = exe.as_deref().and_then(|e| e.rsplit(['\\', '/']).next()).map(str::to_string).unwrap_or_else(|| format!("pid {pid}"));
    ProcessInfo { pid, name, exe }
}

/// A process's executable path. FFI wrapper: OpenProcess with the least access that
/// allows QueryFullProcessImageNameW, into a buffer whose size we pass in and that the
/// call never overruns; the handle is always closed.
fn image_path(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};

    let mut buffer = [0u16; 1024];
    let mut length = buffer.len() as u32;
    // SAFETY: OpenProcess has no memory-safety preconditions; a null handle means failure
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    // SAFETY: `process` is a valid handle; buffer/length describe a writable u16 buffer
    let ok = unsafe { QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut length) };
    // SAFETY: `process` came from OpenProcess and is closed exactly once
    unsafe { CloseHandle(process) };
    (ok != 0).then(|| String::from_utf16_lossy(&buffer[..length as usize]))
}
