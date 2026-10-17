//! Sends a host's outbound traffic to the nucleus's listeners, and puts everything back on
//! shutdown.
//!
//! - Linux: iptables NAT REDIRECT in a dedicated `FAKENET` chain (the kernel tracks the
//!   original destinations; listeners read them with SO_ORIGINAL_DST), plus an optional
//!   NFQUEUE pass that marks connections from excluded processes so the NAT skips them.
//!   Stopping removes the chain; `restore()` also cleans up after a crash.
//! - Windows: WinDivert reflection (see `reflect`), with process filtering from WinDivert's
//!   socket layer. Diversion lasts exactly as long as the process's WinDivert handles, so
//!   nothing needs restoring even after a crash.

use serde::Deserialize;

pub mod host_settings;
pub mod packet;
pub mod reflect;
pub mod wire;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DiverterConfig {
    /// Off by default: turning it on takes over the host's traffic. Enable it inside the
    /// analysis VM.
    pub enabled: bool,
    pub mode: Mode,
    /// Destination ports never diverted (e.g. 22/3389 to manage a gateway)
    pub ignore_ports: Vec<u16>,
    /// Process names (e.g. "python3", "procmon.exe") whose traffic is never diverted.
    /// Single-host mode only. The nucleus never diverts its own traffic.
    pub excluded_processes: Vec<String>,
    /// Linux NFQUEUE number (used only with excluded_processes)
    pub queue_num: u16,
    /// Also divert IPv6 (Linux: needs ip6tables NAT; skipped with a warning if missing)
    pub ipv6: bool,
    /// Answer pings to any address (malware checks connectivity with ICMP echo)
    pub answer_ping: bool,
    /// Windows gateway mode: this host's address(es) on the analysis network
    pub gateway_address: Vec<std::net::IpAddr>,
    /// Windows: point every interface's DNS at `fix_dns_server` while running (FakeNet-NG's
    /// ModifyLocalDNS), restoring the previous servers on stop
    pub fix_dns: bool,
    pub fix_dns_server: std::net::IpAddr,
    /// Windows: add a default route if there is none, so traffic to any address leaves the
    /// stack (and is diverted); removed on stop (FakeNet-NG's FixGateway)
    pub fix_gateway: bool,
}

impl Default for DiverterConfig {
    fn default() -> Self {
        DiverterConfig {
            enabled: false,
            mode: Mode::SingleHost,
            ignore_ports: Vec::new(),
            excluded_processes: Vec::new(),
            queue_num: 4242,
            ipv6: true,
            answer_ping: true,
            gateway_address: Vec::new(),
            fix_dns: false,
            fix_dns_server: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 53)),
            fix_gateway: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Malware runs on this host (OUTPUT chain / WinDivert outbound)
    SingleHost,
    /// This host is the analysis network's gateway (Linux PREROUTING; Windows forward layer,
    /// with `gateway_address`)
    Gateway,
}

/// Where traffic goes, derived from the listeners
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Plan {
    /// Ports with a TCP/UDP listener: traffic to them keeps its port
    pub tcp_ports: Vec<u16>,
    pub udp_ports: Vec<u16>,
    /// Everything else goes to these (the "auto" listeners); None = not diverted
    pub tcp_default: Option<u16>,
    pub udp_default: Option<u16>,
    /// FTP passive data ports: kept as-is so data connections reach the FTP listener
    pub passive_ports: Option<(u16, u16)>,
    pub ignore_ports: Vec<u16>,
}

/// An active diversion. `stop()` (or dropping it) restores the network.
pub struct Diverter {
    #[cfg(target_os = "linux")]
    active: Option<linux::Active>,
    #[cfg(windows)]
    active: Option<windows::Active>,
}

impl Diverter {
    pub fn start(config: &DiverterConfig, plan: Plan) -> anyhow::Result<Diverter> {
        #[cfg(target_os = "linux")]
        return Ok(Diverter { active: Some(linux::Active::start(config, &plan)?) });
        #[cfg(windows)]
        return Ok(Diverter { active: Some(windows::Active::start(config, plan)?) });
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = (config, plan);
            anyhow::bail!("diversion is only supported on Linux and Windows")
        }
    }

    /// For listeners: the real endpoints of reflected connections (Windows only; on Linux
    /// the kernel keeps them)
    pub fn original_lookup(&self) -> Option<fakenet_listeners::OriginalLookup> {
        #[cfg(windows)]
        return self.active.as_ref().map(|a| a.original_lookup());
        #[cfg(not(windows))]
        None
    }

    pub fn stop(mut self) -> anyhow::Result<()> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> anyhow::Result<()> {
        #[cfg(any(target_os = "linux", windows))]
        if let Some(active) = self.active.take() {
            return active.stop();
        }
        Ok(())
    }
}

impl Drop for Diverter {
    fn drop(&mut self) {
        if let Err(e) = self.stop_inner() {
            tracing::error!("Restoring the network failed: {e:#}");
        }
    }
}

/// Removes anything a previous run left behind (e.g. after it was killed)
pub fn restore() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    return linux::cleanup();
    #[cfg(not(target_os = "linux"))]
    Ok(())
}
