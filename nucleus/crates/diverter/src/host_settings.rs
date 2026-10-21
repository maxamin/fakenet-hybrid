//! Windows host settings FakeNet-NG can change while it runs (ModifyLocalDNS, FixGateway),
//! as PowerShell scripts. Pure functions, so they're testable anywhere; only Windows runs
//! them. Scripts only ever contain values we parsed and typed (interface indices, IPs), and
//! routes are added to the ActiveStore, so even a crash can't leave them past a reboot.

use std::net::IpAddr;

use serde::Deserialize;

/// Each IPv4 interface's DNS servers, as JSON
pub const QUERY_DNS: &str = "@(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike 'Loopback*' } | Select-Object InterfaceIndex,ServerAddresses) | ConvertTo-Json -Compress";
/// How many IPv4 default routes exist
pub const QUERY_DEFAULT_ROUTES: &str = "@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).Count";
/// The first usable IPv4 interface and address, as JSON
pub const QUERY_PRIMARY: &str = "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike 'Loopback*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1 InterfaceIndex,IPAddress | ConvertTo-Json -Compress";

/// The Windows Firewall rule group of the outbound block (LEAK-01's fix)
pub const BLOCK_GROUP: &str = "FakeNet hybrid";
/// Everything but loopback (127.0.0.0/8, ::1): what the block rule covers
pub const BLOCKED_ADDRESSES: [&str; 4] = ["0.0.0.0-126.255.255.255", "128.0.0.0-255.255.255.255", "::", "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

/// Blocks outbound traffic to everything but loopback, after the nucleus stops or dies: a
/// firewall block rule (block rules win over every allow rule), the firewall switched on for
/// every profile, and IP forwarding off (routed traffic, gateway mode, isn't filtered by the
/// firewall). What it changes is saved once, so `release_block_script` can put it back; the
/// script can run again (stop, then the exit guard) without losing that.
pub fn install_block_script() -> String {
    let addresses = BLOCKED_ADDRESSES.iter().map(|a| format!("'{a}'")).collect::<Vec<_>>().join(",");
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $dir = Join-Path $env:ProgramData 'FakeNetHybrid'\n\
         New-Item -ItemType Directory -Force -Path $dir | Out-Null\n\
         $state = Join-Path $dir 'block-state.json'\n\
         if (-not (Test-Path $state)) {{\n\
         \x20 @{{ profiles = @(Get-NetFirewallProfile | Select-Object Name,Enabled); forwarding = @(Get-NetIPInterface | Where-Object {{ $_.Forwarding -eq 'Enabled' }} | Select-Object InterfaceIndex,AddressFamily) }} | ConvertTo-Json -Depth 4 | Set-Content -Path $state\n\
         }}\n\
         Remove-NetFirewallRule -Group '{BLOCK_GROUP}' -ErrorAction SilentlyContinue\n\
         New-NetFirewallRule -Group '{BLOCK_GROUP}' -DisplayName 'FakeNet hybrid: outbound blocked (fakenet-nucleus --restore-network lifts it)' -Direction Outbound -Action Block -Profile Any -RemoteAddress @({addresses}) | Out-Null\n\
         Set-NetFirewallProfile -All -Enabled True\n\
         Get-NetIPInterface | Where-Object {{ $_.Forwarding -eq 'Enabled' }} | Set-NetIPInterface -Forwarding Disabled\n"
    )
}

/// Lifts the block: removes the rule group, and restores the firewall profiles' state and
/// IP forwarding as they were before the first block
pub fn release_block_script() -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         Remove-NetFirewallRule -Group '{BLOCK_GROUP}' -ErrorAction SilentlyContinue\n\
         $state = Join-Path (Join-Path $env:ProgramData 'FakeNetHybrid') 'block-state.json'\n\
         if (Test-Path $state) {{\n\
         \x20 $saved = Get-Content -Raw -Path $state | ConvertFrom-Json\n\
         \x20 foreach ($p in @($saved.profiles)) {{ Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled }}\n\
         \x20 foreach ($i in @($saved.forwarding)) {{ Set-NetIPInterface -InterfaceIndex $i.InterfaceIndex -AddressFamily $i.AddressFamily -Forwarding Enabled -ErrorAction SilentlyContinue }}\n\
         \x20 Remove-Item -Path $state\n\
         }}\n"
    )
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DnsSetting {
    #[serde(rename = "InterfaceIndex")]
    pub interface: u32,
    #[serde(rename = "ServerAddresses", default)]
    pub servers: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PrimaryAddress {
    #[serde(rename = "InterfaceIndex")]
    pub interface: u32,
    #[serde(rename = "IPAddress")]
    pub address: IpAddr,
}

/// ConvertTo-Json gives an object for one item and an array for several
pub fn parse_dns(json: &str) -> anyhow::Result<Vec<DnsSetting>> {
    let json = json.trim();
    if json.is_empty() {
        return Ok(Vec::new());
    }
    match serde_json::from_str::<Vec<DnsSetting>>(json) {
        Ok(list) => Ok(list),
        Err(_) => Ok(vec![serde_json::from_str::<DnsSetting>(json)?]),
    }
}

fn list(servers: &[IpAddr]) -> String {
    servers.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(",")
}

pub fn set_dns_script(settings: &[DnsSetting], server: IpAddr) -> String {
    settings.iter().map(|s| format!("Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses {};", s.interface, list(&[server]))).collect()
}

pub fn restore_dns_script(settings: &[DnsSetting]) -> String {
    settings
        .iter()
        .map(|s| match s.servers.is_empty() {
            true => format!("Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses;", s.interface),
            false => format!("Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses {};", s.interface, list(&s.servers)),
        })
        .collect()
}

/// A default route through our own address: packets to anywhere leave the stack, where the
/// diverter takes them
pub fn add_route_script(primary: &PrimaryAddress) -> String {
    format!("New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex {} -NextHop '{}' -RouteMetric 9999 -PolicyStore ActiveStore | Out-Null", primary.interface, primary.address)
}

pub fn remove_route_script(primary: &PrimaryAddress) -> String {
    format!("Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex {} -NextHop '{}' -PolicyStore ActiveStore -Confirm:$false", primary.interface, primary.address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_powershell_json_and_builds_scripts() {
        let one = parse_dns(r#"{"InterfaceIndex":12,"ServerAddresses":["10.0.2.3"]}"#).unwrap();
        assert_eq!(one, [DnsSetting { interface: 12, servers: vec!["10.0.2.3".parse().unwrap()] }]);
        let many = parse_dns(r#"[{"InterfaceIndex":12,"ServerAddresses":["10.0.2.3","8.8.8.8"]},{"InterfaceIndex":7,"ServerAddresses":[]}]"#).unwrap();
        assert_eq!(many.len(), 2);
        assert!(parse_dns(r#"{"InterfaceIndex":"12; Remove-Item C:\\"}"#).is_err()); // Never trusted as text
        assert_eq!(set_dns_script(&many, "192.0.2.53".parse().unwrap()), "Set-DnsClientServerAddress -InterfaceIndex 12 -ServerAddresses '192.0.2.53';Set-DnsClientServerAddress -InterfaceIndex 7 -ServerAddresses '192.0.2.53';");
        let restore = restore_dns_script(&many);
        assert!(restore.contains("-InterfaceIndex 12 -ServerAddresses '10.0.2.3','8.8.8.8'") && restore.contains("-InterfaceIndex 7 -ResetServerAddresses"));
        let primary: PrimaryAddress = serde_json::from_str(r#"{"InterfaceIndex":12,"IPAddress":"10.0.2.15"}"#).unwrap();
        assert!(add_route_script(&primary).contains("-NextHop '10.0.2.15'") && add_route_script(&primary).contains("ActiveStore"));
        assert!(remove_route_script(&primary).starts_with("Remove-NetRoute"));
    }

    #[test]
    fn block_scripts_cover_everything_but_loopback_and_undo_themselves() {
        let install = install_block_script();
        assert!(install.contains("-Direction Outbound -Action Block -Profile Any"));
        assert!(install.contains("'0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255','::','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'"));
        assert!(install.contains("if (-not (Test-Path $state))")); // Saved once, not overwritten
        assert!(install.contains("Set-NetFirewallProfile -All -Enabled True"));
        assert!(install.contains("-Forwarding Disabled"));
        let release = release_block_script();
        assert!(release.contains("Remove-NetFirewallRule -Group 'FakeNet hybrid'"));
        assert!(release.contains("Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled"));
        assert!(release.contains("-Forwarding Enabled"));
        // 127.0.0.0/8 and ::1 stay open: nothing in the ranges touches them
        let parse = |a: &str| a.parse::<std::net::IpAddr>().unwrap();
        for range in BLOCKED_ADDRESSES {
            let (from, to) = range.split_once('-').unwrap_or((range, range));
            for loopback in ["127.0.0.1", "127.255.255.254", "::1"] {
                let (from, to, ip) = (parse(from), parse(to), parse(loopback));
                assert!(!(from.is_ipv4() == ip.is_ipv4() && from <= ip && ip <= to), "{range} covers {loopback}");
            }
        }
    }

}
