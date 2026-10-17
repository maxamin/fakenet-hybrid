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
}
