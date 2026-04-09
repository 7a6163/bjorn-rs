use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::state::AppState;

/// Network scanner: discovers live hosts via nmap -sn, then port-scans each.
///
/// Replaces Python's `scanning.py` NetworkScanner class.
pub struct NetworkScanner {
    state: Arc<AppState>,
}

/// A discovered host from the network scan.
#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub ip: String,
    pub hostname: String,
    pub mac: String,
    pub open_ports: Vec<u16>,
}

impl NetworkScanner {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Run a full network scan cycle:
    /// 1. Detect the local network via `ip route`
    /// 2. Discover live hosts via `nmap -sn`
    /// 3. Port-scan each host with async TCP connect
    /// 4. Upsert results into the SQLite knowledge base
    pub async fn scan(&self) -> Vec<DiscoveredHost> {
        let network = match self.detect_network().await {
            Some(n) => n,
            None => {
                tracing::error!("failed to detect network");
                return vec![];
            }
        };

        tracing::info!(network = %network, "starting network scan");

        // Update display status
        {
            let mut status = self.state.status.write().await;
            status.current_action = "NetworkScanner".to_string();
        }

        // Step 1: Host discovery via nmap -sn
        let live_ips = self.discover_hosts(&network).await;
        if live_ips.is_empty() {
            tracing::warn!("no live hosts found");
            return vec![];
        }
        tracing::info!(count = live_ips.len(), "live hosts discovered");

        // Step 2: Resolve MAC addresses
        let config = self.state.config();
        let mac_blacklist: HashSet<&str> = config
            .mac_scan_blacklist
            .iter()
            .map(|s| s.as_str())
            .collect();
        let ip_blacklist: HashSet<&str> = config
            .ip_scan_blacklist
            .iter()
            .map(|s| s.as_str())
            .collect();

        let mut hosts: Vec<DiscoveredHost> = Vec::new();
        for (ip, hostname) in &live_ips {
            if config.blacklistcheck && ip_blacklist.contains(ip.as_str()) {
                continue;
            }
            let mac = self.resolve_mac(ip).await;
            if config.blacklistcheck && mac_blacklist.contains(mac.as_str()) {
                continue;
            }
            hosts.push(DiscoveredHost {
                ip: ip.clone(),
                hostname: hostname.clone(),
                mac,
                open_ports: vec![],
            });
        }

        // Step 3: Port scan each host
        let ports_to_scan = build_port_list(&config.portlist, config.portstart, config.portend);

        let semaphore = Arc::new(Semaphore::new(200));
        for host in &mut hosts {
            host.open_ports = self.scan_ports(&host.ip, &ports_to_scan, &semaphore).await;
        }

        // Step 4: Upsert into knowledge base
        let alive_macs: HashSet<String> = hosts.iter().map(|h| h.mac.clone()).collect();
        for host in &hosts {
            let ports_str = format_ports(&host.open_ports);
            let hostname = if host.hostname.is_empty() {
                None
            } else {
                Some(host.hostname.as_str())
            };

            if let Err(e) = self
                .state
                .kb
                .upsert_host(&host.mac, &host.ip, hostname, true, &ports_str)
                .await
            {
                tracing::error!(ip = %host.ip, %e, "failed to upsert host");
            }
        }

        // Mark hosts not seen in this scan as dead
        if let Ok(all_hosts) = self.state.kb.all_hosts().await {
            for existing in &all_hosts {
                if !alive_macs.contains(&existing.mac_address) && existing.alive {
                    let _ = self.state.kb.mark_host_dead(&existing.mac_address).await;
                }
            }
        }

        // Update display stats
        if let Ok((alive, total, creds, vulns, attacks)) = self.state.kb.stats().await {
            let mut display = self.state.display.write().await;
            display.target_count = alive;
            display.network_kb_count = total;
            display.cred_count = creds;
            display.vuln_count = vulns;
            display.attack_count = attacks;
            display.update_stats();
        }

        tracing::info!(hosts = hosts.len(), "scan complete");
        hosts
    }

    /// Detect the local network CIDR via `ip route`.
    async fn detect_network(&self) -> Option<String> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .await
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let gateway_iface = parse_default_route_interface(&stdout)?;

        let addr_output = Command::new("ip")
            .args(["-4", "addr", "show", gateway_iface])
            .output()
            .await
            .ok()?;

        let addr_stdout = String::from_utf8_lossy(&addr_output.stdout);
        parse_ip_addr_to_cidr(&addr_stdout)
    }

    /// Discover live hosts using `nmap -sn`.
    async fn discover_hosts(&self, network: &str) -> Vec<(String, String)> {
        let output = Command::new("nmap").args(["-sn", network]).output().await;

        let output = match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let stderr = String::from_utf8_lossy(&o.stderr);
                tracing::debug!(
                    exit_code = ?o.status.code(),
                    stdout_len = stdout.len(),
                    "nmap -sn output"
                );
                if !stderr.is_empty() {
                    tracing::warn!(stderr = %stderr, "nmap stderr");
                }
                if !o.status.success() {
                    tracing::error!(exit_code = ?o.status.code(), "nmap -sn failed");
                    // Still try to parse — nmap sometimes returns non-zero but has results
                }
                o
            }
            Err(e) => {
                tracing::error!(%e, "failed to run nmap");
                return vec![];
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let results = parse_nmap_sn_output(&stdout);
        tracing::info!(hosts_found = results.len(), "nmap parse complete");
        results
    }

    /// Resolve MAC address for an IP using the ARP table.
    async fn resolve_mac(&self, ip: &str) -> String {
        // Read /proc/net/arp
        if let Ok(arp) = tokio::fs::read_to_string("/proc/net/arp").await {
            if let Some(mac) = parse_proc_arp_for_mac(&arp, ip) {
                return mac;
            }
        }

        // Fallback: use `ip neigh`
        if let Ok(output) = Command::new("ip")
            .args(["neigh", "show", ip])
            .output()
            .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(mac) = parse_ip_neigh_for_mac(&stdout) {
                return mac;
            }
        }

        // Last resort: use IP as identifier
        format!("{ip}_unknown")
    }

    /// Async TCP port scan — connect to each port with timeout.
    async fn scan_ports(&self, ip: &str, ports: &[u16], semaphore: &Arc<Semaphore>) -> Vec<u16> {
        let mut handles = Vec::with_capacity(ports.len());
        let ip = ip.to_string();

        for &port in ports {
            let ip = ip.clone();
            let sem = semaphore.clone();
            handles.push(tokio::spawn(async move {
                let Ok(_permit) = sem.acquire().await else {
                    return None;
                };
                let addr = format!("{ip}:{port}");
                match timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await {
                    Ok(Ok(_)) => Some(port),
                    _ => None,
                }
            }));
        }

        let mut open = Vec::new();
        for handle in handles {
            if let Ok(Some(port)) = handle.await {
                open.push(port);
            }
        }
        open.sort();
        open
    }
}

/// Parse the interface name from `ip route show default` output.
///
/// Expects lines like: `default via 192.168.1.1 dev wlan0 ...`
/// Returns the device name (e.g. "wlan0").
fn parse_default_route_interface(output: &str) -> Option<&str> {
    output
        .lines()
        .find(|l| l.starts_with("default"))?
        .split_whitespace()
        .nth(4)
}

/// Parse the gateway IP from `ip route show default` output.
///
/// Expects lines like: `default via 192.168.1.1 dev wlan0 ...`
/// Returns the gateway IP (e.g. "192.168.1.1").
fn parse_default_route_gateway(output: &str) -> Option<&str> {
    output
        .lines()
        .find(|l| l.starts_with("default"))?
        .split_whitespace()
        .nth(2)
}

/// Parse `ip -4 addr show <iface>` output to extract the network CIDR.
///
/// Looks for a line like `inet 192.168.1.100/24 ...` and computes
/// the network address (e.g. "192.168.1.0/24").
fn parse_ip_addr_to_cidr(output: &str) -> Option<String> {
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("inet ") {
            let cidr = line.split_whitespace().nth(1)?;
            let parts: Vec<&str> = cidr.split('/').collect();
            if parts.len() == 2 {
                let ip: Ipv4Addr = parts[0].parse().ok()?;
                let prefix: u32 = parts[1].parse().ok()?;
                let mask = if prefix == 0 {
                    0
                } else {
                    !((1u32 << (32 - prefix)) - 1)
                };
                let network_u32 = u32::from(ip) & mask;
                let network_ip = Ipv4Addr::from(network_u32);
                return Some(format!("{network_ip}/{prefix}"));
            }
        }
    }
    None
}

/// Parse `/proc/net/arp` content to find the MAC address for a given IP.
///
/// The ARP table format has columns: IP, HW type, Flags, HW address, Mask, Device.
/// Returns `None` if not found or MAC is all-zeros.
fn parse_proc_arp_for_mac<'a>(arp_content: &'a str, target_ip: &str) -> Option<String> {
    for line in arp_content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 && fields[0] == target_ip {
            let mac = fields[3].to_lowercase();
            if mac != "00:00:00:00:00:00" {
                return Some(mac);
            }
        }
    }
    None
}

/// Parse `ip neigh show <ip>` output to extract a MAC address.
///
/// Expects lines like: `192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`
fn parse_ip_neigh_for_mac(output: &str) -> Option<String> {
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = fields.iter().position(|&f| f == "lladdr") {
            if let Some(mac) = fields.get(pos + 1) {
                return Some(mac.to_lowercase());
            }
        }
    }
    None
}

/// Format a list of open ports into a semicolon-separated string.
fn format_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(";")
}

/// Build a deduplicated, sorted port list from an explicit list and a range.
fn build_port_list(explicit: &[u16], range_start: u16, range_end: u16) -> Vec<u16> {
    let mut seen = HashSet::new();
    let mut ports = Vec::new();
    for &p in explicit {
        if seen.insert(p) {
            ports.push(p);
        }
    }
    for p in range_start..=range_end {
        if seen.insert(p) {
            ports.push(p);
        }
    }
    ports
}

/// Parse `nmap -sn` output to extract IP addresses and hostnames.
fn parse_nmap_sn_output(output: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    let mut current_ip = None;
    let mut current_hostname = String::new();

    for line in output.lines() {
        if line.starts_with("Nmap scan report for ") {
            let rest = &line["Nmap scan report for ".len()..];
            // Format: "hostname (ip)" or just "ip"
            if let Some(paren_start) = rest.find('(') {
                current_hostname = rest[..paren_start].trim().to_string();
                current_ip = Some(rest[paren_start + 1..].trim_end_matches(')').to_string());
            } else {
                current_ip = Some(rest.trim().to_string());
                current_hostname = String::new();
            }
        } else if line.contains("Host is up") {
            if let Some(ip) = current_ip.take() {
                results.push((ip, current_hostname.clone()));
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── nmap parsing ────────────────────────────────────────────────

    #[test]
    fn parse_nmap_output() {
        let output = r#"Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-01 12:00 UTC
Nmap scan report for router.local (192.168.1.1)
Host is up (0.0020s latency).
Nmap scan report for 192.168.1.50
Host is up (0.0050s latency).
Nmap scan report for victim.local (192.168.1.100)
Host is up (0.010s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.50 seconds"#;

        let results = parse_nmap_sn_output(output);
        assert_eq!(results.len(), 3);
        assert_eq!(
            results[0],
            ("192.168.1.1".to_string(), "router.local".to_string())
        );
        assert_eq!(results[1], ("192.168.1.50".to_string(), String::new()));
        assert_eq!(
            results[2],
            ("192.168.1.100".to_string(), "victim.local".to_string())
        );
    }

    #[test]
    fn parse_nmap_empty_output() {
        let output = "Starting Nmap 7.93\nNmap done: 0 IP addresses scanned\n";
        let results = parse_nmap_sn_output(output);
        assert!(results.is_empty());
    }

    #[test]
    fn parse_nmap_host_down_not_included() {
        // Hosts without "Host is up" should not appear in results
        let output = "Nmap scan report for 10.0.0.1\n\
                       Nmap scan report for 10.0.0.2\n\
                       Host is up (0.001s latency).\n";
        let results = parse_nmap_sn_output(output);
        assert_eq!(results.len(), 1);
        // The second report (10.0.0.2) is the one with "Host is up"
        assert_eq!(results[0].0, "10.0.0.2");
    }

    #[test]
    fn parse_nmap_fqdn_hostname() {
        let output = "Nmap scan report for server.example.com (10.10.10.5)\n\
                       Host is up (0.003s latency).\n";
        let results = parse_nmap_sn_output(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "10.10.10.5");
        assert_eq!(results[0].1, "server.example.com");
    }

    #[test]
    fn parse_nmap_ipv6_style_ignored() {
        // Only IPv4-like entries with "Host is up" should be captured
        let output = "Nmap scan report for fe80::1\nHost is up.\n";
        let results = parse_nmap_sn_output(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "fe80::1");
        assert_eq!(results[0].1, "");
    }

    #[test]
    fn parse_nmap_multiple_same_host_only_first_up() {
        let output = "Nmap scan report for host-a (192.168.1.10)\n\
                       Host is up (0.001s latency).\n\
                       Nmap scan report for host-b (192.168.1.20)\n\
                       Host is up (0.002s latency).\n\
                       Nmap done: 256 IP addresses (2 hosts up)\n";
        let results = parse_nmap_sn_output(output);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], ("192.168.1.10".into(), "host-a".into()));
        assert_eq!(results[1], ("192.168.1.20".into(), "host-b".into()));
    }

    // ── ip route parsing ────────────────────────────────────────────

    #[test]
    fn parse_default_route_interface_typical() {
        let output = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n";
        assert_eq!(parse_default_route_interface(output), Some("wlan0"));
    }

    #[test]
    fn parse_default_route_interface_eth0() {
        let output = "default via 10.0.0.1 dev eth0 proto static\n\
                       10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.50\n";
        assert_eq!(parse_default_route_interface(output), Some("eth0"));
    }

    #[test]
    fn parse_default_route_interface_no_default() {
        let output = "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.50\n";
        assert_eq!(parse_default_route_interface(output), None);
    }

    #[test]
    fn parse_default_route_interface_empty() {
        assert_eq!(parse_default_route_interface(""), None);
    }

    #[test]
    fn parse_default_route_gateway_typical() {
        let output = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n";
        assert_eq!(parse_default_route_gateway(output), Some("192.168.1.1"));
    }

    #[test]
    fn parse_default_route_gateway_10_network() {
        let output = "default via 10.0.0.1 dev eth0\n";
        assert_eq!(parse_default_route_gateway(output), Some("10.0.0.1"));
    }

    #[test]
    fn parse_default_route_gateway_none() {
        let output = "172.16.0.0/16 dev docker0 scope link\n";
        assert_eq!(parse_default_route_gateway(output), None);
    }

    // ── ip addr → CIDR parsing ─────────────────────────────────────

    #[test]
    fn parse_ip_addr_to_cidr_slash24() {
        let output = "3: wlan0: <BROADCAST,MULTICAST,UP> mtu 1500\n\
                           inet 192.168.1.100/24 brd 192.168.1.255 scope global wlan0\n";
        assert_eq!(
            parse_ip_addr_to_cidr(output),
            Some("192.168.1.0/24".to_string())
        );
    }

    #[test]
    fn parse_ip_addr_to_cidr_slash16() {
        let output = "    inet 172.16.5.42/16 brd 172.16.255.255 scope global eth0\n";
        assert_eq!(
            parse_ip_addr_to_cidr(output),
            Some("172.16.0.0/16".to_string())
        );
    }

    #[test]
    fn parse_ip_addr_to_cidr_slash32() {
        let output = "    inet 10.0.0.1/32 scope global lo\n";
        assert_eq!(
            parse_ip_addr_to_cidr(output),
            Some("10.0.0.1/32".to_string())
        );
    }

    #[test]
    fn parse_ip_addr_to_cidr_slash8() {
        let output = "    inet 10.50.100.200/8 brd 10.255.255.255 scope global eth0\n";
        assert_eq!(
            parse_ip_addr_to_cidr(output),
            Some("10.0.0.0/8".to_string())
        );
    }

    #[test]
    fn parse_ip_addr_to_cidr_no_inet_line() {
        let output = "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n\
                           link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n";
        assert_eq!(parse_ip_addr_to_cidr(output), None);
    }

    #[test]
    fn parse_ip_addr_to_cidr_picks_first_inet() {
        let output = "    inet 192.168.1.10/24 brd 192.168.1.255 scope global\n\
                           inet 192.168.1.20/24 brd 192.168.1.255 scope global secondary\n";
        assert_eq!(
            parse_ip_addr_to_cidr(output),
            Some("192.168.1.0/24".to_string())
        );
    }

    #[test]
    fn parse_ip_addr_to_cidr_ignores_inet6() {
        let output = "    inet6 fe80::1/64 scope link\n";
        assert_eq!(parse_ip_addr_to_cidr(output), None);
    }

    // ── /proc/net/arp parsing ───────────────────────────────────────

    #[test]
    fn parse_proc_arp_found() {
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.1      0x1         0x2         AA:BB:CC:DD:EE:FF     *        wlan0\n\
                    192.168.1.50     0x1         0x2         11:22:33:44:55:66     *        wlan0\n";
        assert_eq!(
            parse_proc_arp_for_mac(arp, "192.168.1.50"),
            Some("11:22:33:44:55:66".to_string())
        );
    }

    #[test]
    fn parse_proc_arp_lowercases_mac() {
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    10.0.0.1         0x1         0x2         AA:BB:CC:DD:EE:FF     *        eth0\n";
        assert_eq!(
            parse_proc_arp_for_mac(arp, "10.0.0.1"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn parse_proc_arp_not_found() {
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.1      0x1         0x2         AA:BB:CC:DD:EE:FF     *        wlan0\n";
        assert_eq!(parse_proc_arp_for_mac(arp, "192.168.1.99"), None);
    }

    #[test]
    fn parse_proc_arp_skips_zero_mac() {
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.5      0x1         0x0         00:00:00:00:00:00     *        wlan0\n";
        assert_eq!(parse_proc_arp_for_mac(arp, "192.168.1.5"), None);
    }

    #[test]
    fn parse_proc_arp_empty() {
        let arp =
            "IP address       HW type     Flags       HW address            Mask     Device\n";
        assert_eq!(parse_proc_arp_for_mac(arp, "1.2.3.4"), None);
    }

    #[test]
    fn parse_proc_arp_multiple_matches_returns_first() {
        // Shouldn't normally happen, but test that we get the first match
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    10.0.0.1         0x1         0x2         AA:AA:AA:AA:AA:AA     *        eth0\n\
                    10.0.0.1         0x1         0x2         BB:BB:BB:BB:BB:BB     *        eth1\n";
        assert_eq!(
            parse_proc_arp_for_mac(arp, "10.0.0.1"),
            Some("aa:aa:aa:aa:aa:aa".to_string())
        );
    }

    // ── ip neigh parsing ────────────────────────────────────────────

    #[test]
    fn parse_ip_neigh_reachable() {
        let output = "192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n";
        assert_eq!(
            parse_ip_neigh_for_mac(output),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn parse_ip_neigh_stale() {
        let output = "10.0.0.1 dev eth0 lladdr 11:22:33:44:55:66 STALE\n";
        assert_eq!(
            parse_ip_neigh_for_mac(output),
            Some("11:22:33:44:55:66".to_string())
        );
    }

    #[test]
    fn parse_ip_neigh_lowercases() {
        let output = "10.0.0.1 dev eth0 lladdr AA:BB:CC:DD:EE:FF REACHABLE\n";
        assert_eq!(
            parse_ip_neigh_for_mac(output),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn parse_ip_neigh_no_lladdr() {
        let output = "192.168.1.1 dev wlan0 FAILED\n";
        assert_eq!(parse_ip_neigh_for_mac(output), None);
    }

    #[test]
    fn parse_ip_neigh_empty() {
        assert_eq!(parse_ip_neigh_for_mac(""), None);
    }

    #[test]
    fn parse_ip_neigh_multiple_lines_picks_first() {
        let output = "192.168.1.1 dev wlan0 lladdr aa:aa:aa:aa:aa:aa REACHABLE\n\
                       192.168.1.2 dev wlan0 lladdr bb:bb:bb:bb:bb:bb STALE\n";
        assert_eq!(
            parse_ip_neigh_for_mac(output),
            Some("aa:aa:aa:aa:aa:aa".to_string())
        );
    }

    #[test]
    fn parse_ip_neigh_lladdr_at_end_without_state() {
        // Edge case: lladdr is last token (no state field)
        let output = "10.0.0.1 dev eth0 lladdr cc:dd:ee:ff:00:11\n";
        assert_eq!(
            parse_ip_neigh_for_mac(output),
            Some("cc:dd:ee:ff:00:11".to_string())
        );
    }

    // ── port formatting ─────────────────────────────────────────────

    #[test]
    fn format_ports_typical() {
        assert_eq!(format_ports(&[22, 80, 443]), "22;80;443");
    }

    #[test]
    fn format_ports_single() {
        assert_eq!(format_ports(&[8080]), "8080");
    }

    #[test]
    fn format_ports_empty() {
        assert_eq!(format_ports(&[]), "");
    }

    // ── port list building ──────────────────────────────────────────

    #[test]
    fn build_port_list_no_overlap() {
        let result = build_port_list(&[22, 80], 443, 445);
        assert_eq!(result, vec![22, 80, 443, 444, 445]);
    }

    #[test]
    fn build_port_list_with_overlap() {
        let result = build_port_list(&[22, 80, 443], 80, 82);
        // 80 is in explicit list, so range starts adding from 81
        assert_eq!(result, vec![22, 80, 443, 81, 82]);
    }

    #[test]
    fn build_port_list_empty_explicit() {
        let result = build_port_list(&[], 8000, 8002);
        assert_eq!(result, vec![8000, 8001, 8002]);
    }

    #[test]
    fn build_port_list_single_range() {
        let result = build_port_list(&[22], 22, 22);
        // 22 already in explicit, range adds nothing new
        assert_eq!(result, vec![22]);
    }

    #[test]
    fn build_port_list_deduplicates_explicit() {
        let result = build_port_list(&[22, 80, 22, 80], 443, 443);
        assert_eq!(result, vec![22, 80, 443]);
    }
}
