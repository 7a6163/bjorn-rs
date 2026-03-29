use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
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
        let mac_blacklist: HashSet<&str> = config.mac_scan_blacklist.iter().map(|s| s.as_str()).collect();
        let ip_blacklist: HashSet<&str> = config.ip_scan_blacklist.iter().map(|s| s.as_str()).collect();

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
        let ports_to_scan: Vec<u16> = {
            let mut ports: Vec<u16> = config.portlist.clone();
            // Add range ports
            for p in config.portstart..=config.portend {
                if !ports.contains(&p) {
                    ports.push(p);
                }
            }
            ports
        };

        let semaphore = Arc::new(Semaphore::new(200));
        for host in &mut hosts {
            host.open_ports = self
                .scan_ports(&host.ip, &ports_to_scan, &semaphore)
                .await;
        }

        // Step 4: Upsert into knowledge base
        let alive_macs: HashSet<String> = hosts.iter().map(|h| h.mac.clone()).collect();
        for host in &hosts {
            let ports_str = host
                .open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(";");
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
        // Try `ip route` first
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .await
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse: "default via 192.168.1.1 dev wlan0 ..."
        let gateway_iface = stdout
            .lines()
            .find(|l| l.starts_with("default"))?
            .split_whitespace()
            .nth(4)?; // device name (e.g. "wlan0")

        // Get network from device
        let addr_output = Command::new("ip")
            .args(["-4", "addr", "show", gateway_iface])
            .output()
            .await
            .ok()?;

        let addr_stdout = String::from_utf8_lossy(&addr_output.stdout);
        // Parse: "    inet 192.168.1.100/24 ..."
        for line in addr_stdout.lines() {
            let line = line.trim();
            if line.starts_with("inet ") {
                let cidr = line.split_whitespace().nth(1)?;
                // Convert host address to network address
                let parts: Vec<&str> = cidr.split('/').collect();
                if parts.len() == 2 {
                    let ip: Ipv4Addr = parts[0].parse().ok()?;
                    let prefix: u32 = parts[1].parse().ok()?;
                    let mask = !((1u32 << (32 - prefix)) - 1);
                    let network_u32 = u32::from(ip) & mask;
                    let network_ip = Ipv4Addr::from(network_u32);
                    return Some(format!("{network_ip}/{prefix}"));
                }
            }
        }
        None
    }

    /// Discover live hosts using `nmap -sn`.
    async fn discover_hosts(&self, network: &str) -> Vec<(String, String)> {
        let output = Command::new("nmap")
            .args(["-sn", network])
            .output()
            .await;

        let output = match output {
            Ok(o) if o.status.success() => o,
            Ok(o) => {
                tracing::error!(
                    stderr = %String::from_utf8_lossy(&o.stderr),
                    "nmap -sn failed"
                );
                return vec![];
            }
            Err(e) => {
                tracing::error!(%e, "failed to run nmap");
                return vec![];
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_nmap_sn_output(&stdout)
    }

    /// Resolve MAC address for an IP using the ARP table.
    async fn resolve_mac(&self, ip: &str) -> String {
        // Read /proc/net/arp
        if let Ok(arp) = tokio::fs::read_to_string("/proc/net/arp").await {
            for line in arp.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 4 && fields[0] == ip {
                    let mac = fields[3].to_lowercase();
                    if mac != "00:00:00:00:00:00" {
                        return mac;
                    }
                }
            }
        }

        // Fallback: use `ip neigh`
        if let Ok(output) = Command::new("ip")
            .args(["neigh", "show", ip])
            .output()
            .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                // "192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
                if let Some(pos) = fields.iter().position(|&f| f == "lladdr") {
                    if let Some(mac) = fields.get(pos + 1) {
                        return mac.to_lowercase();
                    }
                }
            }
        }

        // Last resort: use IP as identifier
        format!("{ip}_unknown")
    }

    /// Async TCP port scan — connect to each port with timeout.
    async fn scan_ports(
        &self,
        ip: &str,
        ports: &[u16],
        semaphore: &Arc<Semaphore>,
    ) -> Vec<u16> {
        let mut handles = Vec::with_capacity(ports.len());
        let ip = ip.to_string();

        for &port in ports {
            let ip = ip.clone();
            let sem = semaphore.clone();
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
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
                current_ip = Some(
                    rest[paren_start + 1..]
                        .trim_end_matches(')')
                        .to_string(),
                );
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
        assert_eq!(results[0], ("192.168.1.1".to_string(), "router.local".to_string()));
        assert_eq!(results[1], ("192.168.1.50".to_string(), String::new()));
        assert_eq!(results[2], ("192.168.1.100".to_string(), "victim.local".to_string()));
    }
}
