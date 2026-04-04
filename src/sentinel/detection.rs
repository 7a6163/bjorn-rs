use std::collections::{HashMap, HashSet};

use super::{Alert, Severity};
use chrono::Utc;

/// Lightweight snapshot of a host, used as input to pure detection functions.
/// Decoupled from the database `Host` struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSnapshot {
    pub mac_address: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub alive: bool,
    /// Semicolon-separated port list, e.g. "22;80;443"
    pub ports: String,
}

/// Snapshot of the sentinel baseline state, extracted for testability.
#[derive(Debug, Clone)]
pub struct BaselineState {
    pub known_macs: HashSet<String>,
    pub alive_macs: HashSet<String>,
    pub port_snapshot: HashMap<String, String>,
    pub arp_cache: HashMap<String, String>,
}

impl BaselineState {
    pub fn new() -> Self {
        Self {
            known_macs: HashSet::new(),
            alive_macs: HashSet::new(),
            port_snapshot: HashMap::new(),
            arp_cache: HashMap::new(),
        }
    }

    /// Build a baseline from a set of host snapshots.
    pub fn from_snapshots(hosts: &[HostSnapshot]) -> Self {
        let mut state = Self::new();
        for host in hosts {
            state.known_macs.insert(host.mac_address.clone());
            if host.alive {
                state.alive_macs.insert(host.mac_address.clone());
            }
            state
                .port_snapshot
                .insert(host.mac_address.clone(), host.ports.clone());
            state
                .arp_cache
                .insert(host.ip.clone(), host.mac_address.clone());
        }
        state
    }

    /// Update baseline to reflect the current scan results.
    pub fn update(&self, current: &[HostSnapshot]) -> Self {
        let mut new_state = Self::new();
        for host in current {
            new_state.known_macs.insert(host.mac_address.clone());
            if host.alive {
                new_state.alive_macs.insert(host.mac_address.clone());
            }
            new_state
                .port_snapshot
                .insert(host.mac_address.clone(), host.ports.clone());
            new_state
                .arp_cache
                .insert(host.ip.clone(), host.mac_address.clone());
        }
        new_state
    }
}

fn make_alert(
    severity: Severity,
    category: &str,
    message: &str,
    details: serde_json::Value,
) -> Alert {
    Alert {
        severity,
        category: category.to_string(),
        message: message.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        details,
    }
}

/// Detect hosts whose MAC address was not in the baseline.
pub fn detect_new_hosts(baseline: &BaselineState, current: &[HostSnapshot]) -> Vec<Alert> {
    current
        .iter()
        .filter(|h| !baseline.known_macs.contains(&h.mac_address))
        .map(|h| {
            make_alert(
                Severity::Warning,
                "new_device",
                &format!(
                    "New device detected: {} ({}) MAC: {}",
                    h.ip,
                    h.hostname.as_deref().unwrap_or("unknown"),
                    h.mac_address
                ),
                serde_json::json!({
                    "ip": h.ip,
                    "mac": h.mac_address,
                    "hostname": h.hostname,
                }),
            )
        })
        .collect()
}

/// Detect hosts that were alive in the baseline but are no longer alive.
pub fn detect_dead_hosts(baseline: &BaselineState, current: &[HostSnapshot]) -> Vec<Alert> {
    let current_alive: HashSet<&str> = current
        .iter()
        .filter(|h| h.alive)
        .map(|h| h.mac_address.as_str())
        .collect();

    baseline
        .alive_macs
        .iter()
        .filter(|mac| !current_alive.contains(mac.as_str()))
        .map(|mac| {
            make_alert(
                Severity::Info,
                "device_left",
                &format!("Device went offline: {mac}"),
                serde_json::json!({"mac": mac}),
            )
        })
        .collect()
}

/// Detect hosts that were known but offline and have come back.
pub fn detect_returned_hosts(baseline: &BaselineState, current: &[HostSnapshot]) -> Vec<Alert> {
    current
        .iter()
        .filter(|h| {
            h.alive
                && !baseline.alive_macs.contains(&h.mac_address)
                && baseline.known_macs.contains(&h.mac_address)
        })
        .map(|h| {
            make_alert(
                Severity::Info,
                "device_returned",
                &format!("Device came back online: {}", h.mac_address),
                serde_json::json!({"mac": h.mac_address}),
            )
        })
        .collect()
}

/// Detect port changes on existing hosts by comparing against baseline port snapshots.
pub fn detect_port_changes(baseline: &BaselineState, current: &[HostSnapshot]) -> Vec<Alert> {
    let mut alerts = Vec::new();

    for host in current {
        let old_ports = match baseline.port_snapshot.get(&host.mac_address) {
            Some(p) => p,
            None => continue,
        };

        if *old_ports == host.ports || host.ports.is_empty() {
            continue;
        }

        let old_set: HashSet<&str> = old_ports.split(';').collect();
        let new_set: HashSet<&str> = host.ports.split(';').collect();
        let opened: Vec<&str> = new_set.difference(&old_set).copied().collect();
        let closed: Vec<&str> = old_set.difference(&new_set).copied().collect();

        if !opened.is_empty() || !closed.is_empty() {
            alerts.push(make_alert(
                Severity::Info,
                "port_change",
                &format!(
                    "Port change on {} ({}): opened={:?} closed={:?}",
                    host.ip, host.mac_address, opened, closed
                ),
                serde_json::json!({
                    "ip": host.ip,
                    "mac": host.mac_address,
                    "opened": opened,
                    "closed": closed,
                }),
            ));
        }
    }

    alerts
}

/// Detect ARP spoofing: an IP address that now maps to a different MAC than baseline.
pub fn detect_arp_spoofing(baseline: &BaselineState, current: &[HostSnapshot]) -> Vec<Alert> {
    current
        .iter()
        .filter(|h| {
            h.alive
                && baseline
                    .arp_cache
                    .get(&h.ip)
                    .is_some_and(|known_mac| *known_mac != h.mac_address)
        })
        .map(|h| {
            let known_mac = &baseline.arp_cache[&h.ip];
            make_alert(
                Severity::Critical,
                "arp_spoof",
                &format!(
                    "Possible ARP spoofing! IP {} changed from MAC {} to {}",
                    h.ip, known_mac, h.mac_address
                ),
                serde_json::json!({
                    "ip": h.ip,
                    "old_mac": known_mac,
                    "new_mac": h.mac_address,
                }),
            )
        })
        .collect()
}

/// Run all detection checks and return the combined alerts.
pub fn run_all_checks(baseline: &BaselineState, current: &[HostSnapshot]) -> Vec<Alert> {
    let mut alerts = Vec::new();
    alerts.extend(detect_new_hosts(baseline, current));
    alerts.extend(detect_port_changes(baseline, current));
    alerts.extend(detect_arp_spoofing(baseline, current));
    alerts.extend(detect_dead_hosts(baseline, current));
    alerts.extend(detect_returned_hosts(baseline, current));
    alerts
}
