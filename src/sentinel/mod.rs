use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::Serialize;
use tokio::time::sleep;

use crate::state::AppState;

/// Severity levels for sentinel alerts.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// A network alert detected by Sentinel.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub severity: Severity,
    pub category: String,
    pub message: String,
    pub timestamp: String,
    pub details: serde_json::Value,
}

/// Network watchdog that detects anomalies by monitoring the knowledge base.
///
/// Ports Python's `sentinel.py`. Zero extra network traffic —
/// all checks read from the existing SQLite KB.
pub struct SentinelEngine {
    state: Arc<AppState>,
    known_macs: HashSet<String>,
    alive_macs: HashSet<String>,
    port_snapshot: HashMap<String, String>,
    arp_cache: HashMap<String, String>,
    alerts: Vec<Alert>,
}

impl SentinelEngine {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            known_macs: HashSet::new(),
            alive_macs: HashSet::new(),
            port_snapshot: HashMap::new(),
            arp_cache: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    /// Main sentinel loop. Runs until shutdown.
    pub async fn run(&mut self) {
        let config = self.state.config();
        if !config.sentinel_enabled {
            tracing::info!("sentinel disabled in config");
            return;
        }

        tracing::info!("sentinel watchdog starting");

        // Initialize baseline from current KB state
        self.snapshot_baseline().await;

        loop {
            if self.state.shutdown.is_cancelled() {
                break;
            }

            let interval = self.state.config().sentinel_interval;
            tokio::select! {
                () = sleep(Duration::from_secs(interval)) => {}
                () = self.state.shutdown.cancelled() => break,
            }

            self.check_cycle().await;
        }

        tracing::info!("sentinel stopped");
    }

    /// Take a snapshot of the current state as baseline.
    async fn snapshot_baseline(&mut self) {
        if let Ok(hosts) = self.state.kb.all_hosts().await {
            for host in &hosts {
                self.known_macs.insert(host.mac_address.clone());
                if host.alive {
                    self.alive_macs.insert(host.mac_address.clone());
                }
                self.port_snapshot
                    .insert(host.mac_address.clone(), host.ports.clone());
                self.arp_cache
                    .insert(host.ip.clone(), host.mac_address.clone());
            }
            tracing::info!(
                known = self.known_macs.len(),
                alive = self.alive_macs.len(),
                "sentinel baseline captured"
            );
        }
    }

    /// Run one check cycle — compare current state against baseline.
    async fn check_cycle(&mut self) {
        let hosts = match self.state.kb.all_hosts().await {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(%e, "sentinel: failed to read hosts");
                return;
            }
        };

        let mut current_macs = HashSet::new();
        let mut current_alive = HashSet::new();

        for host in &hosts {
            current_macs.insert(host.mac_address.clone());
            if host.alive {
                current_alive.insert(host.mac_address.clone());
            }

            // Check 1: New device detected
            if !self.known_macs.contains(&host.mac_address) {
                self.emit_alert(
                    Severity::Warning,
                    "new_device",
                    &format!(
                        "New device detected: {} ({}) MAC: {}",
                        host.ip,
                        host.hostname.as_deref().unwrap_or("unknown"),
                        host.mac_address
                    ),
                    serde_json::json!({
                        "ip": host.ip,
                        "mac": host.mac_address,
                        "hostname": host.hostname,
                    }),
                );
            }

            // Check 2: Port changes
            if let Some(old_ports) = self.port_snapshot.get(&host.mac_address) {
                if *old_ports != host.ports && !host.ports.is_empty() {
                    let old_set: HashSet<&str> = old_ports.split(';').collect();
                    let new_set: HashSet<&str> = host.ports.split(';').collect();
                    let opened: Vec<&&str> = new_set.difference(&old_set).collect();
                    let closed: Vec<&&str> = old_set.difference(&new_set).collect();

                    if !opened.is_empty() || !closed.is_empty() {
                        self.emit_alert(
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
                        );
                    }
                }
            }

            // Check 3: ARP spoofing detection (IP mapped to different MAC)
            if let Some(known_mac) = self.arp_cache.get(&host.ip) {
                if *known_mac != host.mac_address && host.alive {
                    self.emit_alert(
                        Severity::Critical,
                        "arp_spoof",
                        &format!(
                            "Possible ARP spoofing! IP {} changed from MAC {} to {}",
                            host.ip, known_mac, host.mac_address
                        ),
                        serde_json::json!({
                            "ip": host.ip,
                            "old_mac": known_mac,
                            "new_mac": host.mac_address,
                        }),
                    );
                }
            }
        }

        // Check 4: Device disappeared — collect first to avoid borrow conflict
        let departed: Vec<String> = self
            .alive_macs
            .iter()
            .filter(|mac| !current_alive.contains(*mac))
            .cloned()
            .collect();
        for mac in &departed {
            self.emit_alert(
                Severity::Info,
                "device_left",
                &format!("Device went offline: {mac}"),
                serde_json::json!({"mac": mac}),
            );
        }

        // Check 5: Device came back
        let returned: Vec<String> = current_alive
            .iter()
            .filter(|mac| !self.alive_macs.contains(*mac) && self.known_macs.contains(*mac))
            .cloned()
            .collect();
        for mac in &returned {
            self.emit_alert(
                Severity::Info,
                "device_returned",
                &format!("Device came back online: {mac}"),
                serde_json::json!({"mac": mac}),
            );
        }

        // Update snapshots
        self.known_macs = current_macs;
        self.alive_macs = current_alive;
        for host in &hosts {
            self.port_snapshot
                .insert(host.mac_address.clone(), host.ports.clone());
            self.arp_cache
                .insert(host.ip.clone(), host.mac_address.clone());
        }
    }

    fn emit_alert(
        &mut self,
        severity: Severity,
        category: &str,
        message: &str,
        details: serde_json::Value,
    ) {
        let alert = Alert {
            severity: severity.clone(),
            category: category.to_string(),
            message: message.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            details,
        };

        match severity {
            Severity::Critical => tracing::error!(category = %category, "{message}"),
            Severity::Warning => tracing::warn!(category = %category, "{message}"),
            Severity::Info => tracing::info!(category = %category, "{message}"),
        }

        self.alerts.push(alert);

        // Keep only last 500 alerts
        if self.alerts.len() > 500 {
            self.alerts.drain(..self.alerts.len() - 500);
        }
    }

    /// Get all alerts (for API/web UI).
    pub fn alerts(&self) -> &[Alert] {
        &self.alerts
    }

    /// Get alerts since a given index.
    pub fn alerts_since(&self, index: usize) -> &[Alert] {
        if index < self.alerts.len() {
            &self.alerts[index..]
        } else {
            &[]
        }
    }
}
