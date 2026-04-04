pub mod detection;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::time::sleep;

use crate::state::AppState;
use detection::{BaselineState, HostSnapshot, run_all_checks};

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

/// Maximum number of alerts to retain.
const MAX_ALERTS: usize = 500;

/// Network watchdog that detects anomalies by monitoring the knowledge base.
///
/// Ports Python's `sentinel.py`. Zero extra network traffic —
/// all checks read from the existing SQLite KB.
pub struct SentinelEngine {
    state: Arc<AppState>,
    baseline: BaselineState,
    alerts: Vec<Alert>,
}

impl SentinelEngine {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            baseline: BaselineState::new(),
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
            let snapshots = hosts_to_snapshots(&hosts);
            self.baseline = BaselineState::from_snapshots(&snapshots);
            tracing::info!(
                known = self.baseline.known_macs.len(),
                alive = self.baseline.alive_macs.len(),
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

        let current = hosts_to_snapshots(&hosts);
        let new_alerts = run_all_checks(&self.baseline, &current);

        for alert in &new_alerts {
            match alert.severity {
                Severity::Critical => {
                    tracing::error!(category = %alert.category, "{}", alert.message)
                }
                Severity::Warning => {
                    tracing::warn!(category = %alert.category, "{}", alert.message)
                }
                Severity::Info => tracing::info!(category = %alert.category, "{}", alert.message),
            }
        }

        self.alerts.extend(new_alerts);
        trim_alerts(&mut self.alerts, MAX_ALERTS);

        // Update baseline to current state
        self.baseline = self.baseline.update(&current);
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

/// Convert KB hosts to lightweight snapshots for the detection layer.
fn hosts_to_snapshots(hosts: &[crate::state::Host]) -> Vec<HostSnapshot> {
    hosts
        .iter()
        .map(|h| HostSnapshot {
            mac_address: h.mac_address.clone(),
            ip: h.ip.clone(),
            hostname: h.hostname.clone(),
            alive: h.alive,
            ports: h.ports.clone(),
        })
        .collect()
}

/// Trim alerts to keep only the last `max` entries.
fn trim_alerts(alerts: &mut Vec<Alert>, max: usize) {
    if alerts.len() > max {
        let drain_count = alerts.len() - max;
        alerts.drain(..drain_count);
    }
}
