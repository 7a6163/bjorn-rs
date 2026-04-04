pub mod scheduling;

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::Semaphore;
use tokio::time::sleep;

use crate::actions::scanning::NetworkScanner;
use crate::actions::vuln_scanner::VulnScanner;
use crate::actions::{Action, ActionOutcome, Target, build_action_registry};
use crate::state::AppState;

use scheduling::{RetryConfig, parent_succeeded, parse_ports, should_retry_action};

#[cfg(test)]
mod tests;

/// The Orchestrator is Bjorn's brain — it coordinates scanning, vulnerability
/// assessment, brute-force attacks, and data exfiltration in a continuous loop.
///
/// Replaces Python's `orchestrator.py`.
pub struct Orchestrator {
    state: Arc<AppState>,
    scanner: NetworkScanner,
    vuln_scanner: VulnScanner,
    actions: Vec<Box<dyn Action>>,
    semaphore: Arc<Semaphore>,
}

impl Orchestrator {
    pub fn new(state: Arc<AppState>) -> Self {
        let scanner = NetworkScanner::new(Arc::clone(&state));
        let vuln_scanner = VulnScanner::new(Arc::clone(&state));
        let actions = build_action_registry(&state);
        let semaphore = Arc::new(Semaphore::new(10));

        tracing::info!(actions = actions.len(), "orchestrator initialized");

        Self {
            state,
            scanner,
            vuln_scanner,
            actions,
            semaphore,
        }
    }

    /// Main orchestrator loop. Runs until shutdown is signalled.
    pub async fn run(&self) {
        // Initial scan
        self.update_status("NetworkScanner", "first scan...").await;
        self.scanner.scan().await;
        self.update_status("IDLE", "").await;

        loop {
            if self.should_exit().await {
                break;
            }

            // Check if in manual mode
            if self.is_manual_mode().await {
                self.idle_wait(Duration::from_secs(5)).await;
                continue;
            }

            // Process alive hosts with registered actions
            let any_executed = self.process_actions().await;

            if !any_executed {
                // No actions executed — run a new network scan
                self.update_status("NetworkScanner", "scanning...").await;
                self.scanner.scan().await;

                // Try actions again after fresh scan
                let _ = self.process_actions().await;

                // Run vulnerability scans if enabled
                self.maybe_run_vuln_scans().await;

                // Idle wait before next cycle
                let config = self.state.config();
                self.update_status("IDLE", "").await;
                self.idle_wait(Duration::from_secs(config.scan_interval))
                    .await;
            }
        }

        tracing::info!("orchestrator stopped");
    }

    /// Process all alive hosts with registered actions.
    /// Returns true if any action was successfully executed.
    async fn process_actions(&self) -> bool {
        let hosts = match self.state.kb.alive_hosts().await {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(%e, "failed to read alive hosts");
                return false;
            }
        };

        if hosts.is_empty() {
            return false;
        }

        let mut any_executed = false;

        // First pass: parent actions (no parent dependency)
        for action in &self.actions {
            if action.parent().is_some() {
                continue;
            }

            for host in &hosts {
                let ports = parse_ports(&host.ports);

                // Check port match
                if let Some(action_port) = action.port() {
                    if !ports.contains(&action_port) {
                        continue;
                    }
                }

                // Check retry delay
                if !self.should_run_action(host.id, action.name()).await {
                    continue;
                }

                let target = Target {
                    host_id: host.id,
                    ip: host.ip.clone(),
                    mac_address: host.mac_address.clone(),
                    hostname: host.hostname.clone(),
                    ports: ports.clone(),
                };

                // Execute with semaphore
                let _permit = self.semaphore.acquire().await.expect("semaphore closed");
                self.update_status(action.name(), &host.ip).await;
                let outcome = action.execute(&target, &self.state).await;
                let status_str = match &outcome {
                    ActionOutcome::Success => "success",
                    ActionOutcome::Failed(_) => "failed",
                };

                let _ = self
                    .state
                    .kb
                    .record_action(host.id, action.name(), status_str)
                    .await;

                if outcome.is_success() {
                    any_executed = true;

                    // Run child actions
                    for child in &self.actions {
                        if child.parent() == Some(action.name()) {
                            if !self.should_run_action(host.id, child.name()).await {
                                continue;
                            }
                            let _permit = self.semaphore.acquire().await.expect("semaphore closed");
                            self.update_status(child.name(), &host.ip).await;
                            let child_outcome = child.execute(&target, &self.state).await;
                            let child_status = match &child_outcome {
                                ActionOutcome::Success => "success",
                                ActionOutcome::Failed(_) => "failed",
                            };
                            let _ = self
                                .state
                                .kb
                                .record_action(host.id, child.name(), child_status)
                                .await;
                        }
                    }
                    break; // Move to next action after first success
                }
            }
        }

        // Second pass: child actions that may still have pending work
        for action in &self.actions {
            if action.parent().is_none() {
                continue;
            }

            for host in &hosts {
                let ports = parse_ports(&host.ports);

                if let Some(action_port) = action.port() {
                    if !ports.contains(&action_port) {
                        continue;
                    }
                }

                // Check parent succeeded
                let parent_name = action.parent().unwrap();
                if !self.has_parent_succeeded(host.id, parent_name).await {
                    continue;
                }

                if !self.should_run_action(host.id, action.name()).await {
                    continue;
                }

                let target = Target {
                    host_id: host.id,
                    ip: host.ip.clone(),
                    mac_address: host.mac_address.clone(),
                    hostname: host.hostname.clone(),
                    ports,
                };

                let _permit = self.semaphore.acquire().await.expect("semaphore closed");
                self.update_status(action.name(), &host.ip).await;
                let outcome = action.execute(&target, &self.state).await;
                let status_str = match &outcome {
                    ActionOutcome::Success => "success",
                    ActionOutcome::Failed(_) => "failed",
                };
                let _ = self
                    .state
                    .kb
                    .record_action(host.id, action.name(), status_str)
                    .await;

                if outcome.is_success() {
                    any_executed = true;
                    break;
                }
            }
        }

        any_executed
    }

    /// Check whether an action should be run based on retry delays.
    async fn should_run_action(&self, host_id: i64, action_name: &str) -> bool {
        let bjorn_config = self.state.config();
        let latest = match self
            .state
            .kb
            .latest_action_result(host_id, action_name)
            .await
        {
            Ok(r) => r,
            Err(_) => return true,
        };

        let retry_config = RetryConfig {
            retry_success_actions: bjorn_config.retry_success_actions,
            success_retry_delay: bjorn_config.success_retry_delay,
            retry_failed_actions: bjorn_config.retry_failed_actions,
            failed_retry_delay: bjorn_config.failed_retry_delay,
        };

        should_retry_action(latest.as_ref(), Utc::now().naive_utc(), &retry_config)
    }

    /// Check if a parent action has succeeded for a given host.
    async fn has_parent_succeeded(&self, host_id: i64, parent_name: &str) -> bool {
        let result = match self
            .state
            .kb
            .latest_action_result(host_id, parent_name)
            .await
        {
            Ok(r) => r,
            Err(_) => return false,
        };
        parent_succeeded(result.as_ref())
    }

    /// Run vulnerability scans on alive hosts if enabled and interval has elapsed.
    async fn maybe_run_vuln_scans(&self) {
        let config = self.state.config();
        if !config.scan_vuln_running {
            return;
        }

        let hosts = match self.state.kb.alive_hosts().await {
            Ok(h) => h,
            Err(_) => return,
        };

        for host in &hosts {
            if !self.should_run_action(host.id, "NmapVulnScanner").await {
                continue;
            }

            let ports = parse_ports(&host.ports);

            let _permit = self.semaphore.acquire().await.expect("semaphore closed");
            let success = self.vuln_scanner.scan_host(host.id, &host.ip, &ports).await;
            let status = if success { "success" } else { "failed" };
            let _ = self
                .state
                .kb
                .record_action(host.id, "NmapVulnScanner", status)
                .await;
        }
    }

    /// Wait for a duration, but exit early if shutdown is signalled.
    async fn idle_wait(&self, duration: Duration) {
        tokio::select! {
            () = sleep(duration) => {}
            () = self.state.shutdown.cancelled() => {}
        }
    }

    async fn should_exit(&self) -> bool {
        if self.state.shutdown.is_cancelled() {
            return true;
        }
        let status = self.state.status.read().await;
        status.should_exit
    }

    async fn is_manual_mode(&self) -> bool {
        let status = self.state.status.read().await;
        status.manual_mode
    }

    async fn update_status(&self, action: &str, detail: &str) {
        let mut status = self.state.status.write().await;
        status.current_action = action.to_string();
        status.detail = detail.to_string();
    }
}
