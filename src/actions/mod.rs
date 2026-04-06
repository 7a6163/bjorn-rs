pub mod brute_force;
pub mod exfiltrate;
pub mod scanning;
pub mod vuln_scanner;

use std::sync::Arc;

use crate::state::AppState;

/// Target information passed to actions.
#[derive(Debug, Clone)]
pub struct Target {
    pub host_id: i64,
    pub ip: String,
    pub mac_address: String,
    pub hostname: Option<String>,
    pub ports: Vec<u16>,
}

/// Result of an action execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionOutcome {
    Success,
    Failed(String),
}

impl ActionOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

/// The core trait that all actions implement.
///
/// Replaces Python's dynamic `importlib` loading with compile-time dispatch.
pub trait Action: Send + Sync {
    /// Unique name (e.g. "SshConnector", "StealFilesSsh").
    fn name(&self) -> &'static str;

    /// Port this action targets. `None` for scanners/standalone.
    fn port(&self) -> Option<u16>;

    /// Parent action that must succeed before this one runs.
    fn parent(&self) -> Option<&'static str>;

    /// Execute the action against a target.
    fn execute<'a>(
        &'a self,
        target: &'a Target,
        state: &'a Arc<AppState>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ActionOutcome> + Send + 'a>>;
}

/// Metadata for registry listing (does not require the full Action impl).
#[derive(Debug, Clone)]
pub struct ActionMeta {
    pub name: &'static str,
    pub port: Option<u16>,
    pub parent: Option<&'static str>,
}

/// Build the complete list of registered actions.
///
/// This is the static equivalent of Python's `generate_actions_json()` +
/// `orchestrator.load_actions()`. New actions are added here.
pub fn build_action_registry(_state: &Arc<AppState>) -> Vec<Box<dyn Action>> {
    vec![
        // Brute-force connectors (parent actions)
        Box::new(brute_force::ssh::create_action()),
        Box::new(brute_force::ftp::create_action()),
        Box::new(brute_force::telnet::create_action()),
        Box::new(brute_force::sql::create_action()),
        Box::new(brute_force::smb::create_action()),
        Box::new(brute_force::rdp::create_action()),
        Box::new(brute_force::postgres::create_action()),
        Box::new(brute_force::mongo::create_action()),
        Box::new(brute_force::redis::create_action()),
        Box::new(brute_force::snmp::create_action()),
        Box::new(brute_force::vnc::create_action()),
        Box::new(brute_force::mqtt::create_action()),
        Box::new(brute_force::http_basic::create_action()),
        Box::new(brute_force::http_basic::create_action_8080()),
        // Exfiltration actions (child actions)
        Box::new(exfiltrate::ssh::StealFilesSsh),
        Box::new(exfiltrate::ftp::StealFilesFtp),
        Box::new(exfiltrate::telnet::StealFilesTelnet),
        Box::new(exfiltrate::sql::StealDataSql),
        Box::new(exfiltrate::smb::StealFilesSmb),
        Box::new(exfiltrate::rdp::StealFilesRdp),
        Box::new(exfiltrate::postgres::StealDataPostgres),
        Box::new(exfiltrate::mongo::StealDataMongo),
        Box::new(exfiltrate::redis::StealDataRedis),
        Box::new(exfiltrate::snmp::StealDataSnmp),
        Box::new(exfiltrate::mqtt::StealDataMqtt),
        Box::new(exfiltrate::http::StealDataHttp),
        Box::new(exfiltrate::http::StealDataHttp8080),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    use tempfile::TempDir;

    use crate::config::{BjornConfig, PathConfig};
    use crate::state::KnowledgeBase;

    async fn test_state() -> (Arc<AppState>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let kb = KnowledgeBase::open(&db_path).await.unwrap();
        let config = BjornConfig::default();
        let paths = PathConfig::new(dir.path());
        let state = AppState::new(config, paths, kb);
        (state, dir)
    }

    #[tokio::test]
    async fn registry_has_expected_action_count() {
        let (state, _dir) = test_state().await;
        let actions = build_action_registry(&state);
        // 14 brute-force + 13 exfiltration = 27 total
        assert_eq!(actions.len(), 27, "expected 27 registered actions");
    }

    #[tokio::test]
    async fn registry_action_names_are_unique() {
        let (state, _dir) = test_state().await;
        let actions = build_action_registry(&state);
        let mut names = HashSet::new();
        for action in &actions {
            let inserted = names.insert(action.name());
            assert!(inserted, "duplicate action name: {}", action.name());
        }
    }

    #[tokio::test]
    async fn registry_all_child_parents_exist() {
        let (state, _dir) = test_state().await;
        let actions = build_action_registry(&state);
        let names: HashSet<&str> = actions.iter().map(|a| a.name()).collect();

        for action in &actions {
            if let Some(parent) = action.parent() {
                assert!(
                    names.contains(parent),
                    "action '{}' references parent '{}' which is not in the registry",
                    action.name(),
                    parent
                );
            }
        }
    }

    #[tokio::test]
    async fn registry_brute_force_actions_have_no_parent() {
        let (state, _dir) = test_state().await;
        let actions = build_action_registry(&state);
        let brute_force_names = [
            "SSHBruteforce",
            "FTPBruteforce",
            "TelnetBruteforce",
            "SQLBruteforce",
            "SMBBruteforce",
            "RDPBruteforce",
            "PostgresBruteforce",
            "MongoBruteforce",
            "RedisBruteforce",
            "SNMPBruteforce",
            "VNCBruteforce",
            "MQTTBruteforce",
            "HTTPBruteforce",
            "HTTPBruteforce8080",
        ];
        for action in &actions {
            if brute_force_names.contains(&action.name()) {
                assert!(
                    action.parent().is_none(),
                    "brute-force action '{}' should have no parent",
                    action.name()
                );
            }
        }
    }

    #[tokio::test]
    async fn registry_exfiltration_actions_all_have_parents() {
        let (state, _dir) = test_state().await;
        let actions = build_action_registry(&state);
        let exfil_names = [
            "StealFilesSSH",
            "StealFilesFTP",
            "StealFilesTelnet",
            "StealDataSQL",
            "StealFilesSMB",
            "StealFilesRDP",
            "StealDataPostgres",
            "StealDataMongo",
            "StealDataRedis",
            "StealDataSNMP",
            "StealDataMQTT",
            "StealDataHTTP",
            "StealDataHTTP8080",
        ];
        for action in &actions {
            if exfil_names.contains(&action.name()) {
                assert!(
                    action.parent().is_some(),
                    "exfiltration action '{}' should have a parent",
                    action.name()
                );
            }
        }
    }

    #[tokio::test]
    async fn registry_port_assignments_are_correct() {
        let (state, _dir) = test_state().await;
        let actions = build_action_registry(&state);

        let expected_ports: Vec<(&str, u16)> = vec![
            ("SSHBruteforce", 22),
            ("FTPBruteforce", 21),
            ("TelnetBruteforce", 23),
            ("SQLBruteforce", 3306),
            ("SMBBruteforce", 445),
            ("RDPBruteforce", 3389),
            ("PostgresBruteforce", 5432),
            ("MongoBruteforce", 27017),
            ("RedisBruteforce", 6379),
            ("SNMPBruteforce", 161),
            ("VNCBruteforce", 5900),
            ("MQTTBruteforce", 1883),
            ("HTTPBruteforce", 80),
            ("HTTPBruteforce8080", 8080),
        ];

        for (name, expected_port) in &expected_ports {
            let action = actions
                .iter()
                .find(|a| a.name() == *name)
                .unwrap_or_else(|| panic!("action '{name}' not found in registry"));
            assert_eq!(
                action.port(),
                Some(*expected_port),
                "action '{name}' should target port {expected_port}"
            );
        }
    }

    #[tokio::test]
    async fn registry_all_actions_have_ports() {
        let (state, _dir) = test_state().await;
        let actions = build_action_registry(&state);
        for action in &actions {
            assert!(
                action.port().is_some(),
                "action '{}' should have a port assignment",
                action.name()
            );
        }
    }

    #[test]
    fn action_outcome_is_success() {
        assert!(ActionOutcome::Success.is_success());
        assert!(!ActionOutcome::Failed("err".to_string()).is_success());
    }

    #[test]
    fn action_outcome_equality() {
        assert_eq!(ActionOutcome::Success, ActionOutcome::Success);
        assert_eq!(
            ActionOutcome::Failed("x".to_string()),
            ActionOutcome::Failed("x".to_string())
        );
        assert_ne!(
            ActionOutcome::Success,
            ActionOutcome::Failed("x".to_string())
        );
    }

    #[test]
    fn action_meta_debug() {
        let meta = ActionMeta {
            name: "TestAction",
            port: Some(22),
            parent: None,
        };
        let debug = format!("{meta:?}");
        assert!(debug.contains("TestAction"));
        assert!(debug.contains("22"));
    }

    #[test]
    fn target_clone() {
        let target = Target {
            host_id: 1,
            ip: "10.0.0.1".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            hostname: Some("host1".to_string()),
            ports: vec![22, 80],
        };
        let cloned = target.clone();
        assert_eq!(cloned.host_id, target.host_id);
        assert_eq!(cloned.ip, target.ip);
        assert_eq!(cloned.mac_address, target.mac_address);
        assert_eq!(cloned.hostname, target.hostname);
        assert_eq!(cloned.ports, target.ports);
    }
}
