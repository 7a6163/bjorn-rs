pub mod scanning;
pub mod vuln_scanner;
pub mod brute_force;
pub mod exfiltrate;

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
