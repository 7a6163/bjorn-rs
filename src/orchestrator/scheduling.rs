//! Pure business logic for orchestrator scheduling decisions.
//!
//! These functions are free of async, `Arc<AppState>`, and database calls,
//! making them straightforward to test.

use chrono::NaiveDateTime;

use crate::actions::ActionMeta;
use crate::state::ActionResult;

// ---------------------------------------------------------------------------
// Retry configuration — a plain-data subset of `BjornConfig`.
// ---------------------------------------------------------------------------

/// Retry-related fields extracted from `BjornConfig` so that pure functions
/// do not depend on the full config tree.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub retry_success_actions: bool,
    pub success_retry_delay: u64,
    pub retry_failed_actions: bool,
    pub failed_retry_delay: u64,
}

// ---------------------------------------------------------------------------
// Port parsing
// ---------------------------------------------------------------------------

/// Parse a semicolon-separated port string (e.g. `"22;80;443"`) into a `Vec<u16>`.
/// Invalid entries are silently skipped.
pub fn parse_ports(ports_str: &str) -> Vec<u16> {
    ports_str
        .split(';')
        .filter_map(|p| p.parse().ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Port → action matching
// ---------------------------------------------------------------------------

/// Return the subset of `registry` whose port requirement is satisfied by the
/// given open ports.  Actions with `port: None` match any host.
pub fn actions_for_ports<'a>(
    open_ports: &[u16],
    registry: &'a [ActionMeta],
) -> Vec<&'a ActionMeta> {
    registry
        .iter()
        .filter(|meta| match meta.port {
            Some(p) => open_ports.contains(&p),
            None => true,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Retry / delay decision
// ---------------------------------------------------------------------------

/// Decide whether an action should run again for a host, given its last
/// recorded result (if any), the current timestamp, and retry configuration.
///
/// Returns `true` when:
/// - The action has never run (`last_result` is `None`).
/// - The last status is unrecognised (neither "success" nor "failed").
/// - The relevant retry flag is enabled *and* enough time has elapsed.
pub fn should_retry_action(
    last_result: Option<&ActionResult>,
    now: NaiveDateTime,
    config: &RetryConfig,
) -> bool {
    let result = match last_result {
        None => return true,
        Some(r) => r,
    };

    let elapsed = (now - result.executed_at).num_seconds().max(0) as u64;

    match result.status.as_str() {
        "success" => {
            if !config.retry_success_actions {
                return false;
            }
            elapsed >= config.success_retry_delay
        }
        "failed" => {
            if !config.retry_failed_actions {
                return false;
            }
            elapsed >= config.failed_retry_delay
        }
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Parent / child relationships
// ---------------------------------------------------------------------------

/// Filter `registry` to only parent actions (those with `parent: None`).
pub fn parent_actions(registry: &[ActionMeta]) -> Vec<&ActionMeta> {
    registry.iter().filter(|m| m.parent.is_none()).collect()
}

/// Filter `registry` to only child actions (those with a `parent`).
pub fn child_actions(registry: &[ActionMeta]) -> Vec<&ActionMeta> {
    registry.iter().filter(|m| m.parent.is_some()).collect()
}

/// Return all child actions whose declared parent matches `parent_name`.
pub fn children_of<'a>(parent_name: &str, registry: &'a [ActionMeta]) -> Vec<&'a ActionMeta> {
    registry
        .iter()
        .filter(|m| m.parent == Some(parent_name))
        .collect()
}

/// Given a parent action's last result, decide which child actions are
/// eligible to run.  Children are only eligible when the parent's latest
/// result is `"success"`.
pub fn pending_child_actions<'a>(
    parent_name: &str,
    parent_result: Option<&ActionResult>,
    registry: &'a [ActionMeta],
) -> Vec<&'a ActionMeta> {
    let parent_succeeded = parent_result
        .map(|r| r.status == "success")
        .unwrap_or(false);

    if !parent_succeeded {
        return Vec::new();
    }

    children_of(parent_name, registry)
}

/// Check whether a parent action has succeeded, given its latest result.
pub fn parent_succeeded(parent_result: Option<&ActionResult>) -> bool {
    parent_result
        .map(|r| r.status == "success")
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    // Helpers ---------------------------------------------------------------

    fn dt(hour: u32, min: u32, sec: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(hour, min, sec)
            .unwrap()
    }

    fn make_result(status: &str, executed_at: NaiveDateTime) -> ActionResult {
        ActionResult {
            id: 1,
            host_id: 1,
            action_name: "TestAction".to_string(),
            status: status.to_string(),
            executed_at,
        }
    }

    fn default_retry_config() -> RetryConfig {
        RetryConfig {
            retry_success_actions: false,
            retry_failed_actions: true,
            success_retry_delay: 900,
            failed_retry_delay: 600,
        }
    }

    fn sample_registry() -> Vec<ActionMeta> {
        vec![
            ActionMeta {
                name: "SshBrute",
                port: Some(22),
                parent: None,
            },
            ActionMeta {
                name: "FtpBrute",
                port: Some(21),
                parent: None,
            },
            ActionMeta {
                name: "HttpBrute",
                port: Some(80),
                parent: None,
            },
            ActionMeta {
                name: "StealFilesSsh",
                port: Some(22),
                parent: Some("SshBrute"),
            },
            ActionMeta {
                name: "StealFilesFtp",
                port: Some(21),
                parent: Some("FtpBrute"),
            },
            ActionMeta {
                name: "NetworkScan",
                port: None,
                parent: None,
            },
        ]
    }

    // -- parse_ports --------------------------------------------------------

    #[test]
    fn parse_ports_basic() {
        assert_eq!(parse_ports("22;80;443"), vec![22, 80, 443]);
    }

    #[test]
    fn parse_ports_skips_invalid() {
        assert_eq!(parse_ports("22;abc;443"), vec![22, 443]);
    }

    #[test]
    fn parse_ports_empty_string() {
        assert_eq!(parse_ports(""), Vec::<u16>::new());
    }

    #[test]
    fn parse_ports_single() {
        assert_eq!(parse_ports("8080"), vec![8080]);
    }

    // -- actions_for_ports --------------------------------------------------

    #[test]
    fn actions_for_ports_matches_open_ports() {
        let registry = sample_registry();
        let matched = actions_for_ports(&[22, 80], &registry);
        let names: Vec<&str> = matched.iter().map(|m| m.name).collect();
        assert!(names.contains(&"SshBrute"));
        assert!(names.contains(&"HttpBrute"));
        assert!(names.contains(&"StealFilesSsh"));
        assert!(names.contains(&"NetworkScan")); // port: None matches all
        assert!(!names.contains(&"FtpBrute"));
    }

    #[test]
    fn actions_for_ports_none_port_always_matches() {
        let registry = sample_registry();
        let matched = actions_for_ports(&[], &registry);
        let names: Vec<&str> = matched.iter().map(|m| m.name).collect();
        assert_eq!(names, vec!["NetworkScan"]);
    }

    // -- should_retry_action ------------------------------------------------

    #[test]
    fn retry_never_run_returns_true() {
        let config = default_retry_config();
        assert!(should_retry_action(None, dt(12, 0, 0), &config));
    }

    #[test]
    fn retry_success_disabled() {
        let config = default_retry_config(); // retry_success_actions = false
        let result = make_result("success", dt(10, 0, 0));
        assert!(!should_retry_action(Some(&result), dt(12, 0, 0), &config));
    }

    #[test]
    fn retry_success_enabled_not_enough_time() {
        let config = RetryConfig {
            retry_success_actions: true,
            success_retry_delay: 900,
            ..default_retry_config()
        };
        let result = make_result("success", dt(10, 0, 0));
        // Only 300s elapsed, need 900
        assert!(!should_retry_action(Some(&result), dt(10, 5, 0), &config));
    }

    #[test]
    fn retry_success_enabled_enough_time() {
        let config = RetryConfig {
            retry_success_actions: true,
            success_retry_delay: 900,
            ..default_retry_config()
        };
        let result = make_result("success", dt(10, 0, 0));
        // 3600s elapsed, need 900
        assert!(should_retry_action(Some(&result), dt(11, 0, 0), &config));
    }

    #[test]
    fn retry_failed_not_enough_time() {
        let config = default_retry_config(); // retry_failed = true, delay = 600
        let result = make_result("failed", dt(10, 0, 0));
        // 60s elapsed, need 600
        assert!(!should_retry_action(Some(&result), dt(10, 1, 0), &config));
    }

    #[test]
    fn retry_failed_enough_time() {
        let config = default_retry_config();
        let result = make_result("failed", dt(10, 0, 0));
        // 3600s elapsed, need 600
        assert!(should_retry_action(Some(&result), dt(11, 0, 0), &config));
    }

    #[test]
    fn retry_failed_disabled() {
        let config = RetryConfig {
            retry_failed_actions: false,
            ..default_retry_config()
        };
        let result = make_result("failed", dt(10, 0, 0));
        assert!(!should_retry_action(Some(&result), dt(12, 0, 0), &config));
    }

    #[test]
    fn retry_unknown_status_returns_true() {
        let config = default_retry_config();
        let result = make_result("unknown", dt(10, 0, 0));
        assert!(should_retry_action(Some(&result), dt(10, 0, 1), &config));
    }

    // -- parent / child helpers ---------------------------------------------

    #[test]
    fn parent_actions_filters_correctly() {
        let registry = sample_registry();
        let parents = parent_actions(&registry);
        let names: Vec<&str> = parents.iter().map(|m| m.name).collect();
        assert_eq!(
            names,
            vec!["SshBrute", "FtpBrute", "HttpBrute", "NetworkScan"]
        );
    }

    #[test]
    fn child_actions_filters_correctly() {
        let registry = sample_registry();
        let children = child_actions(&registry);
        let names: Vec<&str> = children.iter().map(|m| m.name).collect();
        assert_eq!(names, vec!["StealFilesSsh", "StealFilesFtp"]);
    }

    #[test]
    fn children_of_returns_matching() {
        let registry = sample_registry();
        let kids = children_of("SshBrute", &registry);
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].name, "StealFilesSsh");
    }

    #[test]
    fn children_of_no_children() {
        let registry = sample_registry();
        let kids = children_of("HttpBrute", &registry);
        assert!(kids.is_empty());
    }

    // -- pending_child_actions ----------------------------------------------

    #[test]
    fn pending_children_when_parent_succeeded() {
        let registry = sample_registry();
        let result = make_result("success", dt(10, 0, 0));
        let pending = pending_child_actions("SshBrute", Some(&result), &registry);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].name, "StealFilesSsh");
    }

    #[test]
    fn pending_children_when_parent_failed() {
        let registry = sample_registry();
        let result = make_result("failed", dt(10, 0, 0));
        let pending = pending_child_actions("SshBrute", Some(&result), &registry);
        assert!(pending.is_empty());
    }

    #[test]
    fn pending_children_when_no_result() {
        let registry = sample_registry();
        let pending = pending_child_actions("SshBrute", None, &registry);
        assert!(pending.is_empty());
    }

    // -- parent_succeeded ---------------------------------------------------

    #[test]
    fn parent_succeeded_true() {
        let result = make_result("success", dt(10, 0, 0));
        assert!(parent_succeeded(Some(&result)));
    }

    #[test]
    fn parent_succeeded_false_on_failure() {
        let result = make_result("failed", dt(10, 0, 0));
        assert!(!parent_succeeded(Some(&result)));
    }

    #[test]
    fn parent_succeeded_false_on_none() {
        assert!(!parent_succeeded(None));
    }
}
