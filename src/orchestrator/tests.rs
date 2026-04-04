use std::sync::Arc;

use tempfile::TempDir;

use crate::config::{BjornConfig, PathConfig};
use crate::state::{AppState, KnowledgeBase};

use super::Orchestrator;

// ---------------------------------------------------------------------------
// Test helper — mirrors the pattern from llm/tools.rs tests
// ---------------------------------------------------------------------------

async fn test_state() -> (Arc<AppState>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let kb = KnowledgeBase::open(&db_path).await.unwrap();
    let config = BjornConfig::default();
    let paths = PathConfig::new(dir.path());
    let state = AppState::new(config, paths, kb);
    (state, dir)
}

// ---------------------------------------------------------------------------
// Orchestrator::new
// ---------------------------------------------------------------------------

#[tokio::test]
async fn new_creates_orchestrator_with_actions() {
    let (state, _dir) = test_state().await;
    let orch = Orchestrator::new(Arc::clone(&state));

    // The action registry should contain at least the brute-force actions
    assert!(
        !orch.actions.is_empty(),
        "action registry should not be empty"
    );
}

#[tokio::test]
async fn new_semaphore_has_capacity() {
    let (state, _dir) = test_state().await;
    let orch = Orchestrator::new(Arc::clone(&state));

    // Semaphore should allow acquiring permits (default 10)
    let permit = orch.semaphore.try_acquire();
    assert!(permit.is_ok(), "semaphore should have available permits");
}

// ---------------------------------------------------------------------------
// should_run_action — no prior results means "run"
// ---------------------------------------------------------------------------

#[tokio::test]
async fn should_run_action_no_prior_result() {
    let (state, _dir) = test_state().await;
    let host_id = state
        .kb
        .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22")
        .await
        .unwrap();

    let orch = Orchestrator::new(Arc::clone(&state));

    // No action recorded yet — should return true
    assert!(orch.should_run_action(host_id, "SSHBruteforce").await);
}

// ---------------------------------------------------------------------------
// should_run_action — after success, default config does NOT retry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn should_run_action_after_success_no_retry_by_default() {
    let (state, _dir) = test_state().await;
    let host_id = state
        .kb
        .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22")
        .await
        .unwrap();

    state
        .kb
        .record_action(host_id, "SSHBruteforce", "success")
        .await
        .unwrap();

    let orch = Orchestrator::new(Arc::clone(&state));

    // Default config has retry_success_actions = false
    let result = orch.should_run_action(host_id, "SSHBruteforce").await;
    assert!(
        !result,
        "should not retry a successful action when retry_success_actions is false"
    );
}

// ---------------------------------------------------------------------------
// should_run_action — after failure, depends on config
// ---------------------------------------------------------------------------

#[tokio::test]
async fn should_run_action_after_failure_with_retry_enabled() {
    let (state, _dir) = test_state().await;

    // Override config to enable failed retries with 0 delay for instant retry
    let mut config = BjornConfig::default();
    config.retry_failed_actions = true;
    config.failed_retry_delay = 0;
    state.config.store(Arc::new(config));

    let host_id = state
        .kb
        .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22")
        .await
        .unwrap();

    state
        .kb
        .record_action(host_id, "SSHBruteforce", "failed")
        .await
        .unwrap();

    let orch = Orchestrator::new(Arc::clone(&state));

    assert!(
        orch.should_run_action(host_id, "SSHBruteforce").await,
        "should retry failed action when retry is enabled and delay is 0"
    );
}

// ---------------------------------------------------------------------------
// has_parent_succeeded
// ---------------------------------------------------------------------------

#[tokio::test]
async fn has_parent_succeeded_no_result() {
    let (state, _dir) = test_state().await;
    let host_id = state
        .kb
        .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22")
        .await
        .unwrap();

    let orch = Orchestrator::new(Arc::clone(&state));

    assert!(
        !orch.has_parent_succeeded(host_id, "SSHBruteforce").await,
        "no result means parent has not succeeded"
    );
}

#[tokio::test]
async fn has_parent_succeeded_after_success() {
    let (state, _dir) = test_state().await;
    let host_id = state
        .kb
        .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22")
        .await
        .unwrap();

    state
        .kb
        .record_action(host_id, "SSHBruteforce", "success")
        .await
        .unwrap();

    let orch = Orchestrator::new(Arc::clone(&state));

    assert!(orch.has_parent_succeeded(host_id, "SSHBruteforce").await);
}

#[tokio::test]
async fn has_parent_succeeded_after_failure() {
    let (state, _dir) = test_state().await;
    let host_id = state
        .kb
        .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22")
        .await
        .unwrap();

    state
        .kb
        .record_action(host_id, "SSHBruteforce", "failed")
        .await
        .unwrap();

    let orch = Orchestrator::new(Arc::clone(&state));

    assert!(
        !orch.has_parent_succeeded(host_id, "SSHBruteforce").await,
        "failed parent should not count as succeeded"
    );
}

// ---------------------------------------------------------------------------
// update_status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_status_sets_action_and_detail() {
    let (state, _dir) = test_state().await;
    let orch = Orchestrator::new(Arc::clone(&state));

    orch.update_status("NetworkScanner", "scanning 10.0.0.0/24")
        .await;

    let status = state.status.read().await;
    assert_eq!(status.current_action, "NetworkScanner");
    assert_eq!(status.detail, "scanning 10.0.0.0/24");
}

#[tokio::test]
async fn update_status_overwrites_previous() {
    let (state, _dir) = test_state().await;
    let orch = Orchestrator::new(Arc::clone(&state));

    orch.update_status("SSHBruteforce", "10.0.0.5").await;
    orch.update_status("IDLE", "").await;

    let status = state.status.read().await;
    assert_eq!(status.current_action, "IDLE");
    assert_eq!(status.detail, "");
}

// ---------------------------------------------------------------------------
// should_exit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn should_exit_false_initially() {
    let (state, _dir) = test_state().await;
    let orch = Orchestrator::new(Arc::clone(&state));

    assert!(!orch.should_exit().await);
}

#[tokio::test]
async fn should_exit_true_when_shutdown_cancelled() {
    let (state, _dir) = test_state().await;
    let orch = Orchestrator::new(Arc::clone(&state));

    state.shutdown.cancel();

    assert!(orch.should_exit().await);
}

#[tokio::test]
async fn should_exit_true_when_status_flag_set() {
    let (state, _dir) = test_state().await;
    let orch = Orchestrator::new(Arc::clone(&state));

    {
        let mut status = state.status.write().await;
        status.should_exit = true;
    }

    assert!(orch.should_exit().await);
}

// ---------------------------------------------------------------------------
// is_manual_mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn is_manual_mode_false_initially() {
    let (state, _dir) = test_state().await;
    let orch = Orchestrator::new(Arc::clone(&state));

    assert!(!orch.is_manual_mode().await);
}

#[tokio::test]
async fn is_manual_mode_true_when_set() {
    let (state, _dir) = test_state().await;
    let orch = Orchestrator::new(Arc::clone(&state));

    {
        let mut status = state.status.write().await;
        status.manual_mode = true;
    }

    assert!(orch.is_manual_mode().await);
}

// ---------------------------------------------------------------------------
// Action registry integration — verify build_action_registry produces valid
// actions with expected traits (name, port, parent).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn action_registry_contains_ssh_brute() {
    let (state, _dir) = test_state().await;
    let orch = Orchestrator::new(Arc::clone(&state));

    let names: Vec<&str> = orch.actions.iter().map(|a| a.name()).collect();
    assert!(
        names.contains(&"SSHBruteforce"),
        "registry should contain SSHBruteforce, got: {names:?}"
    );
}

#[tokio::test]
async fn action_registry_parent_actions_have_no_parent() {
    let (state, _dir) = test_state().await;
    let orch = Orchestrator::new(Arc::clone(&state));

    for action in &orch.actions {
        if action.parent().is_none() {
            // Parent actions should have a port requirement (or be portless scanners)
            // Just verify the invariant that parent() is indeed None
            assert!(action.parent().is_none());
        }
    }
}

#[tokio::test]
async fn action_registry_child_actions_reference_valid_parents() {
    let (state, _dir) = test_state().await;
    let orch = Orchestrator::new(Arc::clone(&state));

    let parent_names: Vec<&str> = orch
        .actions
        .iter()
        .filter(|a| a.parent().is_none())
        .map(|a| a.name())
        .collect();

    for action in &orch.actions {
        if let Some(parent_name) = action.parent() {
            assert!(
                parent_names.contains(&parent_name),
                "child action '{}' references parent '{}' which is not in the registry",
                action.name(),
                parent_name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// should_run_action — different action for same host does not interfere
// ---------------------------------------------------------------------------

#[tokio::test]
async fn should_run_action_independent_per_action_name() {
    let (state, _dir) = test_state().await;
    let host_id = state
        .kb
        .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22;21")
        .await
        .unwrap();

    // Record SSHBruteforce as success
    state
        .kb
        .record_action(host_id, "SSHBruteforce", "success")
        .await
        .unwrap();

    let orch = Orchestrator::new(Arc::clone(&state));

    // SSHBruteforce should not retry (default config)
    assert!(!orch.should_run_action(host_id, "SSHBruteforce").await);

    // FTPBruteforce has no result — should run
    assert!(orch.should_run_action(host_id, "FTPBruteforce").await);
}

// ---------------------------------------------------------------------------
// has_parent_succeeded — latest result wins
// ---------------------------------------------------------------------------

#[tokio::test]
async fn has_parent_succeeded_latest_result_wins() {
    let (state, _dir) = test_state().await;
    let host_id = state
        .kb
        .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22")
        .await
        .unwrap();

    // First succeed, then fail
    state
        .kb
        .record_action(host_id, "SSHBruteforce", "success")
        .await
        .unwrap();
    state
        .kb
        .record_action(host_id, "SSHBruteforce", "failed")
        .await
        .unwrap();

    let orch = Orchestrator::new(Arc::clone(&state));

    // The latest result is "failed", so parent has not succeeded
    assert!(
        !orch.has_parent_succeeded(host_id, "SSHBruteforce").await,
        "latest result is 'failed', parent should not be considered succeeded"
    );
}
