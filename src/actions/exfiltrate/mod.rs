pub mod ftp;
pub mod http;
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

use std::path::PathBuf;
use std::sync::Arc;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

/// Common helper: get stored credentials for a host + protocol from the KB.
async fn get_credentials(
    state: &Arc<AppState>,
    host_id: i64,
    protocol: &str,
) -> Vec<(String, String)> {
    match state.kb.credentials(Some(protocol)).await {
        Ok(creds) => creds
            .into_iter()
            .filter(|c| c.host_id == host_id)
            .map(|c| (c.username, c.password))
            .collect(),
        Err(e) => {
            tracing::error!(%e, "failed to load credentials");
            vec![]
        }
    }
}

/// Common helper: build the local output directory for stolen files.
fn build_output_dir(state: &Arc<AppState>, protocol: &str, mac: &str, ip: &str) -> PathBuf {
    state
        .paths
        .data_stolen_dir
        .join(protocol)
        .join(format!("{mac}_{ip}"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    async fn build_output_dir_formats_path_correctly() {
        let (state, _dir) = test_state().await;
        let result = build_output_dir(&state, "ssh", "aa:bb:cc:dd:ee:ff", "192.168.1.1");
        let path_str = result.to_string_lossy();
        assert!(
            path_str.contains("data_stolen"),
            "path should contain data_stolen: {path_str}"
        );
        assert!(path_str.ends_with("ssh/aa:bb:cc:dd:ee:ff_192.168.1.1"));
    }

    #[tokio::test]
    async fn build_output_dir_different_protocols() {
        let (state, _dir) = test_state().await;
        let ssh_dir = build_output_dir(&state, "ssh", "00:11:22:33:44:55", "10.0.0.1");
        let ftp_dir = build_output_dir(&state, "ftp", "00:11:22:33:44:55", "10.0.0.1");
        assert_ne!(ssh_dir, ftp_dir);
        assert!(ssh_dir.to_string_lossy().contains("/ssh/"));
        assert!(ftp_dir.to_string_lossy().contains("/ftp/"));
    }

    #[tokio::test]
    async fn get_credentials_returns_empty_for_no_stored_creds() {
        let (state, _dir) = test_state().await;
        let creds = get_credentials(&state, 999, "ssh").await;
        assert!(creds.is_empty());
    }

    #[tokio::test]
    async fn get_credentials_filters_by_host_id() {
        let (state, _dir) = test_state().await;
        // Insert hosts first to satisfy foreign key constraints
        let host1_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22")
            .await
            .unwrap();
        let host2_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:02", "10.0.0.2", None, true, "22")
            .await
            .unwrap();
        // Store credentials for two different hosts
        state
            .kb
            .store_credential(host1_id, "ssh", "user1", "pass1", 22)
            .await
            .unwrap();
        state
            .kb
            .store_credential(host2_id, "ssh", "user2", "pass2", 22)
            .await
            .unwrap();

        let creds = get_credentials(&state, host1_id, "ssh").await;
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0], ("user1".to_string(), "pass1".to_string()));
    }

    #[tokio::test]
    async fn get_credentials_filters_by_protocol() {
        let (state, _dir) = test_state().await;
        let host_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:03", "10.0.0.3", None, true, "21,22")
            .await
            .unwrap();
        state
            .kb
            .store_credential(host_id, "ssh", "user1", "pass1", 22)
            .await
            .unwrap();
        state
            .kb
            .store_credential(host_id, "ftp", "user2", "pass2", 21)
            .await
            .unwrap();

        let ssh_creds = get_credentials(&state, host_id, "ssh").await;
        assert_eq!(ssh_creds.len(), 1);
        assert_eq!(ssh_creds[0].0, "user1");

        let ftp_creds = get_credentials(&state, host_id, "ftp").await;
        assert_eq!(ftp_creds.len(), 1);
        assert_eq!(ftp_creds[0].0, "user2");
    }
}
