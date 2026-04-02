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
