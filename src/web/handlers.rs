use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::process::Command;

use crate::actions::{self, ActionOutcome, Target, build_action_registry};
use crate::config::BjornConfig;
use crate::state::AppState;

// -- Helper types --

#[derive(Serialize)]
struct ApiResponse {
    status: &'static str,
    message: String,
}

fn ok(msg: impl Into<String>) -> (StatusCode, Json<ApiResponse>) {
    (
        StatusCode::OK,
        Json(ApiResponse {
            status: "success",
            message: msg.into(),
        }),
    )
}

fn err_response(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiResponse>) {
    (
        code,
        Json(ApiResponse {
            status: "error",
            message: msg.into(),
        }),
    )
}

// -- GET handlers --

/// GET /load_config — return current config JSON
pub async fn load_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config();
    Json(config.as_ref().clone())
}

/// GET /restore_default_config — reset config to defaults
pub async fn restore_default_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let default = BjornConfig::default();
    if let Err(e) = default.save(&state.paths.shared_config_json) {
        return err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    state.config.store(Arc::new(default.clone()));
    Json(default).into_response()
}

/// GET /get_web_delay
pub async fn get_web_delay(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config();
    Json(serde_json::json!({ "web_delay": config.web_delay }))
}

/// GET /scan_wifi — scan for available WiFi networks
pub async fn scan_wifi() -> impl IntoResponse {
    let scan = Command::new("sudo")
        .args(["iwlist", "wlan0", "scan"])
        .output()
        .await;

    let networks = match scan {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_wifi_networks(&stdout)
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return err_response(StatusCode::INTERNAL_SERVER_ERROR, stderr.to_string())
                .into_response();
        }
        Err(e) => {
            return err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };

    let current_ssid = Command::new("iwgetid")
        .arg("-r")
        .output()
        .await
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    Json(serde_json::json!({
        "networks": networks,
        "current_ssid": current_ssid
    }))
    .into_response()
}

fn parse_wifi_networks(scan_output: &str) -> Vec<String> {
    let mut networks = Vec::new();
    for line in scan_output.lines() {
        if let Some(pos) = line.find("ESSID:") {
            let ssid = line[pos + 6..].trim_matches('"').to_string();
            if !ssid.is_empty() && !networks.contains(&ssid) {
                networks.push(ssid);
            }
        }
    }
    networks
}

/// GET /network_data — latest scan result as HTML table
pub async fn network_data(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let scan_dir = &state.paths.scan_results_dir;
    let latest = match find_latest_result_file(scan_dir).await {
        Some(path) => path,
        None => {
            return err_response(StatusCode::NOT_FOUND, "no scan results found").into_response();
        }
    };

    match fs::read_to_string(&latest).await {
        Ok(content) => {
            let html = csv_to_html_table(&content);
            Response::builder()
                .header(header::CONTENT_TYPE, "text/html")
                .body(Body::from(html))
                .unwrap()
                .into_response()
        }
        Err(e) => err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn find_latest_result_file(dir: &std::path::Path) -> Option<PathBuf> {
    let mut entries = match fs::read_dir(dir).await {
        Ok(e) => e,
        Err(_) => return None,
    };

    let mut latest: Option<(PathBuf, std::time::SystemTime)> = None;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("result_") {
            if let Ok(meta) = entry.metadata().await {
                if let Ok(modified) = meta.modified() {
                    if latest.as_ref().is_none_or(|(_, t)| modified > *t) {
                        latest = Some((entry.path(), modified));
                    }
                }
            }
        }
    }
    latest.map(|(p, _)| p)
}

/// Escape HTML special characters to prevent XSS.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn csv_to_html_table(csv_content: &str) -> String {
    let mut html = String::from(r#"<table class="styled-table"><thead><tr>"#);
    let mut lines = csv_content.lines();

    if let Some(header_line) = lines.next() {
        for header in header_line.split(',') {
            html.push_str(&format!("<th>{}</th>", html_escape(header)));
        }
    }
    html.push_str("</tr></thead><tbody>");

    for line in lines {
        html.push_str("<tr>");
        for cell in line.split(',') {
            let class = if cell.trim().is_empty() {
                "red"
            } else {
                "green"
            };
            html.push_str(&format!(
                r#"<td class="{class}">{}</td>"#,
                html_escape(cell)
            ));
        }
        html.push_str("</tr>");
    }
    html.push_str("</tbody></table>");
    html
}

/// GET /netkb_data — knowledge base as HTML table
pub async fn netkb_data(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.kb.all_hosts().await {
        Ok(hosts) => {
            let mut html = String::from(
                r#"<table class="styled-table"><thead><tr>
                <th>MAC Address</th><th>IP</th><th>Hostname</th><th>Alive</th><th>Ports</th>
                </tr></thead><tbody>"#,
            );
            for host in &hosts {
                let row_class = if !host.alive {
                    r#" class="blue-row""#
                } else {
                    ""
                };
                let alive_str = if host.alive { "1" } else { "0" };
                html.push_str(&format!(
                    r#"<tr{row_class}><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                    host.mac_address,
                    host.ip,
                    host.hostname.as_deref().unwrap_or(""),
                    alive_str,
                    host.ports
                ));
            }
            html.push_str("</tbody></table>");
            Response::builder()
                .header(header::CONTENT_TYPE, "text/html")
                .body(Body::from(html))
                .unwrap()
                .into_response()
        }
        Err(e) => err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// GET /netkb_data_json — alive hosts with ports and actions as JSON
pub async fn netkb_data_json(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.kb.alive_hosts().await {
        Ok(hosts) => {
            let ips: Vec<&str> = hosts.iter().map(|h| h.ip.as_str()).collect();
            let ports: serde_json::Map<String, serde_json::Value> = hosts
                .iter()
                .map(|h| {
                    let port_list: Vec<&str> =
                        h.ports.split(';').filter(|p| !p.is_empty()).collect();
                    (h.ip.clone(), serde_json::json!(port_list))
                })
                .collect();

            // Return registered action names so the manual attack UI can populate the dropdown
            let registry = build_action_registry(&state);
            let action_names: Vec<&str> = registry.iter().map(|a| a.name()).collect();

            Json(serde_json::json!({
                "ips": ips,
                "ports": ports,
                "actions": action_names
            }))
            .into_response()
        }
        Err(e) => err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// GET /screen.png — serve the current e-Paper screenshot
pub async fn screen_image(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let path = state.paths.web_dir.join("screen.png");
    match fs::read(&path).await {
        Ok(bytes) => Response::builder()
            .header(header::CONTENT_TYPE, "image/png")
            .header(header::CACHE_CONTROL, "max-age=0, must-revalidate")
            .body(Body::from(bytes))
            .unwrap()
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// GET /get_logs — tail of log file
pub async fn get_logs(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let log_path = &state.paths.web_console_log;
    match fs::read_to_string(log_path).await {
        Ok(content) => {
            // Keep only last 2000 lines
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(2000);
            let trimmed = lines[start..].join("\n");
            Response::builder()
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(trimmed))
                .unwrap()
                .into_response()
        }
        Err(_) => Response::builder()
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(""))
            .unwrap()
            .into_response(),
    }
}

/// GET /list_credentials — credential CSV files as HTML
pub async fn list_credentials(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let dir = &state.paths.cracked_pwd_dir;
    match build_credentials_html(dir).await {
        Ok(html) => Response::builder()
            .header(header::CONTENT_TYPE, "text/html")
            .body(Body::from(html))
            .unwrap()
            .into_response(),
        Err(e) => err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn build_credentials_html(dir: &std::path::Path) -> std::io::Result<String> {
    let mut html = String::from(r#"<div class="credentials-container">"#);
    let mut entries = fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.ends_with(".csv") {
            let content = fs::read_to_string(entry.path()).await?;
            html.push_str(&format!("<h2>{name_str}</h2>\n"));
            html.push_str(&csv_to_html_table(&content));
        }
    }
    html.push_str("</div>");
    Ok(html)
}

/// GET /list_files — recursive directory listing as JSON
pub async fn list_files(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let dir = &state.paths.data_stolen_dir;
    match list_files_recursive(dir).await {
        Ok(files) => Json(files).into_response(),
        Err(e) => err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Serialize)]
struct FileEntry {
    name: String,
    is_directory: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    children: Option<Vec<FileEntry>>,
}

fn list_files_recursive(
    dir: &std::path::Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<FileEntry>>> + Send + '_>>
{
    Box::pin(async move {
        let mut entries = Vec::new();
        let mut read_dir = fs::read_dir(dir).await?;

        while let Some(entry) = read_dir.next_entry().await? {
            let meta = entry.metadata().await?;
            let name = entry.file_name().to_string_lossy().to_string();
            if meta.is_dir() {
                let children = list_files_recursive(&entry.path()).await?;
                entries.push(FileEntry {
                    name,
                    is_directory: true,
                    path: None,
                    children: Some(children),
                });
            } else {
                entries.push(FileEntry {
                    name,
                    is_directory: false,
                    path: Some(entry.path().to_string_lossy().to_string()),
                    children: None,
                });
            }
        }
        Ok(entries)
    })
}

/// GET /download_file?path=...
#[derive(Deserialize)]
pub struct DownloadFileQuery {
    path: String,
}

pub async fn download_file(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DownloadFileQuery>,
) -> impl IntoResponse {
    // Prevent path traversal: ensure the resolved path is within data_stolen_dir
    let base = &state.paths.data_stolen_dir;
    let requested = base.join(&query.path);
    let canonical = match requested.canonicalize() {
        Ok(p) => p,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let base_canonical = match base.canonicalize() {
        Ok(p) => p,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if !canonical.starts_with(&base_canonical) {
        return StatusCode::FORBIDDEN.into_response();
    }

    match fs::read(&canonical).await {
        Ok(bytes) => {
            let filename = canonical
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "download".to_string());
            Response::builder()
                .header(
                    header::CONTENT_DISPOSITION,
                    format!(r#"attachment; filename="{filename}""#),
                )
                .body(Body::from(bytes))
                .unwrap()
                .into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// GET /download_backup?filename=...
#[derive(Deserialize)]
pub struct DownloadBackupQuery {
    filename: String,
}

pub async fn download_backup(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DownloadBackupQuery>,
) -> impl IntoResponse {
    let base = &state.paths.backups_dir;
    let path = base.join(&query.filename);

    // Path traversal prevention
    let canonical = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let base_canonical = match base.canonicalize() {
        Ok(p) => p,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if !canonical.starts_with(&base_canonical) {
        return StatusCode::FORBIDDEN.into_response();
    }

    match fs::read(&canonical).await {
        Ok(bytes) => Response::builder()
            .header(
                header::CONTENT_DISPOSITION,
                format!(r#"attachment; filename="{}""#, query.filename),
            )
            .header(header::CONTENT_TYPE, "application/zip")
            .body(Body::from(bytes))
            .unwrap()
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// -- POST handlers --

/// POST /save_config — update config from JSON body
pub async fn save_config(
    State(state): State<Arc<AppState>>,
    Json(params): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Read current config, merge params, save
    let config_path = &state.paths.shared_config_json;
    let current_json = match fs::read_to_string(config_path).await {
        Ok(s) => s,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let mut current: serde_json::Value = match serde_json::from_str(&current_json) {
        Ok(v) => v,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    // Merge incoming params into current config — only accept known fields.
    // Reject sensitive fields that should not be set via the web UI.
    let blocked_keys = ["llm_api_key"];
    if let (Some(current_obj), Some(params_obj)) = (current.as_object_mut(), params.as_object()) {
        // Validate: deserialize to BjornConfig to ensure only known fields are accepted
        let test_merge = {
            let mut test = current_obj.clone();
            for (key, value) in params_obj {
                test.insert(key.clone(), value.clone());
            }
            serde_json::from_value::<crate::config::BjornConfig>(serde_json::Value::Object(test))
        };
        if let Err(e) = test_merge {
            return err_response(StatusCode::BAD_REQUEST, format!("invalid config: {e}"));
        }

        for (key, value) in params_obj {
            if blocked_keys.contains(&key.as_str()) {
                continue; // Skip sensitive fields
            }
            current_obj.insert(key.clone(), value.clone());
        }
    }

    // Write back
    let json_str = serde_json::to_string_pretty(&current).unwrap_or_default();
    if let Err(e) = fs::write(config_path, &json_str).await {
        return err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    // Hot-reload into AppState
    state.reload_config();

    ok("configuration saved")
}

/// POST /connect_wifi
#[derive(Deserialize)]
pub struct WifiParams {
    ssid: String,
    password: String,
}

pub async fn connect_wifi(Json(params): Json<WifiParams>) -> impl IntoResponse {
    // Sanitize: reject newlines/control chars that could inject nmconnection sections
    if params.ssid.contains('\n')
        || params.ssid.contains('\r')
        || params.password.contains('\n')
        || params.password.contains('\r')
    {
        return err_response(
            StatusCode::BAD_REQUEST,
            "SSID and password must not contain newlines",
        );
    }

    let nmconnection = format!(
        r#"[connection]
id=preconfigured
type=wifi
autoconnect=true

[wifi]
ssid={}
mode=infrastructure

[wifi-security]
key-mgmt=wpa-psk
psk={}

[ipv4]
method=auto

[ipv6]
method=auto
"#,
        params.ssid, params.password
    );

    let config_path = "/etc/NetworkManager/system-connections/preconfigured.nmconnection";
    if let Err(e) = fs::write(config_path, &nmconnection).await {
        return err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    let _ = Command::new("sudo")
        .args(["chmod", "600", config_path])
        .output()
        .await;
    let _ = Command::new("sudo")
        .args(["nmcli", "connection", "reload"])
        .output()
        .await;

    match Command::new("sudo")
        .args(["nmcli", "connection", "up", "preconfigured"])
        .output()
        .await
    {
        Ok(output) if output.status.success() => ok(format!("connected to {}", params.ssid)),
        Ok(output) => err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from_utf8_lossy(&output.stderr).to_string(),
        ),
        Err(e) => err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// POST /disconnect_wifi
pub async fn disconnect_wifi() -> impl IntoResponse {
    let _ = Command::new("sudo")
        .args(["nmcli", "connection", "down", "preconfigured"])
        .output()
        .await;

    ok("disconnected from WiFi")
}

/// POST /clear_files — full reset of data directories
pub async fn clear_files(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let dirs_to_clear = [
        &state.paths.cracked_pwd_dir,
        &state.paths.data_stolen_dir,
        &state.paths.scan_results_dir,
        &state.paths.vulnerabilities_dir,
        &state.paths.logs_dir,
    ];

    for dir in &dirs_to_clear {
        let _ = clear_directory(dir).await;
    }

    // Also remove config/actions.json and netkb.db
    let _ = fs::remove_file(&state.paths.actions_json).await;
    let _ = fs::remove_file(&state.paths.netkb_db).await;

    ok("files cleared successfully")
}

/// POST /clear_files_light — clear output data only (keep config)
pub async fn clear_files_light(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let dirs_to_clear = [
        &state.paths.cracked_pwd_dir,
        &state.paths.data_stolen_dir,
        &state.paths.scan_results_dir,
        &state.paths.vulnerabilities_dir,
        &state.paths.logs_dir,
    ];

    for dir in &dirs_to_clear {
        let _ = clear_directory(dir).await;
    }

    ok("files cleared successfully")
}

async fn clear_directory(dir: &std::path::Path) -> std::io::Result<()> {
    let mut entries = fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_dir() {
            fs::remove_dir_all(&path).await?;
        } else {
            fs::remove_file(&path).await?;
        }
    }
    Ok(())
}

/// POST /reboot
pub async fn reboot_system() -> impl IntoResponse {
    let _ = Command::new("sudo").arg("reboot").spawn();
    ok("system is rebooting")
}

/// POST /shutdown
pub async fn shutdown_system() -> impl IntoResponse {
    let _ = Command::new("sudo").args(["shutdown", "now"]).spawn();
    ok("system is shutting down")
}

/// POST /restart_bjorn_service
pub async fn restart_bjorn_service() -> impl IntoResponse {
    let _ = Command::new("sudo")
        .args(["systemctl", "restart", "bjorn.service"])
        .spawn();
    ok("bjorn service restarted")
}

/// POST /backup — create a zip backup
pub async fn create_backup(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("backup_{timestamp}.zip");
    let backup_path = state.paths.backups_dir.join(&filename);

    // Use system zip command (simpler than pulling in a zip crate)
    let root = &state.paths.root;
    let result = Command::new("zip")
        .args(["-r", backup_path.to_str().unwrap_or_default()])
        .arg("config")
        .arg("data")
        .arg("resources")
        .current_dir(root)
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => Json(serde_json::json!({
            "status": "success",
            "url": format!("/download_backup?filename={filename}"),
            "filename": filename,
        }))
        .into_response(),
        Ok(output) => err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
        .into_response(),
        Err(e) => err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// POST /stop_orchestrator
pub async fn stop_orchestrator(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut status = state.status.write().await;
    status.should_exit = true;
    status.manual_mode = true;
    ok("orchestrator stopping")
}

/// POST /start_orchestrator
pub async fn start_orchestrator(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut status = state.status.write().await;
    status.should_exit = false;
    status.manual_mode = false;
    ok("orchestrator starting")
}

/// POST /execute_manual_attack — manually execute a specific action on a target
#[derive(Deserialize)]
pub struct ManualAttackParams {
    ip: String,
    port: u16,
    action: String,
}

pub async fn execute_manual_attack(
    State(state): State<Arc<AppState>>,
    Json(params): Json<ManualAttackParams>,
) -> impl IntoResponse {
    // Look up host in knowledge base
    let host = match state.kb.host_by_ip(&params.ip).await {
        Ok(Some(h)) => h,
        Ok(None) => {
            return err_response(StatusCode::NOT_FOUND, format!("no host found for IP: {}", params.ip));
        }
        Err(e) => {
            return err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    };

    // Build action registry and find the requested action
    let registry = build_action_registry(&state);
    let action = match registry.iter().find(|a| a.name() == params.action) {
        Some(a) => a,
        None => {
            return err_response(
                StatusCode::BAD_REQUEST,
                format!("action '{}' not found", params.action),
            );
        }
    };

    let ports: Vec<u16> = host
        .ports
        .split(';')
        .filter_map(|p| p.parse().ok())
        .collect();

    let target = Target {
        host_id: host.id,
        ip: host.ip.clone(),
        mac_address: host.mac_address.clone(),
        hostname: host.hostname.clone(),
        ports,
    };

    tracing::info!(
        action = params.action,
        ip = %params.ip,
        port = params.port,
        "executing manual attack from web UI"
    );

    let outcome = action.execute(&target, &state).await;
    let status_str = match &outcome {
        ActionOutcome::Success => "success",
        ActionOutcome::Failed(_) => "failed",
    };

    let _ = state.kb.record_action(host.id, action.name(), status_str).await;

    match outcome {
        ActionOutcome::Success => ok(format!("{} executed successfully on {}:{}", params.action, params.ip, params.port)),
        ActionOutcome::Failed(msg) => err_response(
            StatusCode::OK,
            format!("{} failed on {}:{}: {}", params.action, params.ip, params.port, msg),
        ),
    }
}

/// POST /restore — upload and extract a backup zip file
pub async fn restore_backup(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if body.is_empty() {
        return err_response(StatusCode::BAD_REQUEST, "no file uploaded");
    }

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let upload_path = state.paths.uploads_dir.join(format!("restore_{timestamp}.zip"));

    // Save uploaded file
    if let Err(e) = fs::write(&upload_path, &body).await {
        return err_response(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to save upload: {e}"));
    }

    // Extract zip to BJORN_ROOT
    let root = &state.paths.root;
    let result = Command::new("unzip")
        .args(["-o", upload_path.to_str().unwrap_or_default(), "-d", root.to_str().unwrap_or_default()])
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            // Reload config after restore
            state.reload_config();
            ok("restore completed successfully")
        }
        Ok(output) => err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("unzip failed: {}", String::from_utf8_lossy(&output.stderr)),
        ),
        Err(e) => err_response(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to run unzip: {e}")),
    }
}

// -- LLM API handlers --

/// POST /api/llm/chat — chat with the LLM
#[derive(Deserialize)]
pub struct LlmChatRequest {
    message: String,
    #[serde(default)]
    use_tools: bool,
}

pub async fn llm_chat(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LlmChatRequest>,
) -> impl IntoResponse {
    let bridge = crate::llm::bridge::LlmBridge::new(Arc::clone(&state));
    let system = "You are Bjorn, an autonomous cyber-security assistant running on a Raspberry Pi. Help the user understand the network state and suggest actions.";

    match bridge.complete(system, &req.message, req.use_tools).await {
        Some(response) => Json(serde_json::json!({
            "status": "success",
            "response": response,
        }))
        .into_response(),
        None => Json(serde_json::json!({
            "status": "error",
            "message": "LLM not available. Check llm_enabled and API key in config.",
        }))
        .into_response(),
    }
}

/// GET /api/llm/status
pub async fn llm_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config();
    Json(serde_json::json!({
        "enabled": config.llm_enabled,
        "mode": config.llm_mode,
        "provider": config.llm_api_provider,
        "model": config.llm_api_model,
        "ollama_url": config.llm_ollama_url,
        "ollama_model": config.llm_ollama_model,
        "has_api_key": !config.llm_api_key.is_empty(),
    }))
}

// -- Tool/MCP-compatible API handlers --

/// GET /api/tools/hosts
pub async fn api_get_hosts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let inputs = serde_json::json!({"alive_only": true});
    let result = crate::llm::tools::execute_tool("get_hosts", &inputs, &state).await;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(result))
        .unwrap()
}

/// GET /api/tools/vulnerabilities
pub async fn api_get_vulnerabilities(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let inputs = serde_json::json!({"limit": 100});
    let result = crate::llm::tools::execute_tool("get_vulnerabilities", &inputs, &state).await;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(result))
        .unwrap()
}

/// GET /api/tools/credentials
pub async fn api_get_credentials(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let inputs = serde_json::json!({});
    let result = crate::llm::tools::execute_tool("get_credentials", &inputs, &state).await;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(result))
        .unwrap()
}

/// GET /api/tools/status
pub async fn api_get_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let inputs = serde_json::json!({});
    let result = crate::llm::tools::execute_tool("get_status", &inputs, &state).await;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(result))
        .unwrap()
}

// -- Sentinel handlers --

/// GET /api/sentinel/alerts — placeholder until Sentinel state is shared
pub async fn sentinel_alerts(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    // TODO: Share SentinelEngine alerts via AppState
    Json(serde_json::json!({
        "alerts": [],
        "note": "Sentinel alerts will be available when sentinel_enabled=true"
    }))
}
