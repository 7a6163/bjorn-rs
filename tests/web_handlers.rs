//! Integration tests for web handlers.
//!
//! Uses axum's test utilities (tower::ServiceExt::oneshot) to send requests
//! through the full router without binding to a real TCP port.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use bjorn::config::{BjornConfig, PathConfig};
use bjorn::state::{AppState, KnowledgeBase};
use bjorn::web::build_router;

/// Build an `Arc<AppState>` backed by an in-memory SQLite KB inside a temp directory.
/// The returned `TempDir` must be held alive for the duration of the test.
async fn test_state() -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let paths = PathConfig::new(dir.path());
    paths.ensure_dirs().unwrap();

    let db_path = dir.path().join("test.db");
    let kb = KnowledgeBase::open(&db_path).await.unwrap();

    // Write the default config to disk so handlers that read from disk work correctly.
    let config = BjornConfig::default();
    let config_json = serde_json::to_string_pretty(&config).unwrap();
    std::fs::write(&paths.shared_config_json, &config_json).unwrap();

    let state = AppState::new(config, paths, kb);
    (state, dir)
}

/// Helper: read the full response body as bytes.
async fn body_bytes(body: Body) -> Vec<u8> {
    body.collect().await.unwrap().to_bytes().to_vec()
}

/// Helper: read the full response body as a UTF-8 string.
async fn body_string(body: Body) -> String {
    String::from_utf8(body_bytes(body).await).unwrap()
}

// ---------------------------------------------------------------------------
// 1. GET /load_config - returns valid JSON config
// ---------------------------------------------------------------------------

#[tokio::test]
async fn load_config_returns_valid_json() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/load_config")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let config: serde_json::Value = serde_json::from_str(&body).unwrap();

    // Verify key fields exist from BjornConfig defaults
    assert!(config.get("web_delay").is_some(), "missing web_delay field");
    assert!(config.get("websrv").is_some(), "missing websrv field");
}

// ---------------------------------------------------------------------------
// 2. GET /get_web_delay - returns web_delay value
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_web_delay_returns_value() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/get_web_delay")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["web_delay"], 2, "default web_delay should be 2");
}

// ---------------------------------------------------------------------------
// 3. GET /netkb_data - returns HTML table
// ---------------------------------------------------------------------------

#[tokio::test]
async fn netkb_data_returns_html_with_empty_db() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/netkb_data")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/html"));

    let body = body_string(resp.into_body()).await;
    assert!(
        body.contains("<table"),
        "response should contain an HTML table"
    );
    assert!(
        body.contains("MAC Address"),
        "table should have MAC Address header"
    );
}

#[tokio::test]
async fn netkb_data_includes_hosts() {
    let (state, _dir) = test_state().await;
    state
        .kb
        .upsert_host(
            "aa:bb:cc:dd:ee:01",
            "10.0.0.1",
            Some("router"),
            true,
            "22;80",
        )
        .await
        .unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .uri("/netkb_data")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    assert!(body.contains("10.0.0.1"), "should contain the host IP");
    assert!(body.contains("aa:bb:cc:dd:ee:01"), "should contain the MAC");
    assert!(body.contains("router"), "should contain the hostname");
}

// ---------------------------------------------------------------------------
// 4. GET /netkb_data_json - returns JSON with ips, ports, actions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn netkb_data_json_returns_structure() {
    let (state, _dir) = test_state().await;
    state
        .kb
        .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22;80")
        .await
        .unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .uri("/netkb_data_json")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert!(json["ips"].is_array(), "should have ips array");
    assert!(json["ports"].is_object(), "should have ports object");
    assert!(json["actions"].is_array(), "should have actions array");

    let ips = json["ips"].as_array().unwrap();
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0], "10.0.0.1");

    let ports = &json["ports"]["10.0.0.1"];
    assert!(ports.is_array());
    let port_list: Vec<&str> = ports
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(port_list.contains(&"22"));
    assert!(port_list.contains(&"80"));
}

#[tokio::test]
async fn netkb_data_json_empty_db() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/netkb_data_json")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["ips"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// 5. GET /screen.png - returns 404 when no image
// ---------------------------------------------------------------------------

#[tokio::test]
async fn screen_png_returns_404_when_missing() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/screen.png")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn screen_png_returns_image_when_present() {
    let (state, _dir) = test_state().await;

    // Create a fake PNG file in the web directory
    let web_dir = &state.paths.web_dir;
    std::fs::create_dir_all(web_dir).unwrap();
    let png_path = web_dir.join("screen.png");
    // Minimal valid PNG: 8-byte signature + IHDR + IEND
    let fake_png = b"\x89PNG\r\n\x1a\nfake";
    std::fs::write(&png_path, fake_png).unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .uri("/screen.png")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(content_type, "image/png");
}

// ---------------------------------------------------------------------------
// 6. GET /list_credentials - returns HTML
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_credentials_returns_html_when_empty() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/list_credentials")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/html"));

    let body = body_string(resp.into_body()).await;
    assert!(body.contains("credentials-container"));
}

#[tokio::test]
async fn list_credentials_includes_csv_data() {
    let (state, _dir) = test_state().await;

    // Write a CSV file into the cracked_pwd_dir
    let csv_content = "host,user,pass\n10.0.0.1,root,secret\n";
    let csv_path = state.paths.cracked_pwd_dir.join("ssh_creds.csv");
    std::fs::write(&csv_path, csv_content).unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .uri("/list_credentials")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    assert!(body.contains("ssh_creds.csv"), "should show the filename");
    assert!(body.contains("10.0.0.1"), "should show credential data");
}

// ---------------------------------------------------------------------------
// 7. POST /save_config - updates config
// ---------------------------------------------------------------------------

#[tokio::test]
async fn save_config_updates_value() {
    let (state, _dir) = test_state().await;

    // Verify default web_delay is 2
    assert_eq!(state.config().web_delay, 2);

    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/save_config")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"web_delay": 5}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "success");

    // Verify the config was hot-reloaded
    assert_eq!(state.config().web_delay, 5);
}

#[tokio::test]
async fn save_config_rejects_wrong_type() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    // web_delay is a u64, sending a string should fail validation
    let req = Request::builder()
        .method("POST")
        .uri("/save_config")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"web_delay": "not_a_number"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "error");
}

// ---------------------------------------------------------------------------
// 8. POST /stop_orchestrator - sets manual mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stop_orchestrator_sets_manual_mode() {
    let (state, _dir) = test_state().await;

    // Verify initial state
    {
        let status = state.status.read().await;
        assert!(!status.manual_mode);
        assert!(!status.should_exit);
    }

    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/stop_orchestrator")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "success");

    // Verify state was updated
    let status = state.status.read().await;
    assert!(status.manual_mode, "manual_mode should be true");
    assert!(status.should_exit, "should_exit should be true");
}

// ---------------------------------------------------------------------------
// 9. POST /start_orchestrator - clears manual mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_orchestrator_clears_manual_mode() {
    let (state, _dir) = test_state().await;

    // Pre-set manual mode
    {
        let mut status = state.status.write().await;
        status.manual_mode = true;
        status.should_exit = true;
    }

    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/start_orchestrator")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "success");

    // Verify state was cleared
    let status = state.status.read().await;
    assert!(!status.manual_mode, "manual_mode should be false");
    assert!(!status.should_exit, "should_exit should be false");
}

// ---------------------------------------------------------------------------
// 10. GET /restore_default_config - resets to defaults
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restore_default_config_resets_values() {
    let (state, _dir) = test_state().await;

    // First change a config value
    {
        let mut modified = (*state.config.load_full()).clone();
        modified.web_delay = 99;
        let json_str = serde_json::to_string_pretty(&modified).unwrap();
        std::fs::write(&state.paths.shared_config_json, &json_str).unwrap();
        state.config.store(Arc::new(modified));
    }
    assert_eq!(state.config().web_delay, 99);

    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/restore_default_config")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The response body should be the default config
    let body = body_string(resp.into_body()).await;
    let config: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        config["web_delay"], 2,
        "web_delay should be reset to default"
    );

    // Verify the in-memory config was also reset
    assert_eq!(state.config().web_delay, 2);
}

// ---------------------------------------------------------------------------
// 11. GET /api/llm/status - returns LLM config status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn llm_status_returns_config_fields() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/llm/status")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    // All expected fields should be present
    assert!(json.get("enabled").is_some(), "missing enabled field");
    assert!(json.get("mode").is_some(), "missing mode field");
    assert!(json.get("provider").is_some(), "missing provider field");
    assert!(json.get("model").is_some(), "missing model field");
    assert!(json.get("ollama_url").is_some(), "missing ollama_url field");
    assert!(
        json.get("ollama_model").is_some(),
        "missing ollama_model field"
    );
    assert!(
        json.get("has_api_key").is_some(),
        "missing has_api_key field"
    );

    // Default config has no API key
    assert_eq!(json["has_api_key"], false);
}

// ---------------------------------------------------------------------------
// 12. GET /api/tools/hosts - returns hosts JSON
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_tools_hosts_returns_json() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/tools/hosts")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("application/json"));

    let body = body_string(resp.into_body()).await;
    // Should be valid JSON (the tool returns a JSON string)
    let _json: serde_json::Value = serde_json::from_str(&body).unwrap();
}

#[tokio::test]
async fn api_tools_hosts_includes_inserted_host() {
    let (state, _dir) = test_state().await;
    state
        .kb
        .upsert_host(
            "aa:bb:cc:dd:ee:02",
            "10.0.0.2",
            Some("webserver"),
            true,
            "80",
        )
        .await
        .unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/tools/hosts")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    assert!(body.contains("10.0.0.2"), "should contain inserted host IP");
}

// ---------------------------------------------------------------------------
// 13. GET /api/tools/credentials - returns credentials JSON
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_tools_credentials_returns_json() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/tools/credentials")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("application/json"));

    let body = body_string(resp.into_body()).await;
    let _json: serde_json::Value = serde_json::from_str(&body).unwrap();
}

// ---------------------------------------------------------------------------
// 14. GET /api/tools/status - returns status JSON
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_tools_status_returns_json() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/tools/status")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("application/json"));

    let body = body_string(resp.into_body()).await;
    let _json: serde_json::Value = serde_json::from_str(&body).unwrap();
}

// ---------------------------------------------------------------------------
// 15. GET /api/sentinel/alerts - returns alerts array
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sentinel_alerts_returns_empty_array() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/sentinel/alerts")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert!(json["alerts"].is_array(), "should have alerts array");
    assert!(
        json["alerts"].as_array().unwrap().is_empty(),
        "alerts should be empty by default"
    );
    assert!(json.get("note").is_some(), "should have a note field");
}

// ---------------------------------------------------------------------------
// 16. GET /list_files - returns directory listing JSON
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_files_returns_empty_array_for_empty_dir() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/list_files")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json.is_array(), "should return a JSON array");
    assert!(json.as_array().unwrap().is_empty(), "should be empty");
}

#[tokio::test]
async fn list_files_includes_created_files() {
    let (state, _dir) = test_state().await;

    // Create a file and a subdirectory in data_stolen_dir
    let file_path = state.paths.data_stolen_dir.join("stolen_data.txt");
    std::fs::write(&file_path, "secret data").unwrap();

    let sub_dir = state.paths.data_stolen_dir.join("subdir");
    std::fs::create_dir_all(&sub_dir).unwrap();
    let nested_file = sub_dir.join("nested.txt");
    std::fs::write(&nested_file, "nested content").unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .uri("/list_files")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let entries = json.as_array().unwrap();
    assert!(!entries.is_empty(), "should have entries");

    // Check that we can find the file and the directory
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"stolen_data.txt"),
        "should contain the file"
    );
    assert!(names.contains(&"subdir"), "should contain the subdirectory");

    // Verify directory entry has children
    let dir_entry = entries.iter().find(|e| e["name"] == "subdir").unwrap();
    assert_eq!(dir_entry["is_directory"], true);
    assert!(dir_entry["children"].is_array());
}

// ---------------------------------------------------------------------------
// 17. POST /backup - creates a backup (conditional on `zip` availability)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn backup_creates_zip_or_fails_gracefully() {
    let (state, _dir) = test_state().await;

    // Create some content to back up
    let config_dir = state.paths.root.join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join("test.json"), "{}").unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/backup")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    // `zip` may not be installed on CI/dev machines, so accept either outcome
    if status == StatusCode::OK {
        assert_eq!(json["status"], "success");
        assert!(
            json.get("filename").is_some(),
            "success response should include filename"
        );
        assert!(
            json.get("url").is_some(),
            "success response should include download url"
        );
    } else {
        assert_eq!(json["status"], "error");
    }
}

// ---------------------------------------------------------------------------
// 18. POST /clear_files_light - clears output data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clear_files_light_removes_output_data() {
    let (state, _dir) = test_state().await;

    // Create files in various output directories
    let cred_file = state.paths.cracked_pwd_dir.join("test_creds.csv");
    std::fs::write(&cred_file, "host,user,pass\n").unwrap();

    let stolen_file = state.paths.data_stolen_dir.join("data.txt");
    std::fs::write(&stolen_file, "stolen").unwrap();

    let scan_file = state.paths.scan_results_dir.join("result_001.csv");
    std::fs::write(&scan_file, "ip,port\n").unwrap();

    // Verify files exist before clearing
    assert!(cred_file.exists());
    assert!(stolen_file.exists());
    assert!(scan_file.exists());

    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/clear_files_light")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "success");

    // Verify files were removed
    assert!(!cred_file.exists(), "credential file should be cleared");
    assert!(!stolen_file.exists(), "stolen data file should be cleared");
    assert!(!scan_file.exists(), "scan result file should be cleared");

    // Verify directories still exist
    assert!(state.paths.cracked_pwd_dir.exists());
    assert!(state.paths.data_stolen_dir.exists());
    assert!(state.paths.scan_results_dir.exists());
}

// ---------------------------------------------------------------------------
// 19. GET /network_data - returns 404 when no scan results
// ---------------------------------------------------------------------------

#[tokio::test]
async fn network_data_returns_404_when_no_results() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/network_data")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "error");
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("no scan results"),
        "should mention no scan results"
    );
}

#[tokio::test]
async fn network_data_returns_html_when_results_exist() {
    let (state, _dir) = test_state().await;

    // Create a scan result file (must be named result_*)
    let scan_file = state.paths.scan_results_dir.join("result_latest.csv");
    std::fs::write(&scan_file, "IP,Port,Service\n10.0.0.1,22,SSH\n").unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .uri("/network_data")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/html"));

    let body = body_string(resp.into_body()).await;
    assert!(body.contains("<table"), "should contain an HTML table");
    assert!(body.contains("10.0.0.1"), "should contain the IP");
    assert!(body.contains("SSH"), "should contain the service");
}

// ---------------------------------------------------------------------------
// 20. Root redirect: GET / redirects to /web/index.html
// ---------------------------------------------------------------------------

#[tokio::test]
async fn root_redirects_to_web_index() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder().uri("/").body(Body::empty()).unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/web/index.html");
}

// ---------------------------------------------------------------------------
// 21. HTML redirects: GET /loot.html redirects to /web/loot.html
// ---------------------------------------------------------------------------

#[tokio::test]
async fn loot_html_redirects_to_web_loot() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/loot.html")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/web/loot.html");
}

#[tokio::test]
async fn config_html_redirects_to_web_config() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/config.html")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/web/config.html");
}

// ---------------------------------------------------------------------------
// 22. GET /get_logs - returns log content
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_logs_returns_empty_when_no_log_file() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/get_logs")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/plain"));

    let body = body_string(resp.into_body()).await;
    assert!(
        body.is_empty(),
        "should return empty string when no log file"
    );
}

#[tokio::test]
async fn get_logs_returns_log_content() {
    let (state, _dir) = test_state().await;

    // Write a log file
    let log_content = "2024-01-01 INFO starting\n2024-01-01 DEBUG scanning\n";
    std::fs::write(&state.paths.web_console_log, log_content).unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .uri("/get_logs")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    assert!(body.contains("starting"), "should contain log content");
    assert!(body.contains("scanning"), "should contain log content");
}

// ---------------------------------------------------------------------------
// 23. POST /clear_files - full reset clears data and removes extra files
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clear_files_removes_actions_and_netkb() {
    let (state, _dir) = test_state().await;

    // Create the extra files that clear_files should remove
    std::fs::write(&state.paths.actions_json, "[]").unwrap();
    std::fs::write(&state.paths.netkb_db, "fake db").unwrap();

    // Also create data in output directories
    let cred_file = state.paths.cracked_pwd_dir.join("creds.csv");
    std::fs::write(&cred_file, "data").unwrap();

    assert!(state.paths.actions_json.exists());
    assert!(state.paths.netkb_db.exists());
    assert!(cred_file.exists());

    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/clear_files")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "success");

    // Verify everything was cleared
    assert!(!cred_file.exists(), "credential file should be removed");
    assert!(
        !state.paths.actions_json.exists(),
        "actions.json should be removed"
    );
    assert!(!state.paths.netkb_db.exists(), "netkb.db should be removed");
}

// ---------------------------------------------------------------------------
// 24. GET /download_file - path traversal prevention
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_file_returns_404_for_nonexistent() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/download_file?path=nonexistent.txt")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn download_file_serves_existing_file() {
    let (state, _dir) = test_state().await;

    let file_path = state.paths.data_stolen_dir.join("loot.txt");
    std::fs::write(&file_path, "captured data").unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .uri("/download_file?path=loot.txt")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let content_disposition = resp
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        content_disposition.contains("loot.txt"),
        "should have correct filename in disposition"
    );

    let body = body_string(resp.into_body()).await;
    assert_eq!(body, "captured data");
}

// ---------------------------------------------------------------------------
// 25. POST /execute_manual_attack - valid host and action
// ---------------------------------------------------------------------------

#[tokio::test]
async fn execute_manual_attack_with_valid_host() {
    let (state, _dir) = test_state().await;

    // Insert a host so the handler can find it
    state
        .kb
        .upsert_host("aa:bb:cc:dd:ee:10", "10.0.0.10", Some("target"), true, "22")
        .await
        .unwrap();

    let app = build_router(Arc::clone(&state));

    // Use SSHBruteforce which is a known action name in the registry.
    // It will fail (no ssh binary / target), but the handler should still
    // return 200 with status "error" (ActionOutcome::Failed).
    let req = Request::builder()
        .method("POST")
        .uri("/execute_manual_attack")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"ip": "10.0.0.10", "port": 22, "action": "SSHBruteforce"}"#,
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    // The action will fail because ssh tools aren't available in test,
    // but the handler itself should succeed (returns 200 either way).
    assert!(
        json["status"].is_string(),
        "response should have a status field"
    );
    assert!(
        json["message"].is_string(),
        "response should have a message field"
    );
}

// ---------------------------------------------------------------------------
// 26. POST /execute_manual_attack - invalid action name
// ---------------------------------------------------------------------------

#[tokio::test]
async fn execute_manual_attack_with_invalid_action() {
    let (state, _dir) = test_state().await;

    state
        .kb
        .upsert_host("aa:bb:cc:dd:ee:10", "10.0.0.10", None, true, "22")
        .await
        .unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/execute_manual_attack")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"ip": "10.0.0.10", "port": 22, "action": "NonExistentAction"}"#,
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "error");
    assert!(
        json["message"].as_str().unwrap().contains("not found"),
        "error message should mention action not found"
    );
}

// ---------------------------------------------------------------------------
// 27. POST /execute_manual_attack - unknown IP returns 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn execute_manual_attack_with_unknown_ip() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/execute_manual_attack")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"ip": "192.168.99.99", "port": 22, "action": "SSHBruteforce"}"#,
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "error");
    assert!(
        json["message"].as_str().unwrap().contains("no host found"),
        "error message should mention no host found"
    );
}

// ---------------------------------------------------------------------------
// 28. POST /save_config - llm_api_key should be blocked
// ---------------------------------------------------------------------------

#[tokio::test]
async fn save_config_blocks_llm_api_key() {
    let (state, _dir) = test_state().await;

    // Ensure default has no API key
    assert!(state.config().llm_api_key.is_empty());

    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/save_config")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"llm_api_key": "sk-secret-key-12345"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "success");

    // The llm_api_key should NOT have been updated (it's a blocked key)
    assert!(
        state.config().llm_api_key.is_empty(),
        "llm_api_key should remain empty because it is a blocked field"
    );
}

// ---------------------------------------------------------------------------
// 29. GET /api/tools/vulnerabilities - returns data when vulns exist
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_tools_vulnerabilities_returns_empty_json() {
    let (state, _dir) = test_state().await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/tools/vulnerabilities")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("application/json"));

    let body = body_string(resp.into_body()).await;
    let _json: serde_json::Value = serde_json::from_str(&body).unwrap();
}

#[tokio::test]
async fn api_tools_vulnerabilities_returns_data() {
    let (state, _dir) = test_state().await;

    // Insert a host and a vulnerability
    let host_id = state
        .kb
        .upsert_host(
            "aa:bb:cc:dd:ee:20",
            "10.0.0.20",
            Some("vuln-target"),
            true,
            "22;80",
        )
        .await
        .unwrap();

    state
        .kb
        .store_vulnerability(host_id, 22, "CVE-2024-9999 OpenSSH RCE", Some("CRITICAL"))
        .await
        .unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/tools/vulnerabilities")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp.into_body()).await;
    assert!(
        body.contains("CVE-2024-9999"),
        "response should contain the vulnerability CVE ID"
    );
    assert!(
        body.contains("CRITICAL"),
        "response should contain the severity"
    );
}
