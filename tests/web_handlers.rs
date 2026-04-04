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
