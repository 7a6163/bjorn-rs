use std::sync::Arc;

use axum::Router;
use axum::response::Redirect;
use axum::routing::{get, post};
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;

use crate::state::AppState;

use super::handlers;

/// Build the Axum router with all routes.
fn build_router(state: Arc<AppState>) -> Router {
    // Static file fallback: serves $BJORN_ROOT so that /web/images/... resolves
    // to $BJORN_ROOT/web/images/... (matches Python's SimpleHTTPRequestHandler
    // which serves from the Bjorn root directory).
    let static_files = ServeDir::new(&state.paths.root);

    Router::new()
        // -- Root redirect to index.html (matches Python's GET /) --
        .route("/", get(|| async { Redirect::temporary("/web/index.html") }))
        // -- GET API routes --
        .route("/load_config", get(handlers::load_config))
        .route(
            "/restore_default_config",
            get(handlers::restore_default_config),
        )
        .route("/get_web_delay", get(handlers::get_web_delay))
        .route("/scan_wifi", get(handlers::scan_wifi))
        .route("/network_data", get(handlers::network_data))
        .route("/netkb_data", get(handlers::netkb_data))
        .route("/netkb_data_json", get(handlers::netkb_data_json))
        .route("/screen.png", get(handlers::screen_image))
        .route("/get_logs", get(handlers::get_logs))
        .route("/list_credentials", get(handlers::list_credentials))
        .route("/list_files", get(handlers::list_files))
        .route("/download_file", get(handlers::download_file))
        .route("/download_backup", get(handlers::download_backup))
        // -- POST API routes --
        .route("/save_config", post(handlers::save_config))
        .route("/connect_wifi", post(handlers::connect_wifi))
        .route("/disconnect_wifi", post(handlers::disconnect_wifi))
        .route("/clear_files", post(handlers::clear_files))
        .route("/clear_files_light", post(handlers::clear_files_light))
        .route("/reboot", post(handlers::reboot_system))
        .route("/shutdown", post(handlers::shutdown_system))
        .route(
            "/restart_bjorn_service",
            post(handlers::restart_bjorn_service),
        )
        .route("/backup", post(handlers::create_backup))
        .route("/restore", post(handlers::restore_backup))
        .route("/execute_manual_attack", post(handlers::execute_manual_attack))
        .route("/stop_orchestrator", post(handlers::stop_orchestrator))
        .route("/start_orchestrator", post(handlers::start_orchestrator))
        // -- LLM API routes --
        .route("/api/llm/chat", post(handlers::llm_chat))
        .route("/api/llm/status", get(handlers::llm_status))
        // -- Tool/MCP-compatible routes --
        .route("/api/tools/hosts", get(handlers::api_get_hosts))
        .route(
            "/api/tools/vulnerabilities",
            get(handlers::api_get_vulnerabilities),
        )
        .route("/api/tools/credentials", get(handlers::api_get_credentials))
        .route("/api/tools/status", get(handlers::api_get_status))
        // -- Sentinel routes --
        .route("/api/sentinel/alerts", get(handlers::sentinel_alerts))
        // -- Middleware --
        .layer(CompressionLayer::new())
        // -- Shared state --
        .with_state(state)
        // -- Fallback: serve static files from web/ --
        .fallback_service(static_files)
}

/// Start the web server on port 8000.
pub async fn run(state: Arc<AppState>) {
    let app = build_router(state);
    let listener = match tokio::net::TcpListener::bind("0.0.0.0:8000").await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(%e, "failed to bind web server to port 8000");
            return;
        }
    };

    tracing::info!(port = 8000, "web server listening");

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!(%e, "web server error");
    }
}
