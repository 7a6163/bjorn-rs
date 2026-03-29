mod actions;
mod config;
mod display;
mod error;
mod logging;
mod orchestrator;
mod state;
mod web;

use std::path::PathBuf;
use std::sync::Arc;

use tokio::signal;
use tokio::time::{sleep, Duration};

use config::{BjornConfig, PathConfig};
use state::{AppState, KnowledgeBase};

/// Check if WiFi is connected by reading the wlan0 interface state.
async fn is_wifi_connected() -> bool {
    // Try reading /sys/class/net/wlan0/operstate
    match tokio::fs::read_to_string("/sys/class/net/wlan0/operstate").await {
        Ok(state) => state.trim() == "up",
        Err(_) => {
            // Fallback: try nmcli
            let output = tokio::process::Command::new("nmcli")
                .args(["-t", "-f", "active", "dev", "wifi"])
                .output()
                .await;
            match output {
                Ok(o) => String::from_utf8_lossy(&o.stdout).contains("yes"),
                Err(_) => false,
            }
        }
    }
}

/// Get the MAC address of the local wireless interface.
async fn get_local_mac() -> Option<String> {
    for iface in &["wlan0", "eth0"] {
        let path = format!("/sys/class/net/{iface}/address");
        if let Ok(mac) = tokio::fs::read_to_string(&path).await {
            let mac = mac.trim().to_lowercase();
            if !mac.is_empty() {
                return Some(mac);
            }
        }
    }
    None
}

/// Wait for WiFi connectivity, respecting the shutdown signal.
async fn wait_for_wifi(state: &Arc<AppState>) {
    loop {
        if is_wifi_connected().await {
            let mut display = state.display.write().await;
            display.wifi_connected = true;
            tracing::info!("wifi connected");
            return;
        }
        tracing::info!("waiting for wifi connection...");
        tokio::select! {
            () = sleep(Duration::from_secs(5)) => {}
            () = state.shutdown.cancelled() => return,
        }
    }
}

/// Orchestrator task placeholder — will be implemented in Phase 4.
async fn orchestrator_task(state: Arc<AppState>) {
    let config = state.config();
    if config.startup_delay > 0 {
        tracing::info!(delay = config.startup_delay, "startup delay");
        tokio::select! {
            () = sleep(Duration::from_secs(config.startup_delay)) => {}
            () = state.shutdown.cancelled() => return,
        }
    }

    wait_for_wifi(&state).await;

    if state.shutdown.is_cancelled() {
        return;
    }

    tracing::info!("orchestrator starting");
    let orch = orchestrator::Orchestrator::new(Arc::clone(&state));
    orch.run().await;
}

/// Display task — renders to e-Paper HAT and saves PNG for web UI.
async fn display_task(state: Arc<AppState>) {
    display::run(state).await;
}

/// Web server task.
async fn web_task(state: Arc<AppState>) {
    let config = state.config();
    if !config.websrv {
        tracing::info!("web server disabled in config");
        return;
    }
    web::run(state).await;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Determine root directory: BJORN_ROOT env var or default
    let root = std::env::var("BJORN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/home/bjorn/Bjorn"));

    let paths = PathConfig::new(&root);
    paths.ensure_dirs()?;

    // Initialize logging (must happen before anything else that logs)
    let _log_guard = logging::init(&paths.logs_dir, true);

    tracing::info!(root = %root.display(), "bjorn starting");

    // Load config
    let mut config = BjornConfig::load_or_default(&paths.shared_config_json);

    // Auto-blacklist local MAC
    if let Some(mac) = get_local_mac().await {
        tracing::info!(mac = %mac, "local MAC address");
        config = config.with_mac_blacklisted(mac);
    }

    // Save config (ensures file exists with all fields)
    config.save(&paths.shared_config_json)?;

    // Open knowledge base
    let kb = KnowledgeBase::open(&paths.netkb_db).await?;
    tracing::info!("knowledge base opened");

    // Build shared state
    let state = AppState::new(config, paths, kb);

    // Spawn the three main tasks
    let orchestrator_handle = tokio::spawn(orchestrator_task(Arc::clone(&state)));
    let display_handle = tokio::spawn(display_task(Arc::clone(&state)));
    let web_handle = tokio::spawn(web_task(Arc::clone(&state)));

    // Wait for shutdown signal (Ctrl+C or SIGTERM)
    tokio::select! {
        result = signal::ctrl_c() => {
            result?;
            tracing::info!("received SIGINT, shutting down");
        }
        () = async {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM handler");
            sigterm.recv().await;
        } => {
            tracing::info!("received SIGTERM, shutting down");
        }
    }

    // Trigger graceful shutdown
    state.shutdown.cancel();

    // Wait for all tasks to finish
    let _ = tokio::join!(orchestrator_handle, display_handle, web_handle);
    tracing::info!("bjorn stopped");

    Ok(())
}
