use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::config::{BjornConfig, PathConfig};
use crate::state::KnowledgeBase;

/// Central shared state for the entire application.
///
/// Replaces Python's `SharedData` singleton with properly synchronized fields.
/// All access goes through `Arc<AppState>` — never cloned, always shared.
#[derive(Debug)]
pub struct AppState {
    /// Runtime configuration. Uses `ArcSwap` for lock-free reads + atomic swap on config change.
    pub config: ArcSwap<BjornConfig>,

    /// All filesystem paths.
    pub paths: PathConfig,

    /// Orchestrator status (what Bjorn is currently doing).
    pub status: RwLock<OrchestratorStatus>,

    /// Display-related data (text, stats) read by the display thread.
    pub display: RwLock<DisplayData>,

    /// SQLite knowledge base.
    pub kb: KnowledgeBase,

    /// Cancellation token for graceful shutdown.
    pub shutdown: CancellationToken,
}

impl AppState {
    /// Create a new `AppState` with the given config, paths, and knowledge base.
    pub fn new(config: BjornConfig, paths: PathConfig, kb: KnowledgeBase) -> Arc<Self> {
        Arc::new(Self {
            config: ArcSwap::from_pointee(config),
            paths,
            status: RwLock::new(OrchestratorStatus::default()),
            display: RwLock::new(DisplayData::default()),
            kb,
            shutdown: CancellationToken::new(),
        })
    }

    /// Hot-reload config from disk.
    pub fn reload_config(&self) {
        let new_config = BjornConfig::load_or_default(&self.paths.shared_config_json);
        self.config.store(Arc::new(new_config));
        tracing::info!("config reloaded");
    }

    /// Read current config (lock-free).
    pub fn config(&self) -> arc_swap::Guard<Arc<BjornConfig>> {
        self.config.load()
    }
}

/// What the orchestrator is currently doing.
#[derive(Debug, Clone, Default)]
pub struct OrchestratorStatus {
    /// Current action name (e.g. "NetworkScanner", "IDLE", "SshConnector").
    pub current_action: String,

    /// Secondary status text (e.g. target IP).
    pub detail: String,

    /// Whether the orchestrator is in manual (paused) mode.
    pub manual_mode: bool,

    /// Signal for the orchestrator to stop.
    pub should_exit: bool,
}

/// Data consumed by the display thread for rendering.
#[derive(Debug, Clone, Default)]
pub struct DisplayData {
    /// Status text shown on screen.
    pub status_text: String,

    /// What Bjorn "says" (comment bubble).
    pub bjorn_says: String,

    /// Whether WiFi is connected.
    pub wifi_connected: bool,

    /// Whether Bluetooth is active.
    pub bluetooth_active: bool,

    /// Whether USB is active.
    pub usb_active: bool,

    // -- Stats --
    pub target_count: u32,
    pub port_count: u32,
    pub vuln_count: u32,
    pub cred_count: u32,
    pub data_count: u32,
    pub zombie_count: u32,
    pub coin_count: u32,
    pub level: u32,
    pub network_kb_count: u32,
    pub attack_count: u32,
}

impl DisplayData {
    /// Recalculate derived stats (coins, level) from base counters.
    /// Mirrors Python `SharedData.update_stats()`.
    pub fn update_stats(&mut self) {
        self.coin_count = self.network_kb_count * 5
            + self.cred_count * 5
            + self.data_count * 5
            + self.zombie_count * 10
            + self.attack_count * 5
            + self.vuln_count * 2;

        // Integer approximation of the Python formula
        self.level = (self.network_kb_count / 10)
            + (self.cred_count / 5)
            + (self.data_count / 10)
            + (self.zombie_count / 2)
            + self.attack_count
            + (self.vuln_count / 100);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_calculation() {
        let mut d = DisplayData::default();
        d.network_kb_count = 10;
        d.cred_count = 5;
        d.data_count = 3;
        d.zombie_count = 2;
        d.attack_count = 4;
        d.vuln_count = 100;
        d.update_stats();

        // coins = 10*5 + 5*5 + 3*5 + 2*10 + 4*5 + 100*2 = 50+25+15+20+20+200 = 330
        assert_eq!(d.coin_count, 330);
    }
}
