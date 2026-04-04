use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{BjornError, Result};

/// Runtime configuration loaded from `shared_config.json`.
///
/// All fields map 1:1 to the Python `SharedData.get_default_config()`.
/// This struct is immutable once loaded; config changes produce a new instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BjornConfig {
    // -- Modes --
    #[serde(default)]
    pub manual_mode: bool,

    #[serde(default = "default_true")]
    pub websrv: bool,

    #[serde(default, alias = "web_increment ")]
    pub web_increment: bool,

    #[serde(default = "default_true")]
    pub debug_mode: bool,

    #[serde(default)]
    pub scan_vuln_running: bool,

    #[serde(default)]
    pub retry_success_actions: bool,

    #[serde(default = "default_true")]
    pub retry_failed_actions: bool,

    #[serde(default = "default_true")]
    pub blacklistcheck: bool,

    #[serde(default = "default_true")]
    pub displaying_csv: bool,

    // -- Log levels --
    #[serde(default = "default_true")]
    pub log_debug: bool,

    #[serde(default = "default_true")]
    pub log_info: bool,

    #[serde(default = "default_true")]
    pub log_warning: bool,

    #[serde(default = "default_true")]
    pub log_error: bool,

    #[serde(default = "default_true")]
    pub log_critical: bool,

    // -- Timing (seconds) --
    #[serde(default = "default_startup_delay")]
    pub startup_delay: u64,

    #[serde(default = "default_2")]
    pub web_delay: u64,

    #[serde(default = "default_1")]
    pub screen_delay: u64,

    #[serde(default = "default_15")]
    pub comment_delaymin: u64,

    #[serde(default = "default_30")]
    pub comment_delaymax: u64,

    #[serde(default = "default_8")]
    pub livestatus_delay: u64,

    #[serde(default = "default_2")]
    pub image_display_delaymin: u64,

    #[serde(default = "default_8")]
    pub image_display_delaymax: u64,

    #[serde(default = "default_scan_interval")]
    pub scan_interval: u64,

    #[serde(default = "default_vuln_interval")]
    pub scan_vuln_interval: u64,

    #[serde(default = "default_failed_retry")]
    pub failed_retry_delay: u64,

    #[serde(default = "default_success_retry")]
    pub success_retry_delay: u64,

    // -- Display --
    #[serde(default = "default_ref_width")]
    pub ref_width: u32,

    #[serde(default = "default_ref_height")]
    pub ref_height: u32,

    #[serde(default = "default_epd_type")]
    pub epd_type: String,

    // -- Lists --
    #[serde(default = "default_portlist")]
    pub portlist: Vec<u16>,

    #[serde(default)]
    pub mac_scan_blacklist: Vec<String>,

    #[serde(default)]
    pub ip_scan_blacklist: Vec<String>,

    #[serde(default = "default_steal_file_names")]
    pub steal_file_names: Vec<String>,

    #[serde(default = "default_steal_file_extensions")]
    pub steal_file_extensions: Vec<String>,

    // -- Network --
    #[serde(default = "default_nmap_aggressivity")]
    pub nmap_scan_aggressivity: String,

    #[serde(default = "default_1_u16")]
    pub portstart: u16,

    #[serde(default = "default_2_u16")]
    pub portend: u16,

    // -- Time waits (seconds) --
    #[serde(default)]
    pub timewait_smb: u64,

    #[serde(default)]
    pub timewait_ssh: u64,

    #[serde(default)]
    pub timewait_telnet: u64,

    #[serde(default)]
    pub timewait_ftp: u64,

    #[serde(default)]
    pub timewait_sql: u64,

    #[serde(default)]
    pub timewait_rdp: u64,

    // -- LLM --
    #[serde(default)]
    pub llm_enabled: bool,

    /// LLM orchestrator mode: "none", "advisor", "autonomous"
    #[serde(default = "default_llm_mode")]
    pub llm_mode: String,

    /// API provider: "anthropic", "openai", "openrouter"
    #[serde(default = "default_llm_provider")]
    pub llm_api_provider: String,

    #[serde(default, skip_serializing)]
    pub llm_api_key: String,

    #[serde(default = "default_llm_model")]
    pub llm_api_model: String,

    #[serde(default)]
    pub llm_api_base_url: String,

    #[serde(default = "default_ollama_url")]
    pub llm_ollama_url: String,

    #[serde(default = "default_ollama_model")]
    pub llm_ollama_model: String,

    /// Max tokens for LLM responses
    #[serde(default = "default_llm_max_tokens")]
    pub llm_max_tokens: u32,

    /// LLM request timeout in seconds
    #[serde(default = "default_llm_timeout")]
    pub llm_timeout: u64,

    // -- Sentinel --
    #[serde(default)]
    pub sentinel_enabled: bool,

    /// Sentinel check interval in seconds
    #[serde(default = "default_sentinel_interval")]
    pub sentinel_interval: u64,
}

impl BjornConfig {
    /// Load config from a JSON file, falling back to defaults for missing fields.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(BjornError::ConfigNotFound {
                path: path.to_path_buf(),
            });
        }
        let contents = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&contents)?;
        Ok(config)
    }

    /// Load config from file, or return defaults if file doesn't exist.
    pub fn load_or_default(path: &Path) -> Self {
        match Self::load(path) {
            Ok(config) => config,
            Err(e) => {
                tracing::warn!(%e, "failed to load config, using defaults");
                Self::default()
            }
        }
    }

    /// Save current config to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Create a new config with an updated MAC blacklist entry.
    pub fn with_mac_blacklisted(mut self, mac: String) -> Self {
        if !self.mac_scan_blacklist.contains(&mac) {
            self.mac_scan_blacklist.push(mac);
        }
        self
    }
}

impl Default for BjornConfig {
    fn default() -> Self {
        Self {
            manual_mode: false,
            websrv: true,
            web_increment: false,
            debug_mode: true,
            scan_vuln_running: false,
            retry_success_actions: false,
            retry_failed_actions: true,
            blacklistcheck: true,
            displaying_csv: true,
            log_debug: true,
            log_info: true,
            log_warning: true,
            log_error: true,
            log_critical: true,
            startup_delay: 10,
            web_delay: 2,
            screen_delay: 1,
            comment_delaymin: 15,
            comment_delaymax: 30,
            livestatus_delay: 8,
            image_display_delaymin: 2,
            image_display_delaymax: 8,
            scan_interval: 180,
            scan_vuln_interval: 900,
            failed_retry_delay: 600,
            success_retry_delay: 900,
            ref_width: 122,
            ref_height: 250,
            epd_type: "epd2in13_V4".to_string(),
            portlist: default_portlist(),
            mac_scan_blacklist: vec![],
            ip_scan_blacklist: vec![],
            steal_file_names: default_steal_file_names(),
            steal_file_extensions: default_steal_file_extensions(),
            nmap_scan_aggressivity: "-T2".to_string(),
            portstart: 1,
            portend: 2,
            timewait_smb: 0,
            timewait_ssh: 0,
            timewait_telnet: 0,
            timewait_ftp: 0,
            timewait_sql: 0,
            timewait_rdp: 0,
            llm_enabled: false,
            llm_mode: "none".to_string(),
            llm_api_provider: "anthropic".to_string(),
            llm_api_key: String::new(),
            llm_api_model: "claude-haiku-4-5-20251001".to_string(),
            llm_api_base_url: String::new(),
            llm_ollama_url: "http://127.0.0.1:11434".to_string(),
            llm_ollama_model: "phi3:mini".to_string(),
            llm_max_tokens: 1024,
            llm_timeout: 30,
            sentinel_enabled: false,
            sentinel_interval: 60,
        }
    }
}

// -- Serde default helpers --

fn default_true() -> bool {
    true
}
fn default_startup_delay() -> u64 {
    10
}
fn default_1() -> u64 {
    1
}
fn default_2() -> u64 {
    2
}
fn default_8() -> u64 {
    8
}
fn default_15() -> u64 {
    15
}
fn default_30() -> u64 {
    30
}
fn default_scan_interval() -> u64 {
    180
}
fn default_vuln_interval() -> u64 {
    900
}
fn default_failed_retry() -> u64 {
    600
}
fn default_success_retry() -> u64 {
    900
}
fn default_ref_width() -> u32 {
    122
}
fn default_ref_height() -> u32 {
    250
}
fn default_epd_type() -> String {
    "epd2in13_V4".to_string()
}
fn default_1_u16() -> u16 {
    1
}
fn default_2_u16() -> u16 {
    2
}

fn default_portlist() -> Vec<u16> {
    vec![
        20, 21, 22, 23, 25, 53, 69, 80, 110, 111, 135, 137, 139, 143, 161, 162, 389, 443, 445, 512,
        513, 514, 587, 636, 993, 995, 1080, 1433, 1521, 1883, 2049, 3306, 3389, 5000, 5001, 5432,
        5900, 6379, 8080, 8443, 9090, 10000, 11211, 27017,
    ]
}

fn default_nmap_aggressivity() -> String {
    "-T2".to_string()
}

fn default_steal_file_names() -> Vec<String> {
    vec!["ssh.csv".to_string(), "hack.txt".to_string()]
}

fn default_steal_file_extensions() -> Vec<String> {
    vec![
        ".bjorn".to_string(),
        ".hack".to_string(),
        ".flag".to_string(),
    ]
}

fn default_llm_mode() -> String {
    "none".to_string()
}
fn default_llm_provider() -> String {
    "anthropic".to_string()
}
fn default_llm_model() -> String {
    "claude-haiku-4-5-20251001".to_string()
}
fn default_ollama_url() -> String {
    "http://127.0.0.1:11434".to_string()
}
fn default_ollama_model() -> String {
    "phi3:mini".to_string()
}
fn default_llm_max_tokens() -> u32 {
    1024
}
fn default_llm_timeout() -> u64 {
    30
}
fn default_sentinel_interval() -> u64 {
    60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_python() {
        let config = BjornConfig::default();
        assert!(!config.manual_mode);
        assert!(config.websrv);
        assert!(config.retry_failed_actions);
        assert!(!config.retry_success_actions);
        assert_eq!(config.startup_delay, 10);
        assert_eq!(config.scan_interval, 180);
        assert_eq!(config.portlist.len(), 44);
        assert_eq!(config.epd_type, "epd2in13_V4");
        assert_eq!(config.nmap_scan_aggressivity, "-T2");
    }

    #[test]
    fn deserialize_from_json() {
        let json = r#"{
            "manual_mode": true,
            "startup_delay": 5,
            "portlist": [22, 80, 443]
        }"#;
        let config: BjornConfig = serde_json::from_str(json).unwrap();
        assert!(config.manual_mode);
        assert_eq!(config.startup_delay, 5);
        assert_eq!(config.portlist, vec![22, 80, 443]);
        // Defaults for missing fields
        assert!(config.websrv);
        assert_eq!(config.scan_interval, 180);
    }

    #[test]
    fn with_mac_blacklisted_is_idempotent() {
        let config = BjornConfig::default().with_mac_blacklisted("aa:bb:cc:dd:ee:ff".to_string());
        assert_eq!(config.mac_scan_blacklist.len(), 1);

        let config = config.with_mac_blacklisted("aa:bb:cc:dd:ee:ff".to_string());
        assert_eq!(config.mac_scan_blacklist.len(), 1);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");

        let original = BjornConfig::default().with_mac_blacklisted("11:22:33:44:55:66".to_string());
        original.save(&path).unwrap();

        let loaded = BjornConfig::load(&path).unwrap();
        assert_eq!(loaded.mac_scan_blacklist, original.mac_scan_blacklist);
        assert_eq!(loaded.startup_delay, original.startup_delay);
        assert_eq!(loaded.portlist.len(), original.portlist.len());
        assert_eq!(loaded.epd_type, original.epd_type);
    }

    #[test]
    fn load_missing_file_returns_error() {
        let result = BjornConfig::load(std::path::Path::new("/nonexistent/config.json"));
        assert!(result.is_err());
    }

    #[test]
    fn load_or_default_returns_defaults_for_missing_file() {
        let config = BjornConfig::load_or_default(std::path::Path::new("/nonexistent/config.json"));
        assert_eq!(config.startup_delay, 10);
        assert_eq!(config.portlist.len(), 44);
    }

    #[test]
    fn load_partial_json_uses_defaults_for_missing_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial.json");
        std::fs::write(&path, r#"{"manual_mode": true}"#).unwrap();

        let config = BjornConfig::load(&path).unwrap();
        assert!(config.manual_mode);
        assert_eq!(config.scan_interval, 180); // default
        assert!(config.websrv); // default
    }

    #[test]
    fn default_portlist_has_no_duplicates() {
        let ports = default_portlist();
        let mut unique = ports.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(ports.len(), unique.len());
    }
}
