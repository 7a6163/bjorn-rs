use std::path::PathBuf;

/// All error variants that Bjorn can produce.
#[derive(Debug, thiserror::Error)]
pub enum BjornError {
    #[error("config error: {0}")]
    Config(String),

    #[error("config file not found: {path}")]
    ConfigNotFound { path: PathBuf },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("network error: {0}")]
    Network(String),

    #[error("action error: {action}: {message}")]
    Action { action: String, message: String },

    #[error("display error: {0}")]
    Display(String),

    #[error("wifi not connected")]
    WifiNotConnected,
}

pub type Result<T> = std::result::Result<T, BjornError>;
