use std::path::Path;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

/// Initialize the tracing/logging system.
///
/// Returns a guard that must be held for the lifetime of the program
/// to ensure all log messages are flushed to disk.
pub fn init(logs_dir: &Path, debug: bool) -> WorkerGuard {
    let level = if debug { "debug" } else { "info" };

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("bjorn={level},sqlx=warn")));

    // File appender with daily rotation
    let file_appender = tracing_appender::rolling::daily(logs_dir, "bjorn.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(true);

    let console_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .compact();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer)
        .init();

    guard
}
