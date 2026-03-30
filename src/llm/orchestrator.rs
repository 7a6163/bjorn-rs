use std::sync::Arc;
use std::time::Duration;

use tokio::time::sleep;

use crate::state::AppState;

use super::bridge::LlmBridge;

/// LLM Orchestrator — integrates LLM decision-making into Bjorn's action loop.
///
/// Three modes (matching Python `llm_orchestrator.py`):
/// - `none`:       LLM has no role in scheduling (default)
/// - `advisor`:    LLM suggests 1 action per orchestrator cycle
/// - `autonomous`: LLM runs its own loop, making decisions independently
pub struct LlmOrchestrator {
    bridge: LlmBridge,
    state: Arc<AppState>,
}

impl LlmOrchestrator {
    pub fn new(state: Arc<AppState>) -> Self {
        let bridge = LlmBridge::new(Arc::clone(&state));
        Self { bridge, state }
    }

    /// Get the current LLM mode from config.
    fn mode(&self) -> String {
        self.state.config().llm_mode.clone()
    }

    /// Called by the orchestrator each cycle in `advisor` mode.
    /// Returns a suggested action name and target IP, or None.
    pub async fn advise(&self) -> Option<(String, String)> {
        if self.mode() != "advisor" || !self.bridge.is_enabled() {
            return None;
        }

        let suggestion = self.bridge.suggest_action().await?;
        tracing::info!(suggestion = %suggestion, "LLM advisor suggestion");

        // Parse the JSON response
        let parsed: serde_json::Value = serde_json::from_str(&suggestion).ok()?;
        let action = parsed.get("action")?.as_str()?.to_string();
        let target = parsed.get("target_ip")?.as_str()?.to_string();
        let reason = parsed
            .get("reason")
            .and_then(|r| r.as_str())
            .unwrap_or("no reason given");

        tracing::info!(
            action = %action,
            target = %target,
            reason = %reason,
            "LLM advisor recommends"
        );

        Some((action, target))
    }

    /// Run the autonomous LLM loop (separate task).
    /// The LLM continuously analyzes state and queues actions.
    pub async fn run_autonomous(&self) {
        if self.mode() != "autonomous" {
            return;
        }

        tracing::info!("LLM autonomous mode starting");

        loop {
            if self.state.shutdown.is_cancelled() {
                break;
            }

            if !self.bridge.is_enabled() {
                sleep(Duration::from_secs(30)).await;
                continue;
            }

            // Ask LLM to analyze and act
            let system = concat!(
                "You are Bjorn's autonomous tactical AI. ",
                "Analyze the current network state using available tools. ",
                "Decide the best next action and execute it using run_action. ",
                "Be strategic: prioritize high-value targets, avoid repeating failed attacks. ",
                "After executing an action, explain your reasoning briefly."
            );

            match self
                .bridge
                .complete(system, "Analyze current state and take action.", true)
                .await
            {
                Some(response) => {
                    tracing::info!(response = %response, "LLM autonomous decision");
                    // Update display with LLM's comment
                    let mut display = self.state.display.write().await;
                    // Truncate to fit e-Paper
                    display.bjorn_says = if response.len() > 80 {
                        format!("{}...", &response[..77])
                    } else {
                        response
                    };
                }
                None => {
                    tracing::debug!("LLM autonomous: no response");
                }
            }

            // Wait before next cycle
            let interval = self.state.config().scan_interval.max(60);
            tokio::select! {
                () = sleep(Duration::from_secs(interval)) => {}
                () = self.state.shutdown.cancelled() => break,
            }
        }

        tracing::info!("LLM autonomous mode stopped");
    }

    /// Generate a comment for the e-Paper display.
    pub async fn generate_comment(&self, status: &str) -> Option<String> {
        if !self.bridge.is_enabled() {
            return None;
        }
        self.bridge.generate_comment(status).await
    }
}
