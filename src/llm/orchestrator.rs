use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
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

// -- Pure functions: parsing, truncation, mode checks --

/// Parse a JSON advisor suggestion into (action, target_ip, reason).
/// Returns `None` if the JSON is invalid or missing required fields.
pub fn parse_advisor_suggestion(suggestion: &str) -> Option<(String, String, String)> {
    let parsed: Value = serde_json::from_str(suggestion).ok()?;
    let action = parsed.get("action")?.as_str()?.to_string();
    let target = parsed.get("target_ip")?.as_str()?.to_string();
    let reason = parsed
        .get("reason")
        .and_then(|r| r.as_str())
        .unwrap_or("no reason given")
        .to_string();
    Some((action, target, reason))
}

/// Truncate a string to fit the e-Paper display (max 80 chars).
/// Appends "..." if truncated.
pub fn truncate_for_display(text: &str, max_len: usize) -> String {
    if text.len() > max_len {
        format!("{}...", &text[..max_len.saturating_sub(3)])
    } else {
        text.to_string()
    }
}

/// Check whether advisor mode should be active given the mode string and enabled flag.
pub fn should_advise(mode: &str, llm_enabled: bool) -> bool {
    mode == "advisor" && llm_enabled
}

/// Check whether autonomous mode should be active given the mode string.
pub fn is_autonomous(mode: &str) -> bool {
    mode == "autonomous"
}

impl LlmOrchestrator {
    pub fn new(state: Arc<AppState>) -> Option<Self> {
        let bridge = LlmBridge::new(Arc::clone(&state))?;
        Some(Self { bridge, state })
    }

    /// Get the current LLM mode from config.
    fn mode(&self) -> String {
        self.state.config().llm_mode.clone()
    }

    /// Called by the orchestrator each cycle in `advisor` mode.
    /// Returns a suggested action name and target IP, or None.
    pub async fn advise(&self) -> Option<(String, String)> {
        if !should_advise(&self.mode(), self.bridge.is_enabled()) {
            return None;
        }

        let suggestion = self.bridge.suggest_action().await?;
        tracing::info!(suggestion = %suggestion, "LLM advisor suggestion");

        let (action, target, reason) = parse_advisor_suggestion(&suggestion)?;

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
        if !is_autonomous(&self.mode()) {
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
                    let mut display = self.state.display.write().await;
                    display.bjorn_says = truncate_for_display(&response, 80);
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

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_advisor_suggestion --

    #[test]
    fn parse_suggestion_valid_json() {
        let json =
            r#"{"action": "SshBruteForce", "target_ip": "192.168.1.5", "reason": "open port 22"}"#;
        let (action, target, reason) = parse_advisor_suggestion(json).unwrap();
        assert_eq!(action, "SshBruteForce");
        assert_eq!(target, "192.168.1.5");
        assert_eq!(reason, "open port 22");
    }

    #[test]
    fn parse_suggestion_missing_reason_uses_default() {
        let json = r#"{"action": "NmapScan", "target_ip": "10.0.0.1"}"#;
        let (action, target, reason) = parse_advisor_suggestion(json).unwrap();
        assert_eq!(action, "NmapScan");
        assert_eq!(target, "10.0.0.1");
        assert_eq!(reason, "no reason given");
    }

    #[test]
    fn parse_suggestion_missing_action_returns_none() {
        let json = r#"{"target_ip": "10.0.0.1"}"#;
        assert!(parse_advisor_suggestion(json).is_none());
    }

    #[test]
    fn parse_suggestion_missing_target_returns_none() {
        let json = r#"{"action": "NmapScan"}"#;
        assert!(parse_advisor_suggestion(json).is_none());
    }

    #[test]
    fn parse_suggestion_invalid_json_returns_none() {
        assert!(parse_advisor_suggestion("not json").is_none());
        assert!(parse_advisor_suggestion("").is_none());
    }

    #[test]
    fn parse_suggestion_action_not_string_returns_none() {
        let json = r#"{"action": 42, "target_ip": "10.0.0.1"}"#;
        assert!(parse_advisor_suggestion(json).is_none());
    }

    // -- truncate_for_display --

    #[test]
    fn truncate_short_text_unchanged() {
        assert_eq!(truncate_for_display("hello", 80), "hello");
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        let text = "a".repeat(80);
        assert_eq!(truncate_for_display(&text, 80), text);
    }

    #[test]
    fn truncate_long_text_adds_ellipsis() {
        let text = "a".repeat(100);
        let result = truncate_for_display(&text, 80);
        assert_eq!(result.len(), 80);
        assert!(result.ends_with("..."));
        assert_eq!(&result[..77], &"a".repeat(77));
    }

    #[test]
    fn truncate_empty_string() {
        assert_eq!(truncate_for_display("", 80), "");
    }

    #[test]
    fn truncate_very_small_max() {
        let result = truncate_for_display("hello world", 5);
        assert_eq!(result, "he...");
    }

    // -- should_advise --

    #[test]
    fn should_advise_true_when_advisor_and_enabled() {
        assert!(should_advise("advisor", true));
    }

    #[test]
    fn should_advise_false_when_not_advisor() {
        assert!(!should_advise("none", true));
        assert!(!should_advise("autonomous", true));
    }

    #[test]
    fn should_advise_false_when_not_enabled() {
        assert!(!should_advise("advisor", false));
    }

    // -- is_autonomous --

    #[test]
    fn is_autonomous_true() {
        assert!(is_autonomous("autonomous"));
    }

    #[test]
    fn is_autonomous_false() {
        assert!(!is_autonomous("none"));
        assert!(!is_autonomous("advisor"));
        assert!(!is_autonomous(""));
    }
}
