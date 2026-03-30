use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde_json::{json, Value};

use crate::config::BjornConfig;
use crate::state::AppState;

use super::tools;

/// LLM backend cascade: Ollama -> External API (Anthropic/OpenAI) -> None.
///
/// Ports the Python `llm_bridge.py` with the same 3-tier fallback strategy.
/// All methods are async and thread-safe via shared `AppState`.
pub struct LlmBridge {
    client: Client,
    state: Arc<AppState>,
}

/// Which backend successfully handled the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmBackend {
    Ollama,
    AnthropicApi,
    OpenAiCompat,
    None,
}

impl LlmBridge {
    pub fn new(state: Arc<AppState>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("failed to build HTTP client");

        Self { client, state }
    }

    /// Check if LLM is enabled in config.
    pub fn is_enabled(&self) -> bool {
        self.state.config().llm_enabled
    }

    /// Generate a completion using the cascade: Ollama -> API -> None.
    /// Supports agentic tool-calling for Anthropic API.
    pub async fn complete(
        &self,
        system: &str,
        user_message: &str,
        use_tools: bool,
    ) -> Option<String> {
        if !self.is_enabled() {
            return None;
        }

        let config = self.state.config();
        let messages = vec![json!({"role": "user", "content": user_message})];

        // 1. Try Ollama
        if let Some(response) = self.call_ollama(&config, &messages, system).await {
            tracing::debug!(backend = "ollama", "LLM response received");
            return Some(response);
        }

        // 2. Try External API
        let api_key = &config.llm_api_key;
        if !api_key.is_empty() {
            let provider = &config.llm_api_provider;
            let result = match provider.as_str() {
                "anthropic" => {
                    self.call_anthropic(&config, &messages, system, use_tools)
                        .await
                }
                _ => self.call_openai_compat(&config, &messages, system).await,
            };
            if let Some(response) = result {
                tracing::debug!(backend = %provider, "LLM response received");
                return Some(response);
            }
        }

        // 3. None — caller falls back to templates
        tracing::debug!("all LLM backends failed, returning None");
        None
    }

    /// Generate a Bjorn comment for the e-Paper display.
    pub async fn generate_comment(&self, status: &str) -> Option<String> {
        let system = concat!(
            "You are Bjorn, a Viking cyber warrior. ",
            "Generate a short, fun comment (max 50 chars) about what you're doing. ",
            "Be creative and use Viking/hacker themed language."
        );
        let prompt = format!("Current status: {status}. Generate a comment.");
        self.complete(system, &prompt, false).await
    }

    /// Ask the LLM to suggest the next action based on current state.
    pub async fn suggest_action(&self) -> Option<String> {
        let system = concat!(
            "You are Bjorn's tactical advisor. Based on the current network state, ",
            "suggest the single best action to execute next. ",
            "Respond with ONLY a JSON object: {\"action\": \"ActionName\", \"target_ip\": \"x.x.x.x\", \"reason\": \"...\"}"
        );
        let prompt = "Analyze the current network state and suggest the next action.";
        self.complete(system, prompt, true).await
    }

    // -- Backend implementations --

    /// Call Ollama /api/chat endpoint.
    async fn call_ollama(
        &self,
        config: &BjornConfig,
        messages: &[Value],
        system: &str,
    ) -> Option<String> {
        let base_url = &config.llm_ollama_url;
        if base_url.is_empty() {
            return None;
        }

        let url = format!("{}/api/chat", base_url.trim_end_matches('/'));
        let model = &config.llm_ollama_model;

        let mut ollama_messages = vec![json!({"role": "system", "content": system})];
        ollama_messages.extend_from_slice(messages);

        let payload = json!({
            "model": model,
            "messages": ollama_messages,
            "stream": false,
            "options": { "num_predict": config.llm_max_tokens }
        });

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .timeout(Duration::from_secs(config.llm_timeout))
            .send()
            .await
            .ok()?;

        let body: Value = response.json().await.ok()?;
        body.get("message")?.get("content")?.as_str().map(String::from)
    }

    /// Call Anthropic Messages API with agentic tool-calling loop (max 6 rounds).
    async fn call_anthropic(
        &self,
        config: &BjornConfig,
        messages: &[Value],
        system: &str,
        use_tools: bool,
    ) -> Option<String> {
        let api_key = &config.llm_api_key;
        let model = &config.llm_api_model;
        let base_url = if config.llm_api_base_url.is_empty() {
            "https://api.anthropic.com"
        } else {
            &config.llm_api_base_url
        };
        let url = format!("{}/v1/messages", base_url.trim_end_matches('/'));

        let tool_defs = if use_tools {
            Some(tools::tool_definitions())
        } else {
            None
        };

        let mut current_messages: Vec<Value> = messages.to_vec();

        for _round in 0..6 {
            let mut payload = json!({
                "model": model,
                "max_tokens": config.llm_max_tokens,
                "messages": current_messages,
                "system": system,
            });

            if let Some(ref tools) = tool_defs {
                payload["tools"] = json!(tools);
            }

            let response = self
                .client
                .post(&url)
                .header("x-api-key", api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&payload)
                .timeout(Duration::from_secs(config.llm_timeout))
                .send()
                .await
                .ok()?;

            let body: Value = response.json().await.ok()?;
            let stop_reason = body.get("stop_reason")?.as_str()?;
            let content = body.get("content")?.as_array()?;

            if stop_reason != "tool_use" || tool_defs.is_none() {
                // Final text response
                for block in content {
                    if block.get("type")?.as_str()? == "text" {
                        return block.get("text")?.as_str().map(String::from);
                    }
                }
                return None;
            }

            // Tool use round — execute tools and feed results back
            current_messages.push(json!({"role": "assistant", "content": content}));

            let mut tool_results = Vec::new();
            for block in content {
                if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                    let tool_name = block.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let tool_input = block.get("input").cloned().unwrap_or(json!({}));
                    let tool_id = block.get("id").and_then(|i| i.as_str()).unwrap_or("");

                    let result = tools::execute_tool(tool_name, &tool_input, &self.state).await;
                    tracing::debug!(tool = %tool_name, result_len = result.len(), "tool executed");

                    tool_results.push(json!({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": result,
                    }));
                }
            }

            if tool_results.is_empty() {
                break;
            }
            current_messages.push(json!({"role": "user", "content": tool_results}));
        }

        None
    }

    /// Call OpenAI-compatible API (OpenAI, OpenRouter, etc.)
    async fn call_openai_compat(
        &self,
        config: &BjornConfig,
        messages: &[Value],
        system: &str,
    ) -> Option<String> {
        let api_key = &config.llm_api_key;
        let model = &config.llm_api_model;
        let base_url = if config.llm_api_base_url.is_empty() {
            "https://api.openai.com/v1"
        } else {
            &config.llm_api_base_url
        };
        let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));

        let mut all_messages = vec![json!({"role": "system", "content": system})];
        all_messages.extend_from_slice(messages);

        let payload = json!({
            "model": model,
            "messages": all_messages,
            "max_tokens": config.llm_max_tokens,
        });

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .json(&payload)
            .timeout(Duration::from_secs(config.llm_timeout))
            .send()
            .await
            .ok()?;

        let body: Value = response.json().await.ok()?;
        body.get("choices")?
            .get(0)?
            .get("message")?
            .get("content")?
            .as_str()
            .map(String::from)
    }
}
