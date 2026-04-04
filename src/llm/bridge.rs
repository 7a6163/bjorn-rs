use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde_json::{Value, json};

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

// -- Pure functions: request building, response parsing, config queries --

/// Check if LLM is enabled in the given config.
pub fn is_enabled(config: &BjornConfig) -> bool {
    config.llm_enabled
}

/// Determine which backends are available based on config.
pub fn available_backends(config: &BjornConfig) -> Vec<LlmBackend> {
    let mut backends = Vec::new();

    if !config.llm_ollama_url.is_empty() {
        backends.push(LlmBackend::Ollama);
    }

    if !config.llm_api_key.is_empty() {
        match config.llm_api_provider.as_str() {
            "anthropic" => backends.push(LlmBackend::AnthropicApi),
            _ => backends.push(LlmBackend::OpenAiCompat),
        }
    }

    backends
}

/// Build the Ollama `/api/chat` request payload.
pub fn build_ollama_request(
    config: &BjornConfig,
    messages: &[Value],
    system: &str,
) -> (String, Value) {
    let url = format!("{}/api/chat", config.llm_ollama_url.trim_end_matches('/'));

    let mut ollama_messages = vec![json!({"role": "system", "content": system})];
    ollama_messages.extend_from_slice(messages);

    let payload = json!({
        "model": config.llm_ollama_model,
        "messages": ollama_messages,
        "stream": false,
        "options": { "num_predict": config.llm_max_tokens }
    });

    (url, payload)
}

/// Parse the Ollama `/api/chat` response body to extract the text content.
pub fn parse_ollama_response(body: &Value) -> Option<String> {
    body.get("message")?
        .get("content")?
        .as_str()
        .map(String::from)
}

/// Resolve the Anthropic API base URL from config, applying the default.
pub fn resolve_anthropic_base_url(config: &BjornConfig) -> &str {
    if config.llm_api_base_url.is_empty() {
        "https://api.anthropic.com"
    } else {
        &config.llm_api_base_url
    }
}

/// Build an Anthropic Messages API request payload for a single round.
pub fn build_anthropic_request(
    config: &BjornConfig,
    messages: &[Value],
    system: &str,
    tool_defs: Option<&Vec<Value>>,
) -> (String, Value) {
    let base_url = resolve_anthropic_base_url(config);
    let url = format!("{}/v1/messages", base_url.trim_end_matches('/'));

    let mut payload = json!({
        "model": config.llm_api_model,
        "max_tokens": config.llm_max_tokens,
        "messages": messages,
        "system": system,
    });

    if let Some(tools) = tool_defs {
        payload["tools"] = json!(tools);
    }

    (url, payload)
}

/// Parse the Anthropic Messages API response body.
/// Returns `(stop_reason, content_blocks)` if present.
pub fn parse_anthropic_response(body: &Value) -> Option<(String, Vec<Value>)> {
    let stop_reason = body.get("stop_reason")?.as_str()?.to_string();
    let content = body.get("content")?.as_array()?.clone();
    Some((stop_reason, content))
}

/// Extract the first text block from Anthropic content blocks.
pub fn extract_text_from_anthropic_content(content: &[Value]) -> Option<String> {
    for block in content {
        let block_type = block.get("type").and_then(|t| t.as_str());
        if block_type == Some("text") {
            return block.get("text").and_then(|t| t.as_str()).map(String::from);
        }
    }
    None
}

/// Extract tool_use blocks from Anthropic content blocks.
/// Returns `(tool_name, tool_input, tool_id)` tuples.
pub fn extract_tool_calls(content: &[Value]) -> Vec<(String, Value, String)> {
    content
        .iter()
        .filter(|block| block.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
        .map(|block| {
            let name = block
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let input = block.get("input").cloned().unwrap_or(json!({}));
            let id = block
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            (name, input, id)
        })
        .collect()
}

/// Build a tool_result message for the Anthropic conversation.
pub fn build_tool_result_message(tool_id: &str, result: &str) -> Value {
    json!({
        "type": "tool_result",
        "tool_use_id": tool_id,
        "content": result,
    })
}

/// Resolve the OpenAI-compatible API base URL from config, applying the default.
pub fn resolve_openai_base_url(config: &BjornConfig) -> &str {
    if config.llm_api_base_url.is_empty() {
        "https://api.openai.com/v1"
    } else {
        &config.llm_api_base_url
    }
}

/// Build an OpenAI-compatible chat completions request payload.
pub fn build_openai_request(
    config: &BjornConfig,
    messages: &[Value],
    system: &str,
) -> (String, Value) {
    let base_url = resolve_openai_base_url(config);
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));

    let mut all_messages = vec![json!({"role": "system", "content": system})];
    all_messages.extend_from_slice(messages);

    let payload = json!({
        "model": config.llm_api_model,
        "messages": all_messages,
        "max_tokens": config.llm_max_tokens,
    });

    (url, payload)
}

/// Parse the OpenAI-compatible chat completions response body to extract text.
pub fn parse_openai_response(body: &Value) -> Option<String> {
    body.get("choices")?
        .get(0)?
        .get("message")?
        .get("content")?
        .as_str()
        .map(String::from)
}

// -- LlmBridge implementation (uses pure functions above + HTTP I/O) --

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
        is_enabled(&self.state.config())
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
        if config.llm_ollama_url.is_empty() {
            return None;
        }

        let (url, payload) = build_ollama_request(config, messages, system);

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .timeout(Duration::from_secs(config.llm_timeout))
            .send()
            .await
            .ok()?;

        let body: Value = response.json().await.ok()?;
        parse_ollama_response(&body)
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

        let tool_defs = if use_tools {
            Some(tools::tool_definitions())
        } else {
            None
        };

        let mut current_messages: Vec<Value> = messages.to_vec();

        for _round in 0..6 {
            let (url, payload) =
                build_anthropic_request(config, &current_messages, system, tool_defs.as_ref());

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
            let (stop_reason, content) = parse_anthropic_response(&body)?;

            if stop_reason != "tool_use" || tool_defs.is_none() {
                return extract_text_from_anthropic_content(&content);
            }

            // Tool use round — execute tools and feed results back
            current_messages.push(json!({"role": "assistant", "content": content}));

            let tool_calls = extract_tool_calls(
                current_messages
                    .last()
                    .unwrap()
                    .get("content")
                    .and_then(|c| c.as_array())
                    .map(|a| a.as_slice())
                    .unwrap_or(&[]),
            );

            if tool_calls.is_empty() {
                break;
            }

            let mut tool_results = Vec::new();
            for (tool_name, tool_input, tool_id) in &tool_calls {
                let result = tools::execute_tool(tool_name, tool_input, &self.state).await;
                tracing::debug!(tool = %tool_name, result_len = result.len(), "tool executed");
                tool_results.push(build_tool_result_message(tool_id, &result));
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
        let (url, payload) = build_openai_request(config, messages, system);

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
        parse_openai_response(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> BjornConfig {
        BjornConfig::default()
    }

    fn config_with(f: impl FnOnce(&mut BjornConfig)) -> BjornConfig {
        let mut cfg = default_config();
        f(&mut cfg);
        cfg
    }

    // -- is_enabled --

    #[test]
    fn is_enabled_returns_false_by_default() {
        let cfg = default_config();
        assert!(!is_enabled(&cfg));
    }

    #[test]
    fn is_enabled_returns_true_when_set() {
        let cfg = config_with(|c| c.llm_enabled = true);
        assert!(is_enabled(&cfg));
    }

    // -- available_backends --

    #[test]
    fn available_backends_default_has_ollama_and_no_api() {
        // Default config has ollama_url set but empty api_key
        let cfg = default_config();
        let backends = available_backends(&cfg);
        assert_eq!(backends, vec![LlmBackend::Ollama]);
    }

    #[test]
    fn available_backends_with_anthropic_key() {
        let cfg = config_with(|c| {
            c.llm_api_key = "sk-ant-test".to_string();
            c.llm_api_provider = "anthropic".to_string();
        });
        let backends = available_backends(&cfg);
        assert!(backends.contains(&LlmBackend::Ollama));
        assert!(backends.contains(&LlmBackend::AnthropicApi));
    }

    #[test]
    fn available_backends_with_openai_key() {
        let cfg = config_with(|c| {
            c.llm_api_key = "sk-test".to_string();
            c.llm_api_provider = "openai".to_string();
        });
        let backends = available_backends(&cfg);
        assert!(backends.contains(&LlmBackend::OpenAiCompat));
        assert!(!backends.contains(&LlmBackend::AnthropicApi));
    }

    #[test]
    fn available_backends_empty_ollama_url() {
        let cfg = config_with(|c| c.llm_ollama_url = String::new());
        let backends = available_backends(&cfg);
        assert!(!backends.contains(&LlmBackend::Ollama));
    }

    #[test]
    fn available_backends_no_backends() {
        let cfg = config_with(|c| {
            c.llm_ollama_url = String::new();
            c.llm_api_key = String::new();
        });
        let backends = available_backends(&cfg);
        assert!(backends.is_empty());
    }

    // -- build_ollama_request --

    #[test]
    fn build_ollama_request_correct_url_and_payload() {
        let cfg = default_config();
        let messages = vec![json!({"role": "user", "content": "hello"})];
        let (url, payload) = build_ollama_request(&cfg, &messages, "system prompt");

        assert_eq!(url, "http://127.0.0.1:11434/api/chat");
        assert_eq!(payload["model"], "phi3:mini");
        assert_eq!(payload["stream"], false);
        assert_eq!(payload["options"]["num_predict"], 1024);

        let msgs = payload["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "system prompt");
        assert_eq!(msgs[1]["role"], "user");
        assert_eq!(msgs[1]["content"], "hello");
    }

    #[test]
    fn build_ollama_request_strips_trailing_slash() {
        let cfg = config_with(|c| c.llm_ollama_url = "http://localhost:11434/".to_string());
        let (url, _) = build_ollama_request(&cfg, &[], "sys");
        assert_eq!(url, "http://localhost:11434/api/chat");
    }

    // -- parse_ollama_response --

    #[test]
    fn parse_ollama_response_extracts_content() {
        let body = json!({
            "model": "phi3:mini",
            "message": { "role": "assistant", "content": "Hello Viking!" },
            "done": true
        });
        assert_eq!(
            parse_ollama_response(&body),
            Some("Hello Viking!".to_string())
        );
    }

    #[test]
    fn parse_ollama_response_returns_none_on_missing_message() {
        let body = json!({"error": "model not found"});
        assert_eq!(parse_ollama_response(&body), None);
    }

    #[test]
    fn parse_ollama_response_returns_none_on_missing_content() {
        let body = json!({"message": {"role": "assistant"}});
        assert_eq!(parse_ollama_response(&body), None);
    }

    // -- build_anthropic_request --

    #[test]
    fn build_anthropic_request_default_url() {
        let cfg = config_with(|c| c.llm_api_key = "key".to_string());
        let messages = vec![json!({"role": "user", "content": "hi"})];
        let (url, payload) = build_anthropic_request(&cfg, &messages, "sys", None);

        assert_eq!(url, "https://api.anthropic.com/v1/messages");
        assert_eq!(payload["system"], "sys");
        assert_eq!(payload["max_tokens"], 1024);
        assert!(payload.get("tools").is_none());
    }

    #[test]
    fn build_anthropic_request_custom_base_url() {
        let cfg = config_with(|c| {
            c.llm_api_base_url = "https://custom.api.com/".to_string();
        });
        let (url, _) = build_anthropic_request(&cfg, &[], "sys", None);
        assert_eq!(url, "https://custom.api.com/v1/messages");
    }

    #[test]
    fn build_anthropic_request_includes_tools() {
        let cfg = default_config();
        let tool_defs = vec![json!({"name": "test_tool"})];
        let (_, payload) = build_anthropic_request(&cfg, &[], "sys", Some(&tool_defs));
        assert_eq!(payload["tools"][0]["name"], "test_tool");
    }

    // -- parse_anthropic_response --

    #[test]
    fn parse_anthropic_response_success() {
        let body = json!({
            "stop_reason": "end_turn",
            "content": [
                {"type": "text", "text": "Hello from Claude!"}
            ]
        });
        let (stop_reason, content) = parse_anthropic_response(&body).unwrap();
        assert_eq!(stop_reason, "end_turn");
        assert_eq!(content.len(), 1);
    }

    #[test]
    fn parse_anthropic_response_tool_use() {
        let body = json!({
            "stop_reason": "tool_use",
            "content": [
                {"type": "text", "text": "Let me check..."},
                {"type": "tool_use", "id": "toolu_1", "name": "get_hosts", "input": {}}
            ]
        });
        let (stop_reason, content) = parse_anthropic_response(&body).unwrap();
        assert_eq!(stop_reason, "tool_use");
        assert_eq!(content.len(), 2);
    }

    #[test]
    fn parse_anthropic_response_returns_none_on_missing_fields() {
        assert!(parse_anthropic_response(&json!({})).is_none());
        assert!(parse_anthropic_response(&json!({"stop_reason": "end_turn"})).is_none());
        assert!(parse_anthropic_response(&json!({"content": []})).is_none());
    }

    // -- extract_text_from_anthropic_content --

    #[test]
    fn extract_text_finds_first_text_block() {
        let content = vec![
            json!({"type": "text", "text": "first"}),
            json!({"type": "text", "text": "second"}),
        ];
        assert_eq!(
            extract_text_from_anthropic_content(&content),
            Some("first".to_string())
        );
    }

    #[test]
    fn extract_text_skips_non_text_blocks() {
        let content = vec![
            json!({"type": "tool_use", "name": "get_hosts", "id": "1", "input": {}}),
            json!({"type": "text", "text": "result"}),
        ];
        assert_eq!(
            extract_text_from_anthropic_content(&content),
            Some("result".to_string())
        );
    }

    #[test]
    fn extract_text_returns_none_when_no_text() {
        let content =
            vec![json!({"type": "tool_use", "name": "get_hosts", "id": "1", "input": {}})];
        assert_eq!(extract_text_from_anthropic_content(&content), None);
    }

    #[test]
    fn extract_text_returns_none_on_empty() {
        assert_eq!(extract_text_from_anthropic_content(&[]), None);
    }

    // -- extract_tool_calls --

    #[test]
    fn extract_tool_calls_parses_tool_use_blocks() {
        let content = vec![
            json!({"type": "text", "text": "Checking..."}),
            json!({
                "type": "tool_use",
                "id": "toolu_abc",
                "name": "get_hosts",
                "input": {"alive_only": true}
            }),
            json!({
                "type": "tool_use",
                "id": "toolu_def",
                "name": "get_vulnerabilities",
                "input": {"host_ip": "192.168.1.1"}
            }),
        ];
        let calls = extract_tool_calls(&content);
        assert_eq!(calls.len(), 2);

        assert_eq!(calls[0].0, "get_hosts");
        assert_eq!(calls[0].1, json!({"alive_only": true}));
        assert_eq!(calls[0].2, "toolu_abc");

        assert_eq!(calls[1].0, "get_vulnerabilities");
        assert_eq!(calls[1].2, "toolu_def");
    }

    #[test]
    fn extract_tool_calls_returns_empty_when_no_tools() {
        let content = vec![json!({"type": "text", "text": "done"})];
        assert!(extract_tool_calls(&content).is_empty());
    }

    #[test]
    fn extract_tool_calls_handles_missing_fields_gracefully() {
        let content = vec![json!({"type": "tool_use"})];
        let calls = extract_tool_calls(&content);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "");
        assert_eq!(calls[0].1, json!({}));
        assert_eq!(calls[0].2, "");
    }

    // -- build_tool_result_message --

    #[test]
    fn build_tool_result_message_structure() {
        let msg = build_tool_result_message("toolu_123", "some result");
        assert_eq!(msg["type"], "tool_result");
        assert_eq!(msg["tool_use_id"], "toolu_123");
        assert_eq!(msg["content"], "some result");
    }

    // -- build_openai_request --

    #[test]
    fn build_openai_request_default_url() {
        let cfg = config_with(|c| c.llm_api_key = "key".to_string());
        let messages = vec![json!({"role": "user", "content": "hi"})];
        let (url, payload) = build_openai_request(&cfg, &messages, "system text");

        assert_eq!(url, "https://api.openai.com/v1/chat/completions");
        assert_eq!(payload["max_tokens"], 1024);

        let msgs = payload["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "system text");
        assert_eq!(msgs[1]["role"], "user");
    }

    #[test]
    fn build_openai_request_custom_base_url() {
        let cfg = config_with(|c| {
            c.llm_api_base_url = "https://openrouter.ai/api/v1".to_string();
        });
        let (url, _) = build_openai_request(&cfg, &[], "sys");
        assert_eq!(url, "https://openrouter.ai/api/v1/chat/completions");
    }

    // -- parse_openai_response --

    #[test]
    fn parse_openai_response_extracts_content() {
        let body = json!({
            "choices": [{
                "message": {"role": "assistant", "content": "Hello!"},
                "finish_reason": "stop"
            }]
        });
        assert_eq!(parse_openai_response(&body), Some("Hello!".to_string()));
    }

    #[test]
    fn parse_openai_response_returns_none_on_empty_choices() {
        let body = json!({"choices": []});
        assert_eq!(parse_openai_response(&body), None);
    }

    #[test]
    fn parse_openai_response_returns_none_on_missing_choices() {
        let body = json!({"error": {"message": "invalid key"}});
        assert_eq!(parse_openai_response(&body), None);
    }

    #[test]
    fn parse_openai_response_returns_none_on_null_content() {
        let body = json!({
            "choices": [{"message": {"role": "assistant", "content": null}}]
        });
        assert_eq!(parse_openai_response(&body), None);
    }

    // -- URL resolution --

    #[test]
    fn resolve_anthropic_base_url_default() {
        let cfg = default_config();
        assert_eq!(
            resolve_anthropic_base_url(&cfg),
            "https://api.anthropic.com"
        );
    }

    #[test]
    fn resolve_anthropic_base_url_custom() {
        let cfg = config_with(|c| c.llm_api_base_url = "https://proxy.example.com".to_string());
        assert_eq!(
            resolve_anthropic_base_url(&cfg),
            "https://proxy.example.com"
        );
    }

    #[test]
    fn resolve_openai_base_url_default() {
        let cfg = default_config();
        assert_eq!(resolve_openai_base_url(&cfg), "https://api.openai.com/v1");
    }

    #[test]
    fn resolve_openai_base_url_custom() {
        let cfg = config_with(|c| c.llm_api_base_url = "https://openrouter.ai/api/v1".to_string());
        assert_eq!(
            resolve_openai_base_url(&cfg),
            "https://openrouter.ai/api/v1"
        );
    }
}
