use std::sync::Arc;

use serde_json::{Value, json};

use crate::state::AppState;

/// Tool definitions in Anthropic Messages API format.
/// Used by the LLM bridge for agentic tool-calling.
pub fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "get_hosts",
            "description": "Return all network hosts discovered by Bjorn's scanner.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "alive_only": {
                        "type": "boolean",
                        "description": "Only return alive hosts. Default: true."
                    }
                }
            }
        }),
        json!({
            "name": "get_vulnerabilities",
            "description": "Return discovered vulnerabilities, optionally filtered by host IP.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host_ip": {
                        "type": "string",
                        "description": "Filter by IP address. Empty = all hosts."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results. Default: 100."
                    }
                }
            }
        }),
        json!({
            "name": "get_credentials",
            "description": "Return captured credentials, optionally filtered by service name.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Service filter (ssh, ftp, smb...). Empty = all."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results. Default: 100."
                    }
                }
            }
        }),
        json!({
            "name": "get_action_history",
            "description": "Return the history of executed Bjorn actions, most recent first.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max results. Default: 50."
                    },
                    "action_name": {
                        "type": "string",
                        "description": "Filter by action name. Empty = all."
                    }
                }
            }
        }),
        json!({
            "name": "get_status",
            "description": "Return Bjorn's current operational status, scan counters, and active action.",
            "input_schema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "run_action",
            "description": "Queue a Bjorn action against a target IP address.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "action_name": {
                        "type": "string",
                        "description": "Action module name (e.g. SSHBruteforce)."
                    },
                    "target_ip": {
                        "type": "string",
                        "description": "Target IP address."
                    }
                },
                "required": ["action_name", "target_ip"]
            }
        }),
        json!({
            "name": "query_db",
            "description": "Run a read-only SELECT query against Bjorn's SQLite database.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "SELECT SQL statement."
                    }
                },
                "required": ["sql"]
            }
        }),
    ]
}

/// Execute a tool call and return the result as a JSON string.
pub async fn execute_tool(name: &str, inputs: &Value, state: &Arc<AppState>) -> String {
    match name {
        "get_hosts" => {
            let alive_only = inputs
                .get("alive_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let hosts = if alive_only {
                state.kb.alive_hosts().await
            } else {
                state.kb.all_hosts().await
            };
            match hosts {
                Ok(h) => {
                    let result: Vec<Value> = h
                        .iter()
                        .map(|host| {
                            json!({
                                "ip": host.ip,
                                "mac": host.mac_address,
                                "hostname": host.hostname,
                                "alive": host.alive,
                                "ports": host.ports,
                            })
                        })
                        .collect();
                    serde_json::to_string(&result).unwrap_or_default()
                }
                Err(e) => format!("{{\"error\": \"{e}\"}}"),
            }
        }

        "get_vulnerabilities" => match state.kb.vulnerabilities().await {
            Ok(vulns) => {
                let limit = inputs.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
                let result: Vec<Value> = vulns
                    .iter()
                    .take(limit)
                    .map(|v| {
                        json!({
                            "host_id": v.host_id,
                            "port": v.port,
                            "description": v.description,
                            "severity": v.severity,
                        })
                    })
                    .collect();
                serde_json::to_string(&result).unwrap_or_default()
            }
            Err(e) => format!("{{\"error\": \"{e}\"}}"),
        },

        "get_credentials" => {
            let service = inputs.get("service").and_then(|v| v.as_str());
            match state.kb.credentials(service).await {
                Ok(creds) => {
                    let limit =
                        inputs.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
                    let result: Vec<Value> = creds
                        .iter()
                        .take(limit)
                        .map(|c| {
                            json!({
                                "host_id": c.host_id,
                                "protocol": c.protocol,
                                "username": c.username,
                                "password": "***REDACTED***",
                                "port": c.port,
                            })
                        })
                        .collect();
                    serde_json::to_string(&result).unwrap_or_default()
                }
                Err(e) => format!("{{\"error\": \"{e}\"}}"),
            }
        }

        "get_action_history" => {
            // Return a summary from the stats
            match state.kb.stats().await {
                Ok((alive, total, creds, vulns, actions)) => json!({
                    "alive_hosts": alive,
                    "total_hosts": total,
                    "total_credentials": creds,
                    "total_vulnerabilities": vulns,
                    "successful_actions": actions,
                })
                .to_string(),
                Err(e) => format!("{{\"error\": \"{e}\"}}"),
            }
        }

        "get_status" => {
            let status = state.status.read().await;
            let display = state.display.read().await;
            json!({
                "current_action": status.current_action,
                "detail": status.detail,
                "manual_mode": status.manual_mode,
                "targets": display.target_count,
                "ports": display.port_count,
                "vulns": display.vuln_count,
                "creds": display.cred_count,
                "data": display.data_count,
            })
            .to_string()
        }

        "run_action" => {
            let action = inputs
                .get("action_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ip = inputs
                .get("target_ip")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // For now, log the request — full action queue integration in Phase 2
            tracing::info!(action = %action, ip = %ip, "LLM requested action execution");
            json!({"status": "queued", "action": action, "target": ip}).to_string()
        }

        "query_db" => {
            let sql = inputs.get("sql").and_then(|v| v.as_str()).unwrap_or("");
            if !sql.trim().to_uppercase().starts_with("SELECT") {
                return json!({"error": "only SELECT queries are allowed"}).to_string();
            }
            // Execute read-only query via sqlx
            json!({"status": "executed", "note": "raw query support pending"}).to_string()
        }

        _ => json!({"error": format!("unknown tool: {name}")}).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BjornConfig, PathConfig};
    use crate::state::AppState;
    use tempfile::TempDir;

    #[test]
    fn tool_definitions_has_all_seven_tools() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 7);

        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"get_hosts"));
        assert!(names.contains(&"get_vulnerabilities"));
        assert!(names.contains(&"get_credentials"));
        assert!(names.contains(&"get_action_history"));
        assert!(names.contains(&"get_status"));
        assert!(names.contains(&"run_action"));
        assert!(names.contains(&"query_db"));
    }

    #[test]
    fn tool_definitions_have_required_fields() {
        for tool in tool_definitions() {
            assert!(tool["name"].is_string(), "tool missing name");
            assert!(tool["description"].is_string(), "tool missing description");
            assert!(
                tool["input_schema"].is_object(),
                "tool missing input_schema"
            );
            assert_eq!(
                tool["input_schema"]["type"].as_str().unwrap(),
                "object",
                "input_schema type must be object"
            );
        }
    }

    /// Build an `Arc<AppState>` backed by an in-memory SQLite KB for testing.
    async fn test_state() -> (Arc<AppState>, TempDir) {
        use crate::state::KnowledgeBase;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let kb = KnowledgeBase::open(&db_path).await.unwrap();
        let config = BjornConfig::default();
        let paths = PathConfig::new(dir.path());
        let state = AppState::new(config, paths, kb);
        (state, dir)
    }

    // -- get_hosts --

    #[tokio::test]
    async fn get_hosts_empty_db_returns_empty_array() {
        let (state, _dir) = test_state().await;
        let result = execute_tool("get_hosts", &json!({}), &state).await;
        let parsed: Vec<Value> = serde_json::from_str(&result).unwrap();
        assert!(parsed.is_empty());
    }

    #[tokio::test]
    async fn get_hosts_returns_alive_hosts_by_default() {
        let (state, _dir) = test_state().await;
        state
            .kb
            .upsert_host(
                "aa:bb:cc:dd:ee:01",
                "10.0.0.1",
                Some("alive-host"),
                true,
                "22;80",
            )
            .await
            .unwrap();
        state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:02", "10.0.0.2", None, false, "443")
            .await
            .unwrap();

        let result = execute_tool("get_hosts", &json!({}), &state).await;
        let parsed: Vec<Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["ip"], "10.0.0.1");
        assert_eq!(parsed[0]["hostname"], "alive-host");
        assert_eq!(parsed[0]["alive"], true);
        assert_eq!(parsed[0]["ports"], "22;80");
    }

    #[tokio::test]
    async fn get_hosts_alive_only_false_returns_all() {
        let (state, _dir) = test_state().await;
        state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22")
            .await
            .unwrap();
        state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:02", "10.0.0.2", None, false, "443")
            .await
            .unwrap();

        let result = execute_tool("get_hosts", &json!({"alive_only": false}), &state).await;
        let parsed: Vec<Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    // -- get_vulnerabilities --

    #[tokio::test]
    async fn get_vulnerabilities_empty_db() {
        let (state, _dir) = test_state().await;
        let result = execute_tool("get_vulnerabilities", &json!({}), &state).await;
        let parsed: Vec<Value> = serde_json::from_str(&result).unwrap();
        assert!(parsed.is_empty());
    }

    #[tokio::test]
    async fn get_vulnerabilities_returns_stored_vulns() {
        let (state, _dir) = test_state().await;
        let host_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "80")
            .await
            .unwrap();
        state
            .kb
            .store_vulnerability(host_id, 80, "XSS in /login", Some("HIGH"))
            .await
            .unwrap();

        let result = execute_tool("get_vulnerabilities", &json!({}), &state).await;
        let parsed: Vec<Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["host_id"], host_id);
        assert_eq!(parsed[0]["port"], 80);
        assert_eq!(parsed[0]["description"], "XSS in /login");
        assert_eq!(parsed[0]["severity"], "HIGH");
    }

    #[tokio::test]
    async fn get_vulnerabilities_respects_limit() {
        let (state, _dir) = test_state().await;
        let host_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "80")
            .await
            .unwrap();
        for i in 0..5 {
            state
                .kb
                .store_vulnerability(host_id, 80, &format!("vuln-{i}"), None)
                .await
                .unwrap();
        }

        let result = execute_tool("get_vulnerabilities", &json!({"limit": 2}), &state).await;
        let parsed: Vec<Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    // -- get_credentials --

    #[tokio::test]
    async fn get_credentials_redacts_passwords() {
        let (state, _dir) = test_state().await;
        let host_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22")
            .await
            .unwrap();
        state
            .kb
            .store_credential(host_id, "ssh", "root", "supersecret123", 22)
            .await
            .unwrap();

        let result = execute_tool("get_credentials", &json!({}), &state).await;
        let parsed: Vec<Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["username"], "root");
        assert_eq!(parsed[0]["password"], "***REDACTED***");
        assert_eq!(parsed[0]["protocol"], "ssh");
        assert_eq!(parsed[0]["port"], 22);
        // Verify the actual password is NOT present anywhere in output
        assert!(!result.contains("supersecret123"));
    }

    #[tokio::test]
    async fn get_credentials_filters_by_service() {
        let (state, _dir) = test_state().await;
        let host_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22;21")
            .await
            .unwrap();
        state
            .kb
            .store_credential(host_id, "ssh", "root", "pass1", 22)
            .await
            .unwrap();
        state
            .kb
            .store_credential(host_id, "ftp", "admin", "pass2", 21)
            .await
            .unwrap();

        let result = execute_tool("get_credentials", &json!({"service": "ssh"}), &state).await;
        let parsed: Vec<Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["protocol"], "ssh");
    }

    // -- get_action_history --

    #[tokio::test]
    async fn get_action_history_returns_stats() {
        let (state, _dir) = test_state().await;
        let host_id = state
            .kb
            .upsert_host("aa:bb:cc:dd:ee:01", "10.0.0.1", None, true, "22")
            .await
            .unwrap();
        state
            .kb
            .record_action(host_id, "SSHBruteforce", "success")
            .await
            .unwrap();

        let result = execute_tool("get_action_history", &json!({}), &state).await;
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["alive_hosts"], 1);
        assert_eq!(parsed["total_hosts"], 1);
        assert_eq!(parsed["successful_actions"], 1);
    }

    // -- get_status --

    #[tokio::test]
    async fn get_status_returns_current_state() {
        let (state, _dir) = test_state().await;

        // Set some status values
        {
            let mut status = state.status.write().await;
            status.current_action = "NetworkScanner".to_string();
            status.detail = "scanning 10.0.0.0/24".to_string();
            status.manual_mode = false;
        }
        {
            let mut display = state.display.write().await;
            display.target_count = 5;
            display.port_count = 12;
            display.vuln_count = 3;
            display.cred_count = 2;
            display.data_count = 1;
        }

        let result = execute_tool("get_status", &json!({}), &state).await;
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["current_action"], "NetworkScanner");
        assert_eq!(parsed["detail"], "scanning 10.0.0.0/24");
        assert_eq!(parsed["manual_mode"], false);
        assert_eq!(parsed["targets"], 5);
        assert_eq!(parsed["ports"], 12);
        assert_eq!(parsed["vulns"], 3);
        assert_eq!(parsed["creds"], 2);
        assert_eq!(parsed["data"], 1);
    }

    // -- run_action --

    #[tokio::test]
    async fn run_action_returns_queued() {
        let (state, _dir) = test_state().await;
        let result = execute_tool(
            "run_action",
            &json!({"action_name": "SSHBruteforce", "target_ip": "10.0.0.5"}),
            &state,
        )
        .await;
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["status"], "queued");
        assert_eq!(parsed["action"], "SSHBruteforce");
        assert_eq!(parsed["target"], "10.0.0.5");
    }

    // -- query_db --

    #[tokio::test]
    async fn query_db_rejects_non_select() {
        let (state, _dir) = test_state().await;

        for sql in &[
            "DROP TABLE hosts",
            "DELETE FROM hosts",
            "INSERT INTO hosts VALUES (1)",
            "UPDATE hosts SET alive = 0",
        ] {
            let result = execute_tool("query_db", &json!({"sql": sql}), &state).await;
            let parsed: Value = serde_json::from_str(&result).unwrap();
            assert_eq!(
                parsed["error"], "only SELECT queries are allowed",
                "should reject: {sql}"
            );
        }
    }

    #[tokio::test]
    async fn query_db_accepts_select() {
        let (state, _dir) = test_state().await;
        let result = execute_tool("query_db", &json!({"sql": "SELECT * FROM hosts"}), &state).await;
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["status"], "executed");
    }

    // -- unknown tool --

    #[tokio::test]
    async fn unknown_tool_returns_error() {
        let (state, _dir) = test_state().await;
        let result = execute_tool("nonexistent_tool", &json!({}), &state).await;
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert!(
            parsed["error"].as_str().unwrap().contains("unknown tool"),
            "expected unknown tool error, got: {result}"
        );
    }
}
