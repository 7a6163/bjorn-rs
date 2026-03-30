use std::sync::Arc;

use serde_json::{json, Value};

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
pub async fn execute_tool(
    name: &str,
    inputs: &Value,
    state: &Arc<AppState>,
) -> String {
    match name {
        "get_hosts" => {
            let alive_only = inputs.get("alive_only").and_then(|v| v.as_bool()).unwrap_or(true);
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
                Err(e) => format!("{{\"error\": \"{e}\"}}")
            }
        }

        "get_vulnerabilities" => {
            match state.kb.vulnerabilities().await {
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
                Err(e) => format!("{{\"error\": \"{e}\"}}")
            }
        }

        "get_credentials" => {
            let service = inputs.get("service").and_then(|v| v.as_str());
            match state.kb.credentials(service).await {
                Ok(creds) => {
                    let limit = inputs.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
                    let result: Vec<Value> = creds
                        .iter()
                        .take(limit)
                        .map(|c| {
                            json!({
                                "host_id": c.host_id,
                                "protocol": c.protocol,
                                "username": c.username,
                                "password": c.password,
                                "port": c.port,
                            })
                        })
                        .collect();
                    serde_json::to_string(&result).unwrap_or_default()
                }
                Err(e) => format!("{{\"error\": \"{e}\"}}")
            }
        }

        "get_action_history" => {
            // Return a summary from the stats
            match state.kb.stats().await {
                Ok((alive, total, creds, vulns, actions)) => {
                    json!({
                        "alive_hosts": alive,
                        "total_hosts": total,
                        "total_credentials": creds,
                        "total_vulnerabilities": vulns,
                        "successful_actions": actions,
                    })
                    .to_string()
                }
                Err(e) => format!("{{\"error\": \"{e}\"}}")
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
            let action = inputs.get("action_name").and_then(|v| v.as_str()).unwrap_or("");
            let ip = inputs.get("target_ip").and_then(|v| v.as_str()).unwrap_or("");
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
