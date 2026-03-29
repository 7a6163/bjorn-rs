use std::time::Duration;

use tokio::process::Command;

use super::{BruteForceAction, Connector};

/// PostgreSQL connector — uses `psql` CLI.
pub struct PostgresConnector;

impl Connector for PostgresConnector {
    fn try_connect(
        &self,
        ip: &str,
        port: u16,
        user: &str,
        password: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let ip = ip.to_string();
        let user = user.to_string();
        let password = password.to_string();
        Box::pin(async move {
            postgres_try_connect(&ip, port, &user, &password).await
        })
    }
}

async fn postgres_try_connect(ip: &str, port: u16, user: &str, password: &str) -> bool {
    // PGPASSWORD=<password> psql -h <ip> -p <port> -U <user> -c "SELECT 1" -t -A
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new("psql")
            .env("PGPASSWORD", password)
            .env("PGCONNECT_TIMEOUT", "5")
            .args([
                "-h", ip,
                "-p", &port.to_string(),
                "-U", user,
                "-c", "SELECT 1",
                "-t", "-A",
            ])
            .output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => output.status.success(),
        _ => false,
    }
}

/// Create a PostgreSQL brute-force action for the action registry.
pub fn create_action() -> BruteForceAction<PostgresConnector> {
    BruteForceAction::new(PostgresConnector, "PostgresBruteforce", "postgres", 5432, None, 10)
}
