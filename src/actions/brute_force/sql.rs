use std::time::Duration;

use tokio::process::Command;

use super::{BruteForceAction, Connector};

/// MySQL connector — uses `mysql` CLI to avoid linking libmysqlclient.
/// This is simpler and more portable for ARM cross-compilation.
pub struct SqlConnector;

impl Connector for SqlConnector {
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
        Box::pin(async move { sql_try_connect(&ip, port, &user, &password).await })
    }
}

async fn sql_try_connect(ip: &str, port: u16, user: &str, password: &str) -> bool {
    // Use mysql CLI: mysql -h <ip> -P <port> -u <user> -p<password> -e "SELECT 1"
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new("mysql")
            .args([
                "-h",
                ip,
                "-P",
                &port.to_string(),
                "-u",
                user,
                &format!("-p{password}"),
                "-e",
                "SELECT 1",
                "--connect-timeout=5",
            ])
            .output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => output.status.success(),
        _ => false,
    }
}

/// Create a SQL brute-force action for the action registry.
pub fn create_action() -> BruteForceAction<SqlConnector> {
    BruteForceAction::new(SqlConnector, "SQLBruteforce", "sql", 3306, None, 10)
}
