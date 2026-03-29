use std::time::Duration;

use tokio::process::Command;

use super::{BruteForceAction, Connector};

/// MongoDB connector — uses `mongosh` CLI.
pub struct MongoConnector;

impl Connector for MongoConnector {
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
            mongo_try_connect(&ip, port, &user, &password).await
        })
    }
}

async fn mongo_try_connect(ip: &str, port: u16, user: &str, password: &str) -> bool {
    // mongosh "mongodb://<user>:<password>@<ip>:<port>/admin" --eval "db.runCommand({ping:1})" --quiet
    let uri = format!("mongodb://{user}:{password}@{ip}:{port}/admin");
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new("mongosh")
            .args([
                &uri,
                "--eval", "db.runCommand({ping:1})",
                "--quiet",
            ])
            .output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            if output.status.success() {
                return true;
            }
            // Fallback: try legacy `mongo` command
            let legacy = tokio::time::timeout(
                Duration::from_secs(10),
                Command::new("mongo")
                    .args([
                        &uri,
                        "--eval", "db.runCommand({ping:1})",
                        "--quiet",
                    ])
                    .output(),
            )
            .await;
            matches!(legacy, Ok(Ok(o)) if o.status.success())
        }
        _ => false,
    }
}

/// Create a MongoDB brute-force action for the action registry.
pub fn create_action() -> BruteForceAction<MongoConnector> {
    BruteForceAction::new(MongoConnector, "MongoBruteforce", "mongo", 27017, None, 10)
}
