use std::sync::Arc;
use std::time::Duration;

use super::{BruteForceAction, Connector};
use russh::client;

/// SSH connector using russh.
pub struct SshConnector;

impl Connector for SshConnector {
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
        Box::pin(async move { ssh_try_connect(&ip, port, &user, &password).await })
    }
}

async fn ssh_try_connect(ip: &str, port: u16, user: &str, password: &str) -> bool {
    let config = Arc::new(client::Config::default());

    let addr = format!("{ip}:{port}");
    let handler = SshHandler;

    let mut session = match tokio::time::timeout(
        Duration::from_secs(15),
        client::connect(config, &addr, handler),
    )
    .await
    {
        Ok(Ok(session)) => session,
        _ => return false,
    };

    let auth_result = tokio::time::timeout(
        Duration::from_secs(10),
        session.authenticate_password(user, password),
    )
    .await;

    let success = match auth_result {
        Ok(Ok(result)) => result.success(),
        _ => false,
    };

    if success {
        let _ = session
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
    }
    success
}

/// Minimal SSH client handler that accepts all host keys.
struct SshHandler;

impl client::Handler for SshHandler {
    type Error = anyhow::Error;

    fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(true) }
    }
}

/// Create an SSH brute-force action for the action registry.
pub fn create_action() -> BruteForceAction<SshConnector> {
    BruteForceAction::new(SshConnector, "SSHBruteforce", "ssh", 22, None, 40)
}
