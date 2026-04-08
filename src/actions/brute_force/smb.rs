use std::time::Duration;

use tokio::process::Command;

use super::{BruteForceAction, Connector};

/// SMB connector — shells out to `smbclient`.
/// Matches Python's smb_connector.py approach.
pub struct SmbConnector;

impl Connector for SmbConnector {
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
        Box::pin(async move { smb_try_connect(&ip, port, &user, &password).await })
    }
}

async fn smb_try_connect(ip: &str, _port: u16, user: &str, password: &str) -> bool {
    // smbclient -L <ip> -U <user>%<password> -N
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        Command::new("smbclient")
            .args(["-L", ip, "-U", &format!("{user}%{password}"), "--timeout=5"])
            .output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            // smbclient returns 0 on successful listing
            if output.status.success() {
                return true;
            }
            // Also check stdout for share listings even with non-zero exit
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.contains("Sharename") && stdout.contains("Disk")
        }
        _ => false,
    }
}

/// Create an SMB brute-force action for the action registry.
pub fn create_action() -> BruteForceAction<SmbConnector> {
    BruteForceAction::new(SmbConnector, "SMBBruteforce", "smb", 445, None, 10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::Action;

    #[test]
    fn test_create_action_name() {
        assert_eq!(create_action().name(), "SMBBruteforce");
    }

    #[test]
    fn test_create_action_port() {
        assert_eq!(create_action().port(), Some(445));
    }

    #[test]
    fn test_create_action_parent() {
        assert_eq!(create_action().parent(), None);
    }
}
