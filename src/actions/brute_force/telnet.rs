use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::{BruteForceAction, Connector};

/// Telnet connector using raw TCP.
pub struct TelnetConnector;

impl Connector for TelnetConnector {
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
        Box::pin(async move { telnet_try_connect(&ip, port, &user, &password).await })
    }
}

async fn telnet_try_connect(ip: &str, port: u16, user: &str, password: &str) -> bool {
    let addr = format!("{ip}:{port}");

    let result = timeout(Duration::from_secs(15), async {
        let mut stream = TcpStream::connect(&addr).await.ok()?;
        let mut buf = [0u8; 4096];

        // Wait for "login: " prompt
        if !read_until_pattern(&mut stream, &mut buf, b"login: ", Duration::from_secs(5)).await {
            return None;
        }

        // Send username
        stream
            .write_all(format!("{user}\n").as_bytes())
            .await
            .ok()?;

        // Wait for "Password: " prompt (if password is needed)
        if !password.is_empty() {
            if !read_until_pattern(&mut stream, &mut buf, b"assword", Duration::from_secs(5)).await
            {
                return None;
            }
            stream
                .write_all(format!("{password}\n").as_bytes())
                .await
                .ok()?;
        }

        // Wait for response — look for shell prompt ($ or #) indicating success
        tokio::time::sleep(Duration::from_secs(2)).await;
        let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .ok()?
            .ok()?;

        let response = &buf[..n];

        // Check for success indicators (shell prompt)
        if response.windows(2).any(|w| w == b"$ " || w == b"# ") {
            Some(())
        } else {
            None
        }
    })
    .await;

    matches!(result, Ok(Some(())))
}

/// Read from stream until a pattern is found or timeout.
async fn read_until_pattern(
    stream: &mut TcpStream,
    buf: &mut [u8],
    pattern: &[u8],
    dur: Duration,
) -> bool {
    let mut accumulated = Vec::new();
    let deadline = tokio::time::Instant::now() + dur;

    loop {
        let remaining = deadline - tokio::time::Instant::now();
        if remaining.is_zero() {
            return false;
        }

        match timeout(remaining, stream.read(buf)).await {
            Ok(Ok(0)) => return false,
            Ok(Ok(n)) => {
                accumulated.extend_from_slice(&buf[..n]);
                if accumulated
                    .windows(pattern.len())
                    .any(|w| w.eq_ignore_ascii_case(pattern))
                {
                    return true;
                }
            }
            _ => return false,
        }
    }
}

/// Create a Telnet brute-force action for the action registry.
pub fn create_action() -> BruteForceAction<TelnetConnector> {
    BruteForceAction::new(TelnetConnector, "TelnetBruteforce", "telnet", 23, None, 40)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::Action;

    #[test]
    fn test_create_action_name() {
        assert_eq!(create_action().name(), "TelnetBruteforce");
    }

    #[test]
    fn test_create_action_port() {
        assert_eq!(create_action().port(), Some(23));
    }

    #[test]
    fn test_create_action_parent() {
        assert_eq!(create_action().parent(), None);
    }
}
