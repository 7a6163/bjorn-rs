use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{BruteForceAction, Connector};

/// Redis connector — uses raw TCP (RESP protocol).
/// Redis AUTH only takes a password (or password + username in ACL mode).
pub struct RedisConnector;

impl Connector for RedisConnector {
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
            redis_try_connect(&ip, port, &user, &password).await
        })
    }
}

async fn redis_try_connect(ip: &str, port: u16, user: &str, password: &str) -> bool {
    let addr = format!("{ip}:{port}");
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(&addr).await.ok()?;

        // Try AUTH with password only first (Redis < 6), then with username (Redis 6+ ACL)
        let auth_cmd = if user.is_empty() || user == "default" {
            format!("*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n", password.len(), password)
        } else {
            format!(
                "*3\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
                user.len(), user, password.len(), password
            )
        };

        stream.write_all(auth_cmd.as_bytes()).await.ok()?;
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.ok()?;
        let response = std::str::from_utf8(&buf[..n]).ok()?;

        if response.starts_with("+OK") {
            return Some(());
        }

        // Also try no-auth PING to detect open Redis
        if password.is_empty() {
            stream
                .write_all(b"*1\r\n$4\r\nPING\r\n")
                .await
                .ok()?;
            let n = stream.read(&mut buf).await.ok()?;
            let response = std::str::from_utf8(&buf[..n]).ok()?;
            if response.contains("+PONG") {
                return Some(());
            }
        }

        None
    })
    .await;

    matches!(result, Ok(Some(())))
}

/// Create a Redis brute-force action for the action registry.
pub fn create_action() -> BruteForceAction<RedisConnector> {
    BruteForceAction::new(RedisConnector, "RedisBruteforce", "redis", 6379, None, 20)
}
