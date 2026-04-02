use std::time::Duration;

use suppaftp::AsyncFtpStream;

use super::{BruteForceAction, Connector};

/// FTP connector using suppaftp.
pub struct FtpConnector;

impl Connector for FtpConnector {
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
        Box::pin(async move { ftp_try_connect(&ip, port, &user, &password).await })
    }
}

async fn ftp_try_connect(ip: &str, port: u16, user: &str, password: &str) -> bool {
    let addr = format!("{ip}:{port}");
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut ftp = AsyncFtpStream::connect(&addr).await.ok()?;
        ftp.login(user, password).await.ok()?;
        let _ = ftp.quit().await;
        Some(())
    })
    .await;

    matches!(result, Ok(Some(())))
}

/// Create an FTP brute-force action for the action registry.
pub fn create_action() -> BruteForceAction<FtpConnector> {
    BruteForceAction::new(FtpConnector, "FTPBruteforce", "ftp", 21, None, 40)
}
