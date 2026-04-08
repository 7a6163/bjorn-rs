use std::time::Duration;

use tokio::net::UdpSocket;

use super::{BruteForceAction, Connector};

/// SNMP community string brute force — raw UDP.
/// Sends SNMPv2c GET sysDescr.0 with each community string as "password".
/// The "user" field is ignored (SNMP v1/v2c only has community strings).
pub struct SnmpConnector;

impl Connector for SnmpConnector {
    fn try_connect(
        &self,
        ip: &str,
        port: u16,
        _user: &str,
        password: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let ip = ip.to_string();
        let community = password.to_string();
        Box::pin(async move { snmp_try_connect(&ip, port, &community).await })
    }
}

/// Build an SNMPv2c GET request for sysDescr.0 (1.3.6.1.2.1.1.1.0).
fn build_snmp_get(community: &str) -> Vec<u8> {
    let community_bytes = community.as_bytes();
    let community_len = community_bytes.len();

    // OID: 1.3.6.1.2.1.1.1.0 (sysDescr.0)
    let oid: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

    // VarBind: SEQUENCE { OID, NULL }
    let varbind_value: &[u8] = &[0x05, 0x00]; // NULL
    let varbind_len = oid.len() + varbind_value.len();
    let mut varbind = vec![0x30, varbind_len as u8];
    varbind.extend_from_slice(oid);
    varbind.extend_from_slice(varbind_value);

    // VarBindList: SEQUENCE { varbind }
    let varbind_list_len = varbind.len();
    let mut varbind_list = vec![0x30, varbind_list_len as u8];
    varbind_list.extend_from_slice(&varbind);

    // PDU: GetRequest (0xA0)
    let request_id: &[u8] = &[0x02, 0x01, 0x01]; // INTEGER 1
    let error_status: &[u8] = &[0x02, 0x01, 0x00]; // INTEGER 0
    let error_index: &[u8] = &[0x02, 0x01, 0x00]; // INTEGER 0
    let pdu_content_len =
        request_id.len() + error_status.len() + error_index.len() + varbind_list.len();
    let mut pdu = vec![0xA0, pdu_content_len as u8];
    pdu.extend_from_slice(request_id);
    pdu.extend_from_slice(error_status);
    pdu.extend_from_slice(error_index);
    pdu.extend_from_slice(&varbind_list);

    // Message: SEQUENCE { version, community, pdu }
    let version: &[u8] = &[0x02, 0x01, 0x01]; // INTEGER 1 (SNMPv2c)
    let community_header = [0x04, community_len as u8];
    let msg_content_len = version.len() + community_header.len() + community_len + pdu.len();
    let mut msg = vec![0x30, msg_content_len as u8];
    msg.extend_from_slice(version);
    msg.extend_from_slice(&community_header);
    msg.extend_from_slice(community_bytes);
    msg.extend_from_slice(&pdu);

    msg
}

async fn snmp_try_connect(ip: &str, port: u16, community: &str) -> bool {
    let addr = format!("{ip}:{port}");
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        let packet = build_snmp_get(community);
        socket.send_to(&packet, &addr).await.ok()?;

        let mut buf = [0u8; 4096];
        let (n, _) = socket.recv_from(&mut buf).await.ok()?;

        // Any valid SNMP response means the community string worked
        if n > 2 && buf[0] == 0x30 {
            Some(())
        } else {
            None
        }
    })
    .await;

    matches!(result, Ok(Some(())))
}

pub fn create_action() -> BruteForceAction<SnmpConnector> {
    BruteForceAction::new(SnmpConnector, "SNMPBruteforce", "snmp", 161, None, 20)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::Action;

    #[test]
    fn test_create_action_name() {
        assert_eq!(create_action().name(), "SNMPBruteforce");
    }

    #[test]
    fn test_create_action_port() {
        assert_eq!(create_action().port(), Some(161));
    }

    #[test]
    fn test_create_action_parent() {
        assert_eq!(create_action().parent(), None);
    }
}
