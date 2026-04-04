#[cfg(test)]
mod tests {
    use crate::sentinel::Severity;
    use crate::sentinel::detection::*;

    fn host(mac: &str, ip: &str, alive: bool, ports: &str) -> HostSnapshot {
        HostSnapshot {
            mac_address: mac.to_string(),
            ip: ip.to_string(),
            hostname: None,
            alive,
            ports: ports.to_string(),
        }
    }

    fn host_with_name(mac: &str, ip: &str, alive: bool, ports: &str, name: &str) -> HostSnapshot {
        HostSnapshot {
            mac_address: mac.to_string(),
            ip: ip.to_string(),
            hostname: Some(name.to_string()),
            alive,
            ports: ports.to_string(),
        }
    }

    // ---- BaselineState ----

    #[test]
    fn baseline_from_snapshots_captures_all_fields() {
        let hosts = vec![
            host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22;80"),
            host("AA:BB:CC:DD:EE:02", "192.168.1.2", false, "443"),
        ];

        let baseline = BaselineState::from_snapshots(&hosts);

        assert_eq!(baseline.known_macs.len(), 2);
        assert!(baseline.known_macs.contains("AA:BB:CC:DD:EE:01"));
        assert!(baseline.known_macs.contains("AA:BB:CC:DD:EE:02"));

        // Only the alive host should be in alive_macs
        assert_eq!(baseline.alive_macs.len(), 1);
        assert!(baseline.alive_macs.contains("AA:BB:CC:DD:EE:01"));

        assert_eq!(
            baseline.port_snapshot.get("AA:BB:CC:DD:EE:01").unwrap(),
            "22;80"
        );
        assert_eq!(
            baseline.arp_cache.get("192.168.1.1").unwrap(),
            "AA:BB:CC:DD:EE:01"
        );
    }

    #[test]
    fn baseline_update_replaces_state() {
        let initial = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")];
        let baseline = BaselineState::from_snapshots(&initial);

        let updated_hosts = vec![host("AA:BB:CC:DD:EE:99", "192.168.1.99", true, "8080")];
        let new_baseline = baseline.update(&updated_hosts);

        assert!(!new_baseline.known_macs.contains("AA:BB:CC:DD:EE:01"));
        assert!(new_baseline.known_macs.contains("AA:BB:CC:DD:EE:99"));
    }

    // ---- detect_new_hosts ----

    #[test]
    fn new_host_detected_when_mac_not_in_baseline() {
        let baseline =
            BaselineState::from_snapshots(&[host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")]);
        let current = vec![
            host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22"),
            host("AA:BB:CC:DD:EE:02", "192.168.1.2", true, "80"),
        ];

        let alerts = detect_new_hosts(&baseline, &current);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Warning);
        assert_eq!(alerts[0].category, "new_device");
        assert!(alerts[0].message.contains("192.168.1.2"));
        assert!(alerts[0].message.contains("AA:BB:CC:DD:EE:02"));
    }

    #[test]
    fn no_new_hosts_when_all_known() {
        let hosts = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")];
        let baseline = BaselineState::from_snapshots(&hosts);

        let alerts = detect_new_hosts(&baseline, &hosts);
        assert!(alerts.is_empty());
    }

    #[test]
    fn new_host_includes_hostname_when_present() {
        let baseline = BaselineState::from_snapshots(&[]);
        let current = vec![host_with_name(
            "AA:BB:CC:DD:EE:01",
            "192.168.1.1",
            true,
            "22",
            "web-server",
        )];

        let alerts = detect_new_hosts(&baseline, &current);

        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("web-server"));
    }

    #[test]
    fn new_host_shows_unknown_when_no_hostname() {
        let baseline = BaselineState::from_snapshots(&[]);
        let current = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")];

        let alerts = detect_new_hosts(&baseline, &current);

        assert!(alerts[0].message.contains("unknown"));
    }

    // ---- detect_dead_hosts ----

    #[test]
    fn dead_host_detected_when_previously_alive_goes_offline() {
        let baseline = BaselineState::from_snapshots(&[
            host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22"),
            host("AA:BB:CC:DD:EE:02", "192.168.1.2", true, "80"),
        ]);
        let current = vec![
            host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22"),
            host("AA:BB:CC:DD:EE:02", "192.168.1.2", false, "80"),
        ];

        let alerts = detect_dead_hosts(&baseline, &current);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Info);
        assert_eq!(alerts[0].category, "device_left");
        assert!(alerts[0].message.contains("AA:BB:CC:DD:EE:02"));
    }

    #[test]
    fn no_dead_hosts_when_all_still_alive() {
        let hosts = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")];
        let baseline = BaselineState::from_snapshots(&hosts);

        let alerts = detect_dead_hosts(&baseline, &hosts);
        assert!(alerts.is_empty());
    }

    #[test]
    fn dead_host_not_reported_for_already_offline_host() {
        let baseline =
            BaselineState::from_snapshots(&[host("AA:BB:CC:DD:EE:01", "192.168.1.1", false, "22")]);
        let current = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", false, "22")];

        let alerts = detect_dead_hosts(&baseline, &current);
        assert!(alerts.is_empty());
    }

    #[test]
    fn dead_host_detected_when_mac_disappears_entirely() {
        let baseline =
            BaselineState::from_snapshots(&[host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")]);
        let current: Vec<HostSnapshot> = vec![];

        let alerts = detect_dead_hosts(&baseline, &current);
        assert_eq!(alerts.len(), 1);
    }

    // ---- detect_returned_hosts ----

    #[test]
    fn returned_host_detected_when_known_offline_comes_back() {
        let baseline = BaselineState::from_snapshots(&[
            host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22"),
            host("AA:BB:CC:DD:EE:02", "192.168.1.2", false, "80"),
        ]);
        // Host 02 was known but offline, now it's alive
        let current = vec![
            host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22"),
            host("AA:BB:CC:DD:EE:02", "192.168.1.2", true, "80"),
        ];

        let alerts = detect_returned_hosts(&baseline, &current);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].category, "device_returned");
        assert!(alerts[0].message.contains("AA:BB:CC:DD:EE:02"));
    }

    #[test]
    fn new_device_not_reported_as_returned() {
        let baseline = BaselineState::from_snapshots(&[]);
        let current = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")];

        // Should NOT be reported as returned since it wasn't known
        let alerts = detect_returned_hosts(&baseline, &current);
        assert!(alerts.is_empty());
    }

    #[test]
    fn already_alive_host_not_reported_as_returned() {
        let hosts = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")];
        let baseline = BaselineState::from_snapshots(&hosts);

        let alerts = detect_returned_hosts(&baseline, &hosts);
        assert!(alerts.is_empty());
    }

    // ---- detect_port_changes ----

    #[test]
    fn port_opened_detected() {
        let baseline =
            BaselineState::from_snapshots(&[host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")]);
        let current = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22;80")];

        let alerts = detect_port_changes(&baseline, &current);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].category, "port_change");
        let details = &alerts[0].details;
        let opened: Vec<String> = serde_json::from_value(details["opened"].clone()).unwrap();
        assert!(opened.contains(&"80".to_string()));
    }

    #[test]
    fn port_closed_detected() {
        let baseline = BaselineState::from_snapshots(&[host(
            "AA:BB:CC:DD:EE:01",
            "192.168.1.1",
            true,
            "22;80;443",
        )]);
        let current = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")];

        let alerts = detect_port_changes(&baseline, &current);

        assert_eq!(alerts.len(), 1);
        let details = &alerts[0].details;
        let closed: Vec<String> = serde_json::from_value(details["closed"].clone()).unwrap();
        assert!(closed.contains(&"80".to_string()));
        assert!(closed.contains(&"443".to_string()));
    }

    #[test]
    fn no_alert_when_ports_unchanged() {
        let hosts = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22;80")];
        let baseline = BaselineState::from_snapshots(&hosts);

        let alerts = detect_port_changes(&baseline, &hosts);
        assert!(alerts.is_empty());
    }

    #[test]
    fn no_alert_when_new_ports_empty() {
        let baseline = BaselineState::from_snapshots(&[host(
            "AA:BB:CC:DD:EE:01",
            "192.168.1.1",
            true,
            "22;80",
        )]);
        let current = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "")];

        let alerts = detect_port_changes(&baseline, &current);
        assert!(alerts.is_empty());
    }

    #[test]
    fn no_alert_for_unknown_host_ports() {
        let baseline = BaselineState::from_snapshots(&[]);
        let current = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22;80")];

        // Host not in baseline port_snapshot, so no port change alert
        let alerts = detect_port_changes(&baseline, &current);
        assert!(alerts.is_empty());
    }

    #[test]
    fn simultaneous_open_and_close_detected() {
        let baseline = BaselineState::from_snapshots(&[host(
            "AA:BB:CC:DD:EE:01",
            "192.168.1.1",
            true,
            "22;80",
        )]);
        let current = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22;443")];

        let alerts = detect_port_changes(&baseline, &current);

        assert_eq!(alerts.len(), 1);
        let details = &alerts[0].details;
        let opened: Vec<String> = serde_json::from_value(details["opened"].clone()).unwrap();
        let closed: Vec<String> = serde_json::from_value(details["closed"].clone()).unwrap();
        assert!(opened.contains(&"443".to_string()));
        assert!(closed.contains(&"80".to_string()));
    }

    // ---- detect_arp_spoofing ----

    #[test]
    fn arp_spoof_detected_when_ip_maps_to_different_mac() {
        let baseline =
            BaselineState::from_snapshots(&[host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")]);
        // Same IP, different MAC
        let current = vec![host("FF:FF:FF:FF:FF:FF", "192.168.1.1", true, "22")];

        let alerts = detect_arp_spoofing(&baseline, &current);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert_eq!(alerts[0].category, "arp_spoof");
        assert!(alerts[0].message.contains("AA:BB:CC:DD:EE:01"));
        assert!(alerts[0].message.contains("FF:FF:FF:FF:FF:FF"));
        assert_eq!(alerts[0].details["old_mac"], "AA:BB:CC:DD:EE:01");
        assert_eq!(alerts[0].details["new_mac"], "FF:FF:FF:FF:FF:FF");
    }

    #[test]
    fn no_spoof_when_mac_unchanged() {
        let hosts = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")];
        let baseline = BaselineState::from_snapshots(&hosts);

        let alerts = detect_arp_spoofing(&baseline, &hosts);
        assert!(alerts.is_empty());
    }

    #[test]
    fn no_spoof_when_host_not_alive() {
        let baseline =
            BaselineState::from_snapshots(&[host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")]);
        // Different MAC but not alive — don't alert
        let current = vec![host("FF:FF:FF:FF:FF:FF", "192.168.1.1", false, "22")];

        let alerts = detect_arp_spoofing(&baseline, &current);
        assert!(alerts.is_empty());
    }

    #[test]
    fn no_spoof_for_new_ip() {
        let baseline =
            BaselineState::from_snapshots(&[host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")]);
        let current = vec![host("FF:FF:FF:FF:FF:FF", "192.168.1.99", true, "22")];

        let alerts = detect_arp_spoofing(&baseline, &current);
        assert!(alerts.is_empty());
    }

    // ---- run_all_checks ----

    #[test]
    fn run_all_checks_combines_all_alert_types() {
        let baseline = BaselineState::from_snapshots(&[
            host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22"),
            host("AA:BB:CC:DD:EE:02", "192.168.1.2", true, "80"),
        ]);
        let current = vec![
            // Host 01 has port change
            host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22;443"),
            // Host 02 went offline (alive=false)
            host("AA:BB:CC:DD:EE:02", "192.168.1.2", false, "80"),
            // Brand new host
            host("AA:BB:CC:DD:EE:03", "192.168.1.3", true, "8080"),
        ];

        let alerts = run_all_checks(&baseline, &current);

        let categories: Vec<&str> = alerts.iter().map(|a| a.category.as_str()).collect();
        assert!(categories.contains(&"new_device"));
        assert!(categories.contains(&"port_change"));
        assert!(categories.contains(&"device_left"));
    }

    #[test]
    fn run_all_checks_empty_when_no_changes() {
        let hosts = vec![host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22")];
        let baseline = BaselineState::from_snapshots(&hosts);

        let alerts = run_all_checks(&baseline, &hosts);
        assert!(alerts.is_empty());
    }

    // ---- Edge cases ----

    #[test]
    fn multiple_new_hosts_all_detected() {
        let baseline = BaselineState::from_snapshots(&[]);
        let current = vec![
            host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22"),
            host("AA:BB:CC:DD:EE:02", "192.168.1.2", true, "80"),
            host("AA:BB:CC:DD:EE:03", "192.168.1.3", false, "443"),
        ];

        let alerts = detect_new_hosts(&baseline, &current);
        assert_eq!(alerts.len(), 3);
    }

    #[test]
    fn multiple_dead_hosts_all_detected() {
        let baseline = BaselineState::from_snapshots(&[
            host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22"),
            host("AA:BB:CC:DD:EE:02", "192.168.1.2", true, "80"),
        ]);
        let current: Vec<HostSnapshot> = vec![];

        let alerts = detect_dead_hosts(&baseline, &current);
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn multiple_spoof_attempts_all_detected() {
        let baseline = BaselineState::from_snapshots(&[
            host("AA:BB:CC:DD:EE:01", "192.168.1.1", true, "22"),
            host("AA:BB:CC:DD:EE:02", "192.168.1.2", true, "80"),
        ]);
        let current = vec![
            host("EVIL:01:01:01:01:01", "192.168.1.1", true, "22"),
            host("EVIL:02:02:02:02:02", "192.168.1.2", true, "80"),
        ];

        let alerts = detect_arp_spoofing(&baseline, &current);
        assert_eq!(alerts.len(), 2);
        assert!(alerts.iter().all(|a| a.severity == Severity::Critical));
    }
}
