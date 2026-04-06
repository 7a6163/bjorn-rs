use std::sync::Arc;

use tokio::process::Command;

use crate::state::AppState;

/// Nmap vulnerability scanner.
///
/// Shells out to `nmap -sV --script vulners.nse` and parses the output
/// for CVEs and exploit references. Results are stored in the KB.
pub struct VulnScanner {
    state: Arc<AppState>,
}

impl VulnScanner {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Scan a single host for vulnerabilities.
    /// Returns `true` on success, `false` on failure.
    pub async fn scan_host(&self, host_id: i64, ip: &str, ports: &[u16]) -> bool {
        if ports.is_empty() {
            return true; // Nothing to scan
        }

        let config = self.state.config();
        let ports_str = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        tracing::info!(ip = %ip, ports = %ports_str, "starting vulnerability scan");

        // Update display
        {
            let mut status = self.state.status.write().await;
            status.current_action = "NmapVulnScanner".to_string();
            status.detail = ip.to_string();
        }

        let result = Command::new("nmap")
            .args([
                &config.nmap_scan_aggressivity,
                "-sV",
                "--script",
                "vulners.nse",
                "-p",
                &ports_str,
                ip,
            ])
            .output()
            .await;

        let output = match result {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            Ok(o) => {
                tracing::error!(
                    ip = %ip,
                    stderr = %String::from_utf8_lossy(&o.stderr),
                    "nmap vuln scan failed"
                );
                return false;
            }
            Err(e) => {
                tracing::error!(ip = %ip, %e, "failed to run nmap");
                return false;
            }
        };

        // Parse vulnerabilities from output
        let vulns = parse_vulnerabilities(&output);

        // Store each vulnerability in the KB
        for vuln in &vulns {
            // Try to extract port from context, default to 0
            let port = vuln.port.unwrap_or(0);
            if let Err(e) = self
                .state
                .kb
                .store_vulnerability(host_id, port, &vuln.description, vuln.severity.as_deref())
                .await
            {
                tracing::error!(%e, "failed to store vulnerability");
            }
        }

        // Save raw output to file
        self.save_raw_output(ip, &output).await;

        tracing::info!(ip = %ip, vulns = vulns.len(), "vulnerability scan complete");
        true
    }

    /// Save the raw nmap output to a file for later review.
    async fn save_raw_output(&self, ip: &str, output: &str) {
        let dir = &self.state.paths.vulnerabilities_dir;
        let sanitized_ip = ip.replace('.', "_");
        let path = dir.join(format!("{sanitized_ip}_vuln_scan.txt"));

        if let Err(e) = tokio::fs::write(&path, output).await {
            tracing::error!(%e, "failed to save vuln scan output");
        }
    }
}

/// A parsed vulnerability from nmap output.
#[derive(Debug, Clone)]
struct ParsedVuln {
    description: String,
    port: Option<u16>,
    severity: Option<String>,
}

/// Parse nmap vulners.nse output for vulnerability references.
fn parse_vulnerabilities(output: &str) -> Vec<ParsedVuln> {
    let mut vulns = Vec::new();
    let mut current_port: Option<u16> = None;

    for line in output.lines() {
        let trimmed = line.trim();

        // Detect port context lines like "22/tcp open ssh"
        if let Some(slash_pos) = trimmed.find("/tcp") {
            if let Ok(port) = trimmed[..slash_pos].parse::<u16>() {
                current_port = Some(port);
            }
        }

        // Capture lines with vulnerability indicators
        if trimmed.contains("CVE-")
            || trimmed.contains("VULNERABLE")
            || trimmed.contains("*EXPLOIT*")
        {
            let severity = if trimmed.contains("*EXPLOIT*") {
                Some("CRITICAL".to_string())
            } else {
                None
            };

            vulns.push(ParsedVuln {
                description: trimmed.to_string(),
                port: current_port,
                severity,
            });
        }
    }
    vulns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vuln_output() {
        let output = r#"
22/tcp open  ssh     OpenSSH 7.9p1
| vulners:
|   cpe:/a:openbsd:openssh:7.9p1:
|     CVE-2019-6111  5.8  https://vulners.com/cve/CVE-2019-6111
|     CVE-2023-38408  9.8  *EXPLOIT*
80/tcp open  http    Apache httpd 2.4.38
|     CVE-2019-0211  7.2  https://vulners.com/cve/CVE-2019-0211
"#;
        let vulns = parse_vulnerabilities(output);
        assert_eq!(vulns.len(), 3);
        assert_eq!(vulns[0].port, Some(22));
        assert!(vulns[0].description.contains("CVE-2019-6111"));
        assert_eq!(vulns[1].severity.as_deref(), Some("CRITICAL"));
        assert_eq!(vulns[2].port, Some(80));
    }

    #[test]
    fn parse_empty_output() {
        let vulns = parse_vulnerabilities("");
        assert!(vulns.is_empty());
    }

    #[test]
    fn parse_no_cves_found() {
        let output = r#"
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-01 00:00 UTC
22/tcp open  ssh     OpenSSH 8.9p1
| vulners:
|   cpe:/a:openbsd:openssh:8.9p1:
|       No known vulnerabilities
80/tcp open  http    nginx 1.24.0
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"#;
        let vulns = parse_vulnerabilities(output);
        assert!(vulns.is_empty(), "expected no vulns but found {vulns:?}");
    }

    #[test]
    fn parse_malformed_port_line() {
        // Port line with non-numeric prefix should not crash
        let output = "abc/tcp open ssh\n  CVE-2020-1234 7.5\n";
        let vulns = parse_vulnerabilities(output);
        assert_eq!(vulns.len(), 1);
        // Port should be None because "abc" does not parse as u16
        assert_eq!(vulns[0].port, None);
        assert!(vulns[0].description.contains("CVE-2020-1234"));
    }

    #[test]
    fn parse_malformed_no_slash_tcp() {
        // Lines without /tcp should not set current_port
        let output = "some random line\n  CVE-2021-9999 5.0\n";
        let vulns = parse_vulnerabilities(output);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].port, None);
    }

    #[test]
    fn parse_multiple_cves_same_port() {
        let output = r#"
443/tcp open  https   Apache 2.4.49
|     CVE-2021-41773  7.5  https://vulners.com/cve/CVE-2021-41773
|     CVE-2021-42013  9.8  https://vulners.com/cve/CVE-2021-42013
|     CVE-2021-40438  9.0  *EXPLOIT*
|     CVE-2021-44790  9.8  https://vulners.com/cve/CVE-2021-44790
"#;
        let vulns = parse_vulnerabilities(output);
        assert_eq!(vulns.len(), 4);
        for vuln in &vulns {
            assert_eq!(vuln.port, Some(443));
        }
        // Only the *EXPLOIT* one should have CRITICAL severity
        assert_eq!(vulns[0].severity, None);
        assert_eq!(vulns[1].severity, None);
        assert_eq!(vulns[2].severity.as_deref(), Some("CRITICAL"));
        assert_eq!(vulns[3].severity, None);
    }

    #[test]
    fn parse_multiple_ports_interleaved() {
        let output = r#"
22/tcp open  ssh
|     CVE-2020-1111  5.0
8080/tcp open  http-proxy
|     CVE-2020-2222  8.0
3306/tcp open  mysql
|     CVE-2020-3333  6.5
|     CVE-2020-4444  7.0  *EXPLOIT*
"#;
        let vulns = parse_vulnerabilities(output);
        assert_eq!(vulns.len(), 4);
        assert_eq!(vulns[0].port, Some(22));
        assert_eq!(vulns[1].port, Some(8080));
        assert_eq!(vulns[2].port, Some(3306));
        assert_eq!(vulns[3].port, Some(3306));
    }

    #[test]
    fn parse_vulnerable_keyword() {
        let output = "80/tcp open http\n  VULNERABLE: httpd allows directory listing\n";
        let vulns = parse_vulnerabilities(output);
        assert_eq!(vulns.len(), 1);
        assert!(vulns[0].description.contains("VULNERABLE"));
        assert_eq!(vulns[0].port, Some(80));
        // VULNERABLE alone does not trigger CRITICAL — only *EXPLOIT* does
        assert_eq!(vulns[0].severity, None);
    }

    #[test]
    fn parse_exploit_marker_sets_critical() {
        let output = "22/tcp open ssh\n  *EXPLOIT* some-exploit-db-ref\n";
        let vulns = parse_vulnerabilities(output);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity.as_deref(), Some("CRITICAL"));
    }

    #[test]
    fn parse_cve_without_port_context() {
        // CVE appears before any port line
        let output = "  CVE-2023-0001  10.0  *EXPLOIT*\n22/tcp open ssh\n  CVE-2023-0002  5.0\n";
        let vulns = parse_vulnerabilities(output);
        assert_eq!(vulns.len(), 2);
        // First CVE has no port context
        assert_eq!(vulns[0].port, None);
        assert_eq!(vulns[0].severity.as_deref(), Some("CRITICAL"));
        // Second CVE is under port 22
        assert_eq!(vulns[1].port, Some(22));
        assert_eq!(vulns[1].severity, None);
    }

    #[test]
    fn parse_whitespace_only_output() {
        let vulns = parse_vulnerabilities("   \n\n  \t  \n");
        assert!(vulns.is_empty());
    }

    #[test]
    fn parsed_vuln_clone() {
        let vuln = ParsedVuln {
            description: "CVE-2024-0001".to_string(),
            port: Some(443),
            severity: Some("CRITICAL".to_string()),
        };
        let cloned = vuln.clone();
        assert_eq!(cloned.description, vuln.description);
        assert_eq!(cloned.port, vuln.port);
        assert_eq!(cloned.severity, vuln.severity);
    }
}
