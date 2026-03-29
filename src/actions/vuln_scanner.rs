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
        if trimmed.contains("CVE-") || trimmed.contains("VULNERABLE") || trimmed.contains("*EXPLOIT*")
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
}
