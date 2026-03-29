use chrono::NaiveDateTime;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

use crate::error::Result;

/// SQLite-backed network knowledge base.
///
/// Replaces the CSV-based `netkb.csv` with proper ACID transactions
/// and concurrent-safe access via WAL mode.
#[derive(Debug, Clone)]
pub struct KnowledgeBase {
    pool: SqlitePool,
}

/// A discovered host on the network.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Host {
    pub id: i64,
    pub mac_address: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub alive: bool,
    pub ports: String, // Semicolon-separated port list, e.g. "22;80;443"
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
}

/// Result of an action executed against a host.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ActionResult {
    pub id: i64,
    pub host_id: i64,
    pub action_name: String,
    pub status: String, // "success" or "failed"
    pub executed_at: NaiveDateTime,
}

/// A cracked credential.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Credential {
    pub id: i64,
    pub host_id: i64,
    pub protocol: String, // "ssh", "ftp", "smb", "rdp", "telnet", "sql"
    pub username: String,
    pub password: String,
    pub port: u16,
    pub discovered_at: NaiveDateTime,
}

/// Summary of a vulnerability found on a host.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Vulnerability {
    pub id: i64,
    pub host_id: i64,
    pub port: u16,
    pub description: String,
    pub severity: Option<String>,
    pub discovered_at: NaiveDateTime,
}

impl KnowledgeBase {
    /// Open (or create) the SQLite database and run migrations.
    pub async fn open(db_path: &std::path::Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let options = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        let kb = Self { pool };
        kb.migrate().await?;
        Ok(kb)
    }

    /// Run schema migrations.
    async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS hosts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT    NOT NULL UNIQUE,
                ip          TEXT    NOT NULL,
                hostname    TEXT,
                alive       BOOLEAN NOT NULL DEFAULT 1,
                ports       TEXT    NOT NULL DEFAULT '',
                first_seen  DATETIME NOT NULL DEFAULT (datetime('now')),
                last_seen   DATETIME NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_hosts_alive ON hosts(alive);
            CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac_address);
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS action_results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id     INTEGER NOT NULL REFERENCES hosts(id),
                action_name TEXT    NOT NULL,
                status      TEXT    NOT NULL,
                executed_at DATETIME NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_ar_host_action
                ON action_results(host_id, action_name);
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS credentials (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id       INTEGER NOT NULL REFERENCES hosts(id),
                protocol      TEXT    NOT NULL,
                username      TEXT    NOT NULL,
                password      TEXT    NOT NULL,
                port          INTEGER NOT NULL,
                discovered_at DATETIME NOT NULL DEFAULT (datetime('now')),
                UNIQUE(host_id, protocol, username, port)
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id       INTEGER NOT NULL REFERENCES hosts(id),
                port          INTEGER NOT NULL,
                description   TEXT    NOT NULL,
                severity      TEXT,
                discovered_at DATETIME NOT NULL DEFAULT (datetime('now')),
                UNIQUE(host_id, port, description)
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // -- Host operations --

    /// Upsert a host by MAC address. Returns the host ID.
    pub async fn upsert_host(
        &self,
        mac_address: &str,
        ip: &str,
        hostname: Option<&str>,
        alive: bool,
        ports: &str,
    ) -> Result<i64> {
        let result = sqlx::query_scalar::<_, i64>(
            r#"
            INSERT INTO hosts (mac_address, ip, hostname, alive, ports, last_seen)
            VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))
            ON CONFLICT(mac_address) DO UPDATE SET
                ip = excluded.ip,
                hostname = COALESCE(excluded.hostname, hosts.hostname),
                alive = excluded.alive,
                ports = excluded.ports,
                last_seen = datetime('now')
            RETURNING id
            "#,
        )
        .bind(mac_address)
        .bind(ip)
        .bind(hostname)
        .bind(alive)
        .bind(ports)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Get all alive hosts.
    pub async fn alive_hosts(&self) -> Result<Vec<Host>> {
        let hosts = sqlx::query_as::<_, Host>("SELECT * FROM hosts WHERE alive = 1")
            .fetch_all(&self.pool)
            .await?;
        Ok(hosts)
    }

    /// Get all known hosts.
    pub async fn all_hosts(&self) -> Result<Vec<Host>> {
        let hosts = sqlx::query_as::<_, Host>("SELECT * FROM hosts ORDER BY last_seen DESC")
            .fetch_all(&self.pool)
            .await?;
        Ok(hosts)
    }

    /// Mark a host as dead.
    pub async fn mark_host_dead(&self, mac_address: &str) -> Result<()> {
        sqlx::query("UPDATE hosts SET alive = 0, last_seen = datetime('now') WHERE mac_address = ?1")
            .bind(mac_address)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // -- Action result operations --

    /// Record the result of an action execution.
    pub async fn record_action(
        &self,
        host_id: i64,
        action_name: &str,
        status: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO action_results (host_id, action_name, status)
            VALUES (?1, ?2, ?3)
            "#,
        )
        .bind(host_id)
        .bind(action_name)
        .bind(status)
        .fetch_optional(&self.pool)
        .await?;
        Ok(())
    }

    /// Get the latest action result for a host + action combination.
    pub async fn latest_action_result(
        &self,
        host_id: i64,
        action_name: &str,
    ) -> Result<Option<ActionResult>> {
        let result = sqlx::query_as::<_, ActionResult>(
            r#"
            SELECT * FROM action_results
            WHERE host_id = ?1 AND action_name = ?2
            ORDER BY id DESC
            LIMIT 1
            "#,
        )
        .bind(host_id)
        .bind(action_name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result)
    }

    // -- Credential operations --

    /// Store a cracked credential (ignores duplicates).
    pub async fn store_credential(
        &self,
        host_id: i64,
        protocol: &str,
        username: &str,
        password: &str,
        port: u16,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO credentials (host_id, protocol, username, password, port)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
        )
        .bind(host_id)
        .bind(protocol)
        .bind(username)
        .bind(password)
        .bind(port)
        .fetch_optional(&self.pool)
        .await?;
        Ok(())
    }

    /// Get all credentials, optionally filtered by protocol.
    pub async fn credentials(&self, protocol: Option<&str>) -> Result<Vec<Credential>> {
        let creds = if let Some(proto) = protocol {
            sqlx::query_as::<_, Credential>(
                "SELECT * FROM credentials WHERE protocol = ?1 ORDER BY discovered_at DESC",
            )
            .bind(proto)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, Credential>(
                "SELECT * FROM credentials ORDER BY discovered_at DESC",
            )
            .fetch_all(&self.pool)
            .await?
        };
        Ok(creds)
    }

    // -- Vulnerability operations --

    /// Store a vulnerability (ignores duplicates).
    pub async fn store_vulnerability(
        &self,
        host_id: i64,
        port: u16,
        description: &str,
        severity: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO vulnerabilities (host_id, port, description, severity)
            VALUES (?1, ?2, ?3, ?4)
            "#,
        )
        .bind(host_id)
        .bind(port)
        .bind(description)
        .bind(severity)
        .fetch_optional(&self.pool)
        .await?;
        Ok(())
    }

    /// Get all vulnerabilities.
    pub async fn vulnerabilities(&self) -> Result<Vec<Vulnerability>> {
        let vulns = sqlx::query_as::<_, Vulnerability>(
            "SELECT * FROM vulnerabilities ORDER BY discovered_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(vulns)
    }

    // -- Stats --

    /// Get summary counts for display.
    pub async fn stats(
        &self,
    ) -> Result<(u32, u32, u32, u32, u32)> {
        // (alive_hosts, total_hosts, total_creds, total_vulns, total_actions)
        let alive: (i32,) =
            sqlx::query_as("SELECT COUNT(*) FROM hosts WHERE alive = 1")
                .fetch_one(&self.pool)
                .await?;
        let total: (i32,) =
            sqlx::query_as("SELECT COUNT(*) FROM hosts")
                .fetch_one(&self.pool)
                .await?;
        let creds: (i32,) =
            sqlx::query_as("SELECT COUNT(*) FROM credentials")
                .fetch_one(&self.pool)
                .await?;
        let vulns: (i32,) =
            sqlx::query_as("SELECT COUNT(*) FROM vulnerabilities")
                .fetch_one(&self.pool)
                .await?;
        let actions: (i32,) =
            sqlx::query_as("SELECT COUNT(*) FROM action_results WHERE status = 'success'")
                .fetch_one(&self.pool)
                .await?;

        Ok((
            alive.0 as u32,
            total.0 as u32,
            creds.0 as u32,
            vulns.0 as u32,
            actions.0 as u32,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    async fn test_kb() -> (KnowledgeBase, TempDir) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let kb = KnowledgeBase::open(&db_path).await.unwrap();
        (kb, dir)
    }

    #[tokio::test]
    async fn upsert_and_query_host() {
        let (kb, _dir) = test_kb().await;

        let id = kb
            .upsert_host("aa:bb:cc:dd:ee:ff", "192.168.1.10", Some("victim"), true, "22;80")
            .await
            .unwrap();
        assert!(id > 0);

        let hosts = kb.alive_hosts().await.unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "192.168.1.10");
        assert_eq!(hosts[0].ports, "22;80");

        // Upsert same MAC with new IP
        let id2 = kb
            .upsert_host("aa:bb:cc:dd:ee:ff", "192.168.1.20", None, true, "22;80;443")
            .await
            .unwrap();
        assert_eq!(id, id2);

        let hosts = kb.alive_hosts().await.unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "192.168.1.20");
        assert_eq!(hosts[0].ports, "22;80;443");
    }

    #[tokio::test]
    async fn action_results() {
        let (kb, _dir) = test_kb().await;

        let host_id = kb
            .upsert_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None, true, "22")
            .await
            .unwrap();

        kb.record_action(host_id, "SshConnector", "failed")
            .await
            .unwrap();
        kb.record_action(host_id, "SshConnector", "success")
            .await
            .unwrap();

        let latest = kb
            .latest_action_result(host_id, "SshConnector")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.status, "success");
    }

    #[tokio::test]
    async fn credentials_dedup() {
        let (kb, _dir) = test_kb().await;

        let host_id = kb
            .upsert_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None, true, "22")
            .await
            .unwrap();

        kb.store_credential(host_id, "ssh", "root", "toor", 22)
            .await
            .unwrap();
        // Duplicate — should be ignored
        kb.store_credential(host_id, "ssh", "root", "toor", 22)
            .await
            .unwrap();

        let creds = kb.credentials(Some("ssh")).await.unwrap();
        assert_eq!(creds.len(), 1);
    }

    #[tokio::test]
    async fn stats_counts() {
        let (kb, _dir) = test_kb().await;

        let h1 = kb
            .upsert_host("aa:bb:cc:00:00:01", "10.0.0.1", None, true, "22")
            .await
            .unwrap();
        let _h2 = kb
            .upsert_host("aa:bb:cc:00:00:02", "10.0.0.2", None, false, "80")
            .await
            .unwrap();

        kb.store_credential(h1, "ssh", "root", "pass", 22)
            .await
            .unwrap();
        kb.store_vulnerability(h1, 22, "CVE-2024-1234", Some("HIGH"))
            .await
            .unwrap();
        kb.record_action(h1, "SshConnector", "success")
            .await
            .unwrap();

        let (alive, total, creds, vulns, actions) = kb.stats().await.unwrap();
        assert_eq!(alive, 1);
        assert_eq!(total, 2);
        assert_eq!(creds, 1);
        assert_eq!(vulns, 1);
        assert_eq!(actions, 1);
    }
}
