use std::path::{Path, PathBuf};

/// All filesystem paths used by Bjorn.
///
/// Immutable once constructed. Mirrors `SharedData.initialize_paths()` from Python.
#[derive(Debug, Clone)]
pub struct PathConfig {
    /// Root directory of the Bjorn installation
    pub root: PathBuf,

    // -- Top-level directories --
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub actions_dir: PathBuf,
    pub web_dir: PathBuf,
    pub resources_dir: PathBuf,
    pub backup_base_dir: PathBuf,

    // -- Under backup --
    pub backups_dir: PathBuf,
    pub uploads_dir: PathBuf,

    // -- Under data --
    pub logs_dir: PathBuf,
    pub output_dir: PathBuf,
    pub input_dir: PathBuf,

    // -- Under output --
    pub cracked_pwd_dir: PathBuf,
    pub data_stolen_dir: PathBuf,
    pub zombies_dir: PathBuf,
    pub vulnerabilities_dir: PathBuf,
    pub scan_results_dir: PathBuf,

    // -- Under resources --
    pub images_dir: PathBuf,
    pub fonts_dir: PathBuf,
    pub comments_dir: PathBuf,
    pub status_images_dir: PathBuf,
    pub static_images_dir: PathBuf,

    // -- Under input --
    pub dictionary_dir: PathBuf,

    // -- Config files --
    pub shared_config_json: PathBuf,
    pub actions_json: PathBuf,

    // -- Resource files --
    pub comments_json: PathBuf,

    // -- Data files --
    pub netkb_db: PathBuf,
    pub livestatus_file: PathBuf,

    // -- Vulnerability files --
    pub vuln_summary_file: PathBuf,
    pub vuln_scan_progress_file: PathBuf,

    // -- Dictionary files --
    pub users_file: PathBuf,
    pub passwords_file: PathBuf,

    // -- Credential output files --
    pub ssh_creds_file: PathBuf,
    pub smb_creds_file: PathBuf,
    pub telnet_creds_file: PathBuf,
    pub ftp_creds_file: PathBuf,
    pub sql_creds_file: PathBuf,
    pub rdp_creds_file: PathBuf,

    // -- Log files --
    pub web_console_log: PathBuf,
}

impl PathConfig {
    /// Construct all paths relative to the given root directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();

        let config_dir = root.join("config");
        let data_dir = root.join("data");
        let actions_dir = root.join("actions");
        let web_dir = root.join("web");
        let resources_dir = root.join("resources");
        let backup_base_dir = root.join("backup");

        let backups_dir = backup_base_dir.join("backups");
        let uploads_dir = backup_base_dir.join("uploads");

        let logs_dir = data_dir.join("logs");
        let output_dir = data_dir.join("output");
        let input_dir = data_dir.join("input");

        let cracked_pwd_dir = output_dir.join("crackedpwd");
        let data_stolen_dir = output_dir.join("data_stolen");
        let zombies_dir = output_dir.join("zombies");
        let vulnerabilities_dir = output_dir.join("vulnerabilities");
        let scan_results_dir = output_dir.join("scan_results");

        let images_dir = resources_dir.join("images");
        let fonts_dir = resources_dir.join("fonts");
        let comments_dir = resources_dir.join("comments");
        let status_images_dir = images_dir.join("status");
        let static_images_dir = images_dir.join("static");

        let dictionary_dir = input_dir.join("dictionary");

        Self {
            shared_config_json: config_dir.join("shared_config.json"),
            actions_json: config_dir.join("actions.json"),
            comments_json: comments_dir.join("comments.json"),
            netkb_db: data_dir.join("netkb.db"),
            livestatus_file: data_dir.join("livestatus.csv"),
            vuln_summary_file: vulnerabilities_dir.join("vulnerability_summary.csv"),
            vuln_scan_progress_file: vulnerabilities_dir.join("scan_progress.json"),
            users_file: dictionary_dir.join("users.txt"),
            passwords_file: dictionary_dir.join("passwords.txt"),
            ssh_creds_file: cracked_pwd_dir.join("ssh.csv"),
            smb_creds_file: cracked_pwd_dir.join("smb.csv"),
            telnet_creds_file: cracked_pwd_dir.join("telnet.csv"),
            ftp_creds_file: cracked_pwd_dir.join("ftp.csv"),
            sql_creds_file: cracked_pwd_dir.join("sql.csv"),
            rdp_creds_file: cracked_pwd_dir.join("rdp.csv"),
            web_console_log: logs_dir.join("temp_log.txt"),

            root,
            config_dir,
            data_dir,
            actions_dir,
            web_dir,
            resources_dir,
            backup_base_dir,
            backups_dir,
            uploads_dir,
            logs_dir,
            output_dir,
            input_dir,
            cracked_pwd_dir,
            data_stolen_dir,
            zombies_dir,
            vulnerabilities_dir,
            scan_results_dir,
            images_dir,
            fonts_dir,
            comments_dir,
            status_images_dir,
            static_images_dir,
            dictionary_dir,
        }
    }

    /// Create all necessary directories. Idempotent.
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        let dirs = [
            &self.config_dir,
            &self.logs_dir,
            &self.cracked_pwd_dir,
            &self.data_stolen_dir,
            &self.zombies_dir,
            &self.vulnerabilities_dir,
            &self.scan_results_dir,
            &self.backups_dir,
            &self.uploads_dir,
            &self.dictionary_dir,
            &self.status_images_dir,
            &self.static_images_dir,
        ];
        for dir in dirs {
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }
}

impl Default for PathConfig {
    fn default() -> Self {
        Self::new("/home/bjorn/Bjorn")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_relative_to_root() {
        let paths = PathConfig::new("/opt/bjorn");
        assert_eq!(paths.config_dir, Path::new("/opt/bjorn/config"));
        assert_eq!(
            paths.shared_config_json,
            Path::new("/opt/bjorn/config/shared_config.json")
        );
        assert_eq!(paths.netkb_db, Path::new("/opt/bjorn/data/netkb.db"));
        assert_eq!(
            paths.ssh_creds_file,
            Path::new("/opt/bjorn/data/output/crackedpwd/ssh.csv")
        );
    }
}
