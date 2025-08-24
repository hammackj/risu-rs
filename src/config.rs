use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

/// Application configuration loaded from a YAML file.
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// URL of the database to connect to.
    #[serde(default = "default_database_url")]
    pub database_url: String,
    /// Logging level used by the application.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Paths to search for compiled template modules.
    #[serde(default = "default_template_paths")]
    pub template_paths: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: default_database_url(),
            log_level: default_log_level(),
            template_paths: default_template_paths(),
        }
    }
}

fn default_database_url() -> String {
    "sqlite://:memory:".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_template_paths() -> Vec<String> {
    vec!["./templates".to_string()]
}

/// Write a configuration file containing default values to the given path.
pub fn create_config(path: &Path) -> std::io::Result<()> {
    let cfg = Config::default();
    let yaml = serde_yaml::to_string(&cfg).expect("serialize default config");
    fs::write(path, yaml)
}

/// Load configuration from the given path, falling back to defaults when
/// values are missing or empty.
pub fn load_config(path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    let mut cfg: Config = serde_yaml::from_str(&raw).unwrap_or_default();

    if cfg.database_url.trim().is_empty() {
        cfg.database_url = default_database_url();
    }
    if cfg.log_level.trim().is_empty() {
        cfg.log_level = default_log_level();
    }
    if cfg.template_paths.is_empty() {
        cfg.template_paths = default_template_paths();
    }

    Ok(cfg)
}

