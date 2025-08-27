//! Loading and writing application configuration.
//!
//! Configuration is stored in a simple YAML file:
//!
//! ```yaml
//! database_url: sqlite://:memory:
//! log_level: info
//! template_paths:
//!   - ./templates
//! # Prefix added to report output paths when generating reports
//! report_prefix: reports/
//! # Default argument values passed to templates keyed by template name
//! template_settings:
//!   simple:
//!     title: Example Report
//! # Override plugin severities keyed by plugin ID
//! severity_overrides:
//!   41028: 0
//! ```

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};

/// Application configuration loaded from a YAML file.
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// URL of the database to connect to.
    #[serde(default = "default_database_url")]
    pub database_url: String,
    /// Logging level used by the application.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Log output format (plain or json).
    #[serde(default = "default_log_format")]
    pub log_format: String,
    /// Paths to search for compiled template modules.
    #[serde(default = "default_template_paths")]
    pub template_paths: Vec<String>,
    /// Report title metadata
    #[serde(default)]
    pub report_title: Option<String>,
    /// Report author metadata
    #[serde(default)]
    pub report_author: Option<String>,
    /// Report company metadata
    #[serde(default)]
    pub report_company: Option<String>,
    /// Report classification metadata
    #[serde(default)]
    pub report_classification: Option<String>,
    /// Prefix added to report output paths when generating reports
    #[serde(default)]
    pub report_prefix: Option<String>,
    /// Default argument values passed to templates keyed by template name
    #[serde(default)]
    pub template_settings: HashMap<String, HashMap<String, String>>,
    /// Override plugin severities keyed by plugin ID
    #[serde(default)]
    pub severity_overrides: HashMap<i32, i32>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: default_database_url(),
            log_level: default_log_level(),
            log_format: default_log_format(),
            template_paths: default_template_paths(),
            report_title: None,
            report_author: None,
            report_company: None,
            report_classification: None,
            report_prefix: None,
            template_settings: HashMap::new(),
            severity_overrides: HashMap::new(),
        }
    }
}

fn default_database_url() -> String {
    "sqlite://:memory:".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "plain".to_string()
}

fn default_template_paths() -> Vec<String> {
    vec!["./templates".to_string()]
}

/// Write a configuration file containing default values to the given path.
pub fn create_config(path: &Path) -> Result<(), crate::error::Error> {
    if path.exists() {
        return Err(crate::error::Error::Config(format!(
            "configuration file '{}' already exists",
            path.display()
        )));
    }
    let cfg = Config::default();
    let yaml = serde_yaml::to_string(&cfg)?;
    let mut output = String::new();
    for line in yaml.lines() {
        if line.starts_with("report_prefix:") {
            output.push_str("# Prefix added to report output paths\n");
            output.push_str("# report_prefix: reports/\n");
        }
        if line.starts_with("template_settings:") {
            output
                .push_str("# Default argument values passed to templates keyed by template name\n");
            output.push_str("# template_settings:\n#   simple:\n#     title: Example Report\n");
        }
        if line.starts_with("severity_overrides:") {
            output.push_str("# Override plugin severities keyed by plugin ID\n");
            output.push_str("# severity_overrides:\n#   41028: 0\n");
        }
        output.push_str(line);
        output.push('\n');
    }
    fs::write(path, output)?;
    Ok(())
}

/// Load configuration from the given path, falling back to defaults when
/// values are missing or empty.
pub fn load_config(path: &Path) -> Result<Config, crate::error::Error> {
    if !path.exists() {
        return Err(crate::error::Error::Config(format!(
            "configuration file '{}' not found",
            path.display()
        )));
    }
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
    if cfg.log_format.trim().is_empty() {
        cfg.log_format = default_log_format();
    }
    if cfg
        .report_prefix
        .as_ref()
        .map(|s| s.trim().is_empty())
        .unwrap_or(false)
    {
        cfg.report_prefix = None;
    }

    Ok(cfg)
}
