use std::error::Error;
use std::fs;
use std::path::Path;

use crate::{graphs, parser::NessusReport};

use super::helpers;

/// Generate an OS distribution graph and return a data URI embedding.
pub fn os_distribution_data_uri(
    report: &NessusReport,
    dir: &Path,
) -> Result<String, Box<dyn Error>> {
    let path = graphs::os_distribution(report, dir)?;
    let bytes = fs::read(path)?;
    helpers::embed_graph(&bytes)
}

/// Generate a top vulnerability graph and return a data URI embedding.
pub fn top_vuln_data_uri(
    report: &NessusReport,
    dir: &Path,
    n: usize,
) -> Result<String, Box<dyn Error>> {
    let path = graphs::top_vulnerabilities(report, dir, n)?;
    let bytes = fs::read(path)?;
    helpers::embed_graph(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Host, Item};
    use tempfile::tempdir;

    fn report() -> NessusReport {
        NessusReport {
            version: "1".into(),
            hosts: vec![Host {
                id: 1,
                nessus_report_id: None,
                name: Some("host1".into()),
                os: Some("Linux".into()),
                mac: None,
                start: None,
                end: None,
                ip: Some("10.0.0.1".into()),
                fqdn: None,
                netbios: None,
                notes: None,
                risk_score: None,
                user_id: None,
                engagement_id: None,
            }],
            items: vec![Item {
                id: 1,
                plugin_name: Some("vuln".into()),
                ..Default::default()
            }],
            plugins: Vec::new(),
            patches: Vec::new(),
            attachments: Vec::new(),
            host_properties: Vec::new(),
            service_descriptions: Vec::new(),
            references: Vec::new(),
            policies: Vec::new(),
            policy_plugins: Vec::new(),
            family_selections: Vec::new(),
            plugin_preferences: Vec::new(),
            server_preferences: Vec::new(),
        }
    }

    #[test]
    fn produces_data_uris() {
        let r = report();
        let dir = tempdir().unwrap();
        let os_uri = os_distribution_data_uri(&r, dir.path()).unwrap();
        assert!(os_uri.starts_with("data:image/png;base64,"));
        let vuln_uri = top_vuln_data_uri(&r, dir.path(), 5).unwrap();
        assert!(vuln_uri.starts_with("data:image/png;base64,"));
    }
}
