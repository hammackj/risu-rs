use super::helpers;
use crate::parser::NessusReport;
use std::collections::HashMap;

/// Produce a simple scan summary.
pub fn summary(report: &NessusReport) -> String {
    format!(
        "{}\nHosts: {}\nItems: {}",
        helpers::heading2("Scan Summary"),
        report.hosts.len(),
        report.items.len()
    )
}

/// Convert plugin 19506 output to a map of key/value pairs.
pub fn scan_info_to_hash(output: &str) -> HashMap<String, String> {
    output
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

/// Calculate counts of authenticated vs unauthenticated hosts using plugin 19506 output.
pub fn authenticated_count(report: &NessusReport) -> (usize, usize) {
    let mut auth = 0usize;
    let mut unauth = 0usize;
    for item in &report.items {
        if item.plugin_id == Some(19506) {
            if let Some(ref output) = item.plugin_output {
                let info = scan_info_to_hash(output);
                if let Some(v) = info.get("credentialed checks") {
                    if v.to_ascii_lowercase().contains("yes") {
                        auth += 1;
                    } else {
                        unauth += 1;
                    }
                }
            }
        }
    }
    (auth, unauth)
}

/// Render an authentication status section.
pub fn authentication_section(report: &NessusReport) -> String {
    let (auth, unauth) = authenticated_count(report);
    format!(
        "{}\nAuthenticated hosts: {}\nUnauthenticated hosts: {}",
        helpers::heading2("Authentication Status"),
        auth,
        unauth
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Host, Item, Report};

    fn sample_report() -> NessusReport {
        NessusReport {
            report: Report::default(),
            version: "1".into(),
            hosts: vec![Host {
                id: 1,
                nessus_report_id: None,
                name: Some("h".into()),
                os: None,
                mac: None,
                start: None,
                end: None,
                ip: None,
                fqdn: None,
                netbios: None,
                notes: None,
                risk_score: None,
                user_id: None,
                engagement_id: None,
            }],
            items: vec![Item {
                id: 1,
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
    fn summary_has_counts() {
        let report = sample_report();
        let s = summary(&report);
        assert!(s.contains("Hosts: 1"));
        assert!(s.contains("Items: 1"));
        assert!(s.starts_with("## Scan Summary"));
    }

    #[test]
    fn scan_info_to_hash_parses_output() {
        let out = "Credentialed checks : yes\nScanner : Nessus";
        let h = scan_info_to_hash(out);
        assert_eq!(h.get("credentialed checks"), Some(&"yes".to_string()));
        assert_eq!(h.get("scanner"), Some(&"Nessus".to_string()));
    }

    #[test]
    fn authenticated_count_classifies_hosts() {
        let mut report = sample_report();
        report.items = vec![
            Item {
                id: 1,
                host_id: Some(0),
                plugin_id: Some(19506),
                plugin_output: Some("Credentialed checks : yes".into()),
                ..Default::default()
            },
            Item {
                id: 2,
                host_id: Some(0),
                plugin_id: Some(19506),
                plugin_output: Some("Credentialed checks : no".into()),
                ..Default::default()
            },
        ];
        let (auth, unauth) = authenticated_count(&report);
        assert_eq!(auth, 1);
        assert_eq!(unauth, 1);
    }

    #[test]
    fn authentication_section_counts_hosts() {
        let mut report = sample_report();
        report.items = vec![
            Item {
                id: 1,
                host_id: Some(0),
                plugin_id: Some(19506),
                plugin_output: Some("Credentialed checks : yes".into()),
                ..Default::default()
            },
            Item {
                id: 2,
                host_id: Some(0),
                plugin_id: Some(19506),
                plugin_output: Some("Credentialed checks : no".into()),
                ..Default::default()
            },
        ];
        let section = authentication_section(&report);
        assert!(section.contains("Authenticated hosts: 1"));
        assert!(section.contains("Unauthenticated hosts: 1"));
    }
}
