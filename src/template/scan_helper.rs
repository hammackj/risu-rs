use super::helpers;
use crate::parser::NessusReport;

/// Produce a simple scan summary.
pub fn summary(report: &NessusReport) -> String {
    format!(
        "{}\nHosts: {}\nItems: {}",
        helpers::heading2("Scan Summary"),
        report.hosts.len(),
        report.items.len()
    )
}

/// Calculate counts of authenticated vs unauthenticated hosts using plugin 19506 output.
fn authenticated_count(report: &NessusReport) -> (usize, usize) {
    let mut auth = 0usize;
    let mut unauth = 0usize;
    for item in &report.items {
        if item.plugin_id == Some(19506) {
            if let Some(ref output) = item.plugin_output {
                for line in output.lines() {
                    if let Some((key, value)) = line.split_once(':') {
                        if key.trim().eq_ignore_ascii_case("credentialed checks") {
                            if value.to_lowercase().contains("yes") {
                                auth += 1;
                            } else {
                                unauth += 1;
                            }
                        }
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
    use crate::models::{Host, Item};

    fn sample_report() -> NessusReport {
        NessusReport {
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
