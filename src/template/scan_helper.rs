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
}
