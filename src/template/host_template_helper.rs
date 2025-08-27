use super::{helpers, template_helper};
use crate::{
    models::{Host, host::UNSUPPORTED_WINDOWS_PLUGINS},
    parser::NessusReport,
};

/// Format the host name as a heading using existing helpers.
pub fn host_heading(host: &Host) -> String {
    let name = host.name.as_deref().unwrap_or("unknown");
    helpers::heading2(name)
}

/// Produce a label combining host name, IP address, and NetBIOS name if present.
pub fn host_label(host: &Host) -> String {
    let name = host.name.as_deref().unwrap_or("unknown");
    let ip = host.ip.as_deref().unwrap_or("n/a");
    if let Some(nb) = host.netbios.as_deref() {
        format!("{name} ({ip} / {nb})")
    } else {
        format!("{name} ({ip})")
    }
}

fn unsupported_os(title: &str, plugin_name: &str, report: &NessusReport) -> String {
    let hosts: Vec<String> = report
        .items
        .iter()
        .filter(|it| it.plugin_name.as_deref() == Some(plugin_name))
        .filter_map(|it| {
            it.host_id
                .and_then(|id| report.hosts.get(id as usize))
                .map(|h| host_label(h))
        })
        .collect();

    if hosts.is_empty() {
        String::new()
    } else {
        let mut out = String::new();
        out.push_str(&helpers::heading2(title));
        out.push('\n');
        out.push_str(&template_helper::bullet_list(hosts));
        out.push('\n');
        out
    }
}

/// Enumerate hosts running unsupported Windows versions.
pub fn unsupported_os_windows(report: &NessusReport) -> String {
    let mut out = String::new();
    for (plugin, os) in UNSUPPORTED_WINDOWS_PLUGINS {
        let title = format!("Unsupported {os} Installations");
        let section = unsupported_os(&title, plugin, report);
        if !section.is_empty() {
            out.push_str(&section);
            out.push('\n');
        }
    }
    out
}

/// Appendix section listing unsupported operating systems.
pub fn unsupported_os_appendix_section(report: &NessusReport) -> String {
    unsupported_os_windows(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Item, Scanner};

    fn sample_host() -> Host {
        Host {
            id: 1,
            nessus_report_id: None,
            name: Some("srv".into()),
            os: None,
            mac: None,
            start: None,
            end: None,
            ip: Some("1.1.1.1".into()),
            fqdn: None,
            netbios: None,
            notes: None,
            risk_score: None,
            user_id: None,
            engagement_id: None,
            scanner_id: None,
        }
    }

    #[test]
    fn heading_and_label() {
        let h = sample_host();
        assert_eq!(host_heading(&h), "## srv");
        assert_eq!(host_label(&h), "srv (1.1.1.1)");
    }

    #[test]
    fn label_includes_netbios() {
        let mut h = sample_host();
        h.netbios = Some("EXAMPLE".into());
        assert_eq!(host_label(&h), "srv (1.1.1.1 / EXAMPLE)");
    }

    #[test]
    fn unsupported_os_section_lists_host() {
        let host = sample_host();
        let item = Item {
            id: 1,
            host_id: Some(0),
            plugin_id: None,
            attachment_id: None,
            plugin_output: None,
            port: None,
            svc_name: None,
            protocol: None,
            severity: None,
            plugin_name: Some("Microsoft Windows XP Unsupported Installation Detection".into()),
            description: None,
            solution: None,
            risk_factor: None,
            cvss_base_score: None,
            verified: None,
            cm_compliance_info: None,
            cm_compliance_actual_value: None,
            cm_compliance_check_id: None,
            cm_compliance_policy_value: None,
            cm_compliance_audit_file: None,
            cm_compliance_check_name: None,
            cm_compliance_result: None,
            cm_compliance_output: None,
            cm_compliance_reference: None,
            cm_compliance_see_also: None,
            cm_compliance_solution: None,
            real_severity: None,
            risk_score: None,
            user_id: None,
            engagement_id: None,
            rollup_finding: Some(false),
            scanner_id: None,
        };
        let report = NessusReport {
            report: crate::models::Report::default(),
            version: String::new(),
            hosts: vec![host],
            items: vec![item],
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
            filters: crate::parser::Filters::default(),
            scanner: Scanner::default(),
        };

        let out = unsupported_os_windows(&report);
        assert!(out.contains("Unsupported Windows XP Installations"));
        assert!(out.contains("srv (1.1.1.1)"));
    }
}
