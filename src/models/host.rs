use super::{Host, Item};

/// Nessus plugin names that indicate unsupported Windows installations and the
/// corresponding operating system name.
pub const UNSUPPORTED_WINDOWS_PLUGINS: &[(&str, &str)] = &[
    (
        "Microsoft Windows NT 4.0 Unsupported Installation Detection",
        "Windows NT 4.0",
    ),
    (
        "Microsoft Windows 2000 Unsupported Installation Detection",
        "Windows 2000",
    ),
    (
        "Microsoft Windows XP Unsupported Installation Detection",
        "Windows XP",
    ),
    (
        "Microsoft Windows Server 2003 Unsupported Installation Detection",
        "Windows 2003",
    ),
    (
        "Microsoft Windows 8 Unsupported Installation Detection",
        "Windows 8",
    ),
];

impl Host {
    /// Return the unsupported Windows OS detected on this host, if any.
    pub fn unsupported_windows_os(&self, items: &[&Item]) -> Option<&'static str> {
        for item in items {
            if let Some(name) = item.plugin_name.as_deref() {
                for (plugin, os) in UNSUPPORTED_WINDOWS_PLUGINS {
                    if name == *plugin {
                        return Some(*os);
                    }
                }
            }
        }
        None
    }

    /// Whether this host is running an unsupported Windows OS.
    pub fn is_unsupported_windows(&self, items: &[&Item]) -> bool {
        self.unsupported_windows_os(items).is_some()
    }

    /// Explanatory text for an unsupported OS finding on this host.
    pub fn unsupported_windows_text(&self, items: &[&Item]) -> Option<String> {
        self.unsupported_windows_os(items)
            .map(|os| format!("Unsupported operating system: {os}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn make_item(plugin: &str) -> Item {
        Item {
            id: 1,
            host_id: Some(1),
            plugin_id: None,
            attachment_id: None,
            plugin_output: None,
            port: None,
            svc_name: None,
            protocol: None,
            severity: None,
            plugin_name: Some(plugin.into()),
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
        }
    }

    #[test]
    fn detects_unsupported() {
        let host = sample_host();
        let item = make_item("Microsoft Windows XP Unsupported Installation Detection");
        let items = vec![&item];
        assert_eq!(host.unsupported_windows_os(&items), Some("Windows XP"));
        assert!(host.is_unsupported_windows(&items));
    }

    #[test]
    fn no_detection_when_missing() {
        let host = sample_host();
        let items: Vec<&Item> = Vec::new();
        assert!(host.unsupported_windows_os(&items).is_none());
    }
}
