use std::collections::{BTreeMap, HashMap};
use std::error::Error;

use crate::models::Item;
use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Generate a "fix list" of high and critical findings grouped by host.
///
/// Each host is listed in alphabetical order with associated high/critical
/// findings. CVE identifiers referenced by each finding are included when
/// available. The template supports both PDF and CSV renderers via the common
/// [`Renderer`] trait.
pub struct FixListTemplate;

impl FixListTemplate {
    /// Map numeric severity levels to human readable labels.
    fn severity_label(sev: i32) -> &'static str {
        match sev {
            4 => "Critical",
            3 => "High",
            2 => "Medium",
            1 => "Low",
            _ => "Info",
        }
    }

    /// Determine a display name for a host.
    fn host_display(report: &NessusReport, item: &Item) -> String {
        item.host_id
            .and_then(|hid| report.hosts.get(hid as usize))
            .and_then(|h| {
                h.ip
                    .clone()
                    .or(h.fqdn.clone())
                    .or(h.netbios.clone())
                    .or(h.name.clone())
            })
            .unwrap_or_else(|| "unknown".into())
    }
}

impl Template for FixListTemplate {
    fn name(&self) -> &str {
        "fix_list"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        _args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        // Group findings by host using a BTreeMap for sorted output.
        let mut by_host: BTreeMap<String, Vec<&Item>> = BTreeMap::new();
        for item in &report.items {
            if item.severity.unwrap_or(0) < 3 {
                continue;
            }
            let host_name = Self::host_display(report, item);
            by_host.entry(host_name).or_default().push(item);
        }

        for (host, items) in by_host {
            // Sort findings for a host by severity (desc) then plugin id.
            let mut items: Vec<&Item> = items;
            items.sort_by(|a, b| {
                b.severity
                    .unwrap_or(0)
                    .cmp(&a.severity.unwrap_or(0))
                    .then_with(|| a.plugin_id.unwrap_or(0).cmp(&b.plugin_id.unwrap_or(0)))
            });

            // Write the host heading (works for CSV/PDF renderers).
            renderer.heading(2, &host)?;

            for item in items {
                let name = item
                    .plugin_name
                    .clone()
                    .unwrap_or_else(|| format!("Plugin {}", item.plugin_id.unwrap_or(0)));
                let severity = Self::severity_label(item.severity.unwrap_or(0));
                // Collect CVE identifiers from references.
                let cves: Vec<String> = report
                    .references
                    .iter()
                    .filter(|r| {
                        r.item_id == Some(item.id) && r.source.as_deref() == Some("CVE")
                    })
                    .filter_map(|r| r.value.clone())
                    .collect();
                let cve_str = if cves.is_empty() {
                    String::new()
                } else {
                    cves.join(";")
                };
                let line = if cve_str.is_empty() {
                    format!("{severity},{name}")
                } else {
                    format!("{severity},{name},{cve_str}")
                };
                renderer.text(&line)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Host, Reference, Report, Scanner};
    use crate::parser::Filters;
    use crate::renderer::CsvRenderer;

    #[test]
    fn groups_and_sorts_by_host() {
        // Hosts in unsorted order: "b" then "a"
        let host_b = Host {
            id: 0,
            nessus_report_id: None,
            name: Some("b".into()),
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
            scanner_id: None,
        };
        let host_a = Host {
            id: 1,
            nessus_report_id: None,
            name: Some("a".into()),
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
            scanner_id: None,
        };

        // Findings
        let item_b1 = Item {
            id: 1,
            host_id: Some(0),
            plugin_id: Some(1),
            plugin_name: Some("CriticalA".into()),
            severity: Some(4),
            ..Item::default()
        };
        let item_b2 = Item {
            id: 2,
            host_id: Some(0),
            plugin_id: Some(2),
            plugin_name: Some("HighA".into()),
            severity: Some(3),
            ..Item::default()
        };
        let item_a1 = Item {
            id: 3,
            host_id: Some(1),
            plugin_id: Some(3),
            plugin_name: Some("CriticalB".into()),
            severity: Some(4),
            ..Item::default()
        };

        let ref1 = Reference {
            id: 1,
            item_id: Some(1),
            plugin_id: None,
            source: Some("CVE".into()),
            value: Some("CVE-0001".into()),
            user_id: None,
            engagement_id: None,
        };
        let ref2 = Reference {
            id: 2,
            item_id: Some(2),
            plugin_id: None,
            source: Some("CVE".into()),
            value: Some("CVE-0002".into()),
            user_id: None,
            engagement_id: None,
        };
        let ref3 = Reference {
            id: 3,
            item_id: Some(3),
            plugin_id: None,
            source: Some("CVE".into()),
            value: Some("CVE-0003".into()),
            user_id: None,
            engagement_id: None,
        };

        let report = NessusReport {
            report: Report::default(),
            version: String::new(),
            hosts: vec![host_b, host_a],
            items: vec![item_b1, item_b2, item_a1],
            plugins: Vec::new(),
            patches: Vec::new(),
            attachments: Vec::new(),
            host_properties: Vec::new(),
            service_descriptions: Vec::new(),
            references: vec![ref1, ref2, ref3],
            policies: Vec::new(),
            policy_plugins: Vec::new(),
            family_selections: Vec::new(),
            plugin_preferences: Vec::new(),
            server_preferences: Vec::new(),
            scanner: Scanner::default(),
            filters: Filters::default(),
        };

        let mut renderer = CsvRenderer::new();
        FixListTemplate
            .generate(&report, &mut renderer, &HashMap::new())
            .unwrap();
        let mut buf = Vec::new();
        renderer.save(&mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(out.as_bytes());
        let lines: Vec<String> = rdr
            .records()
            .map(|r| r.unwrap().get(0).unwrap().to_string())
            .collect();

        assert_eq!(lines[0], "a");
        assert_eq!(lines[1], "Critical,CriticalB,CVE-0003");
        assert_eq!(lines[2], "b");
        assert_eq!(lines[3], "Critical,CriticalA,CVE-0001");
        assert_eq!(lines[4], "High,HighA,CVE-0002");
    }
}

