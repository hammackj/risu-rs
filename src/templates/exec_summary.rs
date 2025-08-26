use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{
    template_helper::{self, malware, scan},
    Template,
};

/// Implementation of the exec_summary template providing an overview similar to the Ruby version.
pub struct ExecSummaryTemplate;

impl Template for ExecSummaryTemplate {
    fn name(&self) -> &str {
        "exec_summary"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        let title = args
            .get("title")
            .map(String::as_str)
            .unwrap_or("Exec Summary");
        renderer.heading(1, title)?;

        // Scan summary
        renderer.text(&scan::summary(report))?;

        // Severity breakdown
        let mut severities = [0u32; 5];
        for item in &report.items {
            if let Some(sev) = item.severity {
                if (0..=4).contains(&sev) {
                    severities[sev as usize] += 1;
                }
            }
        }
        let severity_fields = [
            template_helper::field("Critical", &severities[4].to_string()),
            template_helper::field("High", &severities[3].to_string()),
            template_helper::field("Medium", &severities[2].to_string()),
            template_helper::field("Low", &severities[1].to_string()),
            template_helper::field("Info", &severities[0].to_string()),
        ]
        .join("\n");
        let severity_text = format!(
            "{}\n{}",
            template_helper::heading(2, "Severity Breakdown"),
            severity_fields
        );
        renderer.text(&severity_text)?;

        // Top hosts by non-informational findings
        let mut host_counts: HashMap<&str, u32> = HashMap::new();
        for item in &report.items {
            if item.severity.unwrap_or(0) > 0 {
                if let Some(hid) = item.host_id {
                    if let Some(host) = report.hosts.get(hid as usize) {
                        if let Some(name) = host.name.as_deref() {
                            *host_counts.entry(name).or_default() += 1;
                        }
                    }
                }
            }
        }
        let mut host_vec: Vec<(&str, u32)> = host_counts.into_iter().collect();
        host_vec.sort_by(|a, b| b.1.cmp(&a.1));
        host_vec.truncate(5);
        let host_lines: Vec<String> = host_vec
            .into_iter()
            .map(|(name, count)| format!("{name}: {count}"))
            .collect();
        let host_section = format!(
            "{}\n{}",
            template_helper::heading(2, "Top Hosts"),
            template_helper::bullet_list(&host_lines)
        );
        renderer.text(&host_section)?;

        // Remediation summary – top plugins by count
        let mut plugin_counts: HashMap<&str, u32> = HashMap::new();
        for item in &report.items {
            if item.severity.unwrap_or(0) > 0 {
                if let Some(pname) = item.plugin_name.as_deref() {
                    *plugin_counts.entry(pname).or_default() += 1;
                }
            }
        }
        let mut plugin_vec: Vec<(&str, u32)> = plugin_counts.into_iter().collect();
        plugin_vec.sort_by(|a, b| b.1.cmp(&a.1));
        plugin_vec.truncate(5);
        let plugin_lines: Vec<String> = plugin_vec
            .into_iter()
            .map(|(name, count)| format!("{name}: {count}"))
            .collect();
        let plugin_section = format!(
            "{}\n{}",
            template_helper::heading(2, "Remediation Summary"),
            template_helper::bullet_list(&plugin_lines)
        );
        renderer.text(&plugin_section)?;

        // Authentication status
        renderer.text(&scan::authentication_section(report))?;

        // Conficker section
        let conficker_hosts: Vec<String> = report
            .items
            .iter()
            .filter(|i| {
                i.plugin_name.as_deref() == Some("Conficker Worm Detection (uncredentialed check)")
            })
            .filter_map(|i| {
                i.host_id
                    .and_then(|hid| report.hosts.get(hid as usize).and_then(|h| h.name.clone()))
            })
            .collect();
        let conf_refs: Vec<&str> = conficker_hosts.iter().map(|s| s.as_str()).collect();
        renderer.text(&malware::conficker_section(&conf_refs))?;

        Ok(())
    }
}
