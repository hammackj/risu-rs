use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{helpers, malware_template_helper, scan_helper, Template};

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
        renderer.text(&scan_helper::summary(report))?;

        // Severity breakdown
        let mut severities = [0u32; 5];
        for item in &report.items {
            if let Some(sev) = item.severity {
                if (0..=4).contains(&sev) {
                    severities[sev as usize] += 1;
                }
            }
        }
        let severity_text = format!(
            "{}\nCritical: {}\nHigh: {}\nMedium: {}\nLow: {}\nInfo: {}",
            helpers::heading2("Severity Breakdown"),
            severities[4],
            severities[3],
            severities[2],
            severities[1],
            severities[0]
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
        let mut lines = vec![helpers::heading2("Top Hosts")];
        for (name, count) in host_vec {
            lines.push(format!("- {name}: {count}"));
        }
        renderer.text(&lines.join("\n"))?;

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
        let mut lines = vec![helpers::heading2("Remediation Summary")];
        for (name, count) in plugin_vec {
            lines.push(format!("- {name}: {count}"));
        }
        renderer.text(&lines.join("\n"))?;

        // Authentication status
        renderer.text(&scan_helper::authentication_section(report))?;

        // Conficker section
        let conficker_hosts: Vec<String> = report
            .items
            .iter()
            .filter(|i| i.plugin_name.as_deref() == Some("Conficker Worm Detection (uncredentialed check)"))
            .filter_map(|i| {
                i.host_id.and_then(|hid| {
                    report
                        .hosts
                        .get(hid as usize)
                        .and_then(|h| h.name.clone())
                })
            })
            .collect();
        let conf_refs: Vec<&str> = conficker_hosts.iter().map(|s| s.as_str()).collect();
        renderer.text(&malware_template_helper::conficker_section(&conf_refs))?;

        Ok(())
    }
}
