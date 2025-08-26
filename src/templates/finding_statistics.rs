use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Simple statistics about findings in the report.
pub struct FindingStatisticsTemplate;

impl Template for FindingStatisticsTemplate {
    fn name(&self) -> &str {
        "finding_statistics"
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
            .unwrap_or("Finding Statistics");
        renderer.heading(1, title)?;

        let host_count = report.hosts.len();
        let mut severities = [0u32; 5];
        for item in &report.items {
            if let Some(sev) = item.severity {
                if (0..=4).contains(&sev) {
                    severities[sev as usize] += 1;
                }
            }
        }
        let high = severities[4] + severities[3];
        let medium = severities[2];
        let low = severities[1];
        let info = severities[0];
        let total = high + medium + low + info;

        renderer.text(&format!("Number of hosts: {host_count}"))?;
        renderer.text(&format!("Number of risks: {total}"))?;
        renderer.text(&format!("High Risks: {high}"))?;
        renderer.text(&format!("Medium Risks: {medium}"))?;
        renderer.text(&format!("Low Risks: {low}"))?;
        renderer.text(&format!("Info Risks: {info}"))?;
        Ok(())
    }
}
