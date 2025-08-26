use std::collections::HashMap;
use std::error::Error;

use crate::analysis::risk;
use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Placeholder implementation for the executive_summary_detailed template.
pub struct ExecutiveSummaryDetailedTemplate;

impl Template for ExecutiveSummaryDetailedTemplate {
    fn name(&self) -> &str {
        "executive_summary_detailed"
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
            .unwrap_or("Executive Summary Detailed");
        renderer.text(title)?;
        renderer.text(&format!("Hosts: {}", report.hosts.len()))?;

        let mut severities = [0u32; 5];
        for item in &report.items {
            if let Some(sev) = item.severity {
                if (0..=4).contains(&sev) {
                    severities[sev as usize] += 1;
                }
            }
        }
        let network = risk::Network {
            critical: severities[4],
            high: severities[3],
            medium: severities[2],
            low: severities[1],
        };
        let risk_score = network.risk_score();
        renderer.text(&format!("Risk Score: {:.2}", risk_score))?;
        renderer.text(
            "Risk scores derived from weighted averages of finding severities (Critical=9, High=7, Medium=4, Low=1).",
        )?;
        Ok(())
    }
}
