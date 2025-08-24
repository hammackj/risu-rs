use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Rough STIG findings summary template.
pub struct StigFindingsSummaryTemplate;

impl Template for StigFindingsSummaryTemplate {
    fn name(&self) -> &str {
        "stig_findings_summary"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
    ) -> Result<(), Box<dyn Error>> {
        renderer.text("STIG Findings Summary")?;

        // Summarize counts by severity level.
        let mut counts = [0usize; 5];
        for item in &report.items {
            if let Some(sev) = item.severity {
                if (0..5).contains(&sev) {
                    counts[sev as usize] += 1;
                }
            }
        }
        for (sev, count) in counts.iter().enumerate() {
            renderer.text(&format!("Severity {sev}: {count} findings"))?;
        }
        Ok(())
    }
}
