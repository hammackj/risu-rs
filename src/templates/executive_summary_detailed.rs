use std::collections::HashMap;
use std::error::Error;

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
        Ok(())
    }
}
