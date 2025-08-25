use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Placeholder implementation for the exec_summary template.
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
        renderer.text(title)?;
        renderer.text(&format!("Hosts: {}", report.hosts.len()))?;
        Ok(())
    }
}
