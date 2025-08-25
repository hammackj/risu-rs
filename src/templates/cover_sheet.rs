use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Placeholder implementation for the cover_sheet template.
pub struct CoverSheetTemplate;

impl Template for CoverSheetTemplate {
    fn name(&self) -> &str {
        "cover_sheet"
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
            .unwrap_or("Cover Sheet");
        renderer.text(title)?;
        renderer.text(&format!("Hosts: {}", report.hosts.len()))?;
        Ok(())
    }
}
