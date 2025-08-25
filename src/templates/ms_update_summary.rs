use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Placeholder implementation for the ms_update_summary template.
pub struct MSUpdateSummaryTemplate;

impl Template for MSUpdateSummaryTemplate {
    fn name(&self) -> &str {
        "ms_update_summary"
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
            .unwrap_or("Missing Microsoft Updates Summary");
        renderer.text(title)?;
        renderer.text(&format!("Patches: {}", report.patches.len()))?;
        Ok(())
    }
}

/// Metadata about this template.
pub struct Metadata {
    pub name: &'static str,
    pub author: &'static str,
    pub renderer: &'static str,
}

pub static METADATA: Metadata = Metadata {
    name: "ms_update_summary",
    author: "ported",
    renderer: "text",
};
