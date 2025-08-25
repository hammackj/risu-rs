use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Placeholder implementation for the top_25 template.
pub struct Top25Template;

impl Template for Top25Template {
    fn name(&self) -> &str {
        "top_25"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        let title = args.get("title").map(String::as_str).unwrap_or("Top 25");
        renderer.text(title)?;
        renderer.text(&format!("Hosts: {}", report.hosts.len()))?;
        Ok(())
    }
}
