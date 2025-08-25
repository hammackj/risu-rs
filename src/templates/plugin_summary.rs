use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Placeholder implementation for the plugin_summary template.
pub struct PluginSummaryTemplate;

impl Template for PluginSummaryTemplate {
    fn name(&self) -> &str {
        "plugin_summary"
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
            .unwrap_or("Plugin Summary");
        renderer.text(title)?;
        renderer.text(&format!("Hosts: {}", report.hosts.len()))?;
        Ok(())
    }
}
