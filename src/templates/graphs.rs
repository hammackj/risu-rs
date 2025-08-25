use std::collections::HashMap;
use std::error::Error;

use crate::graphs;
use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Placeholder implementation for the graphs template.
pub struct GraphsTemplate;

impl Template for GraphsTemplate {
    fn name(&self) -> &str {
        "graphs"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        let title = args.get("title").map(String::as_str).unwrap_or("Graphs");
        renderer.heading(1, title)?;
        let tmp = std::env::temp_dir();
        if let Ok(p) = graphs::os_distribution(report, &tmp) {
            renderer.text(&format!("OS distribution chart: {}", p.display()))?;
        }
        if let Ok(p) = graphs::top_vulnerabilities(report, &tmp, 5) {
            renderer.text(&format!("Top vulnerabilities chart: {}", p.display()))?;
        }
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
    name: "graphs",
    author: "ported",
    renderer: "text",
};
