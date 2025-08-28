use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{template_helper::graph, Template};

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
        if let Ok(uri) = graph::os_distribution_data_uri(report, &tmp) {
            renderer.heading(2, "OS distribution (Windows 2000/XP variants combined)")?;
            renderer.image_data_uri(&uri)?;
        }
        if let Ok(uri) = graph::top_vuln_data_uri(report, &tmp, 5) {
            renderer.heading(2, "Top vulnerabilities")?;
            renderer.image_data_uri(&uri)?;
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
