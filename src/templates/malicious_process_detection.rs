use std::collections::HashMap;
use std::error::Error;

use crate::models::Item;
use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Port of the Ruby `malicious_process_detection.rb` template.
pub struct MaliciousProcessDetectionTemplate;

impl Template for MaliciousProcessDetectionTemplate {
    fn name(&self) -> &str {
        "malicious_process_detection"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        _args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        renderer.text("Malicious Process Detection Findings")?;
        let items: Vec<&Item> = report
            .items
            .iter()
            .filter(|i| i.plugin_id == Some(59275))
            .collect();
        for item in items {
            let host = item
                .host_id
                .and_then(|id| report.hosts.get(id as usize))
                .and_then(|h| h.name.clone().or(h.fqdn.clone()).or(h.ip.clone()))
                .unwrap_or_else(|| "unknown".into());
            renderer.text(&format!("Host: {host}"))?;
            if let Some(output) = &item.plugin_output {
                renderer.text(output)?;
            }
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
    name: "malicious_process_detection",
    author: "hammackj",
    renderer: "text",
};
