use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Rough port of the Host Summary report from the Ruby implementation.
pub struct HostSummaryTemplate;

impl Template for HostSummaryTemplate {
    fn name(&self) -> &str {
        "host_summary"
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
            .unwrap_or("Host Summary Report");
        renderer.text(title)?;
        renderer.text(&format!("Total Hosts: {}", report.hosts.len()))?;
        for host in &report.hosts {
            let name = host.name.as_deref().unwrap_or("unknown");
            renderer.text(&format!("Host: {name}"))?;
        }
        Ok(())
    }
}
