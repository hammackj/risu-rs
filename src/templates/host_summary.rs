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
    ) -> Result<(), Box<dyn Error>> {
        renderer.text("Host Summary Report")?;
        renderer.text(&format!("Total Hosts: {}", report.hosts.len()))?;
        for host in &report.hosts {
            let name = host.name.as_deref().unwrap_or("unknown");
            renderer.text(&format!("Host: {name}"))?;
        }
        Ok(())
    }
}
