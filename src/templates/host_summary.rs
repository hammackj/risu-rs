use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{Template, host_template_helper, shares_template_helper};

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
            renderer.text(&host_template_helper::host_heading(host))?;
            renderer.text(&host_template_helper::host_label(host))?;
            renderer.text(&shares_template_helper::share_enumeration(&[]))?;
        }
        Ok(())
    }
}
