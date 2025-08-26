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
        for (idx, host) in report.hosts.iter().enumerate() {
            renderer.text(&host_template_helper::host_heading(host))?;
            renderer.text(&host_template_helper::host_label(host))?;

            // Gather vulnerability counts for this host.
            let items: Vec<_> = report
                .items
                .iter()
                .filter(|it| {
                    it.host_id == Some(idx as i32)
                        || (it.host_id.is_none() && report.hosts.len() == 1)
                })
                .collect();
            let mut counts = [0u32; 5];
            for it in items {
                if let Some(sev) = it.severity {
                    if (0..=4).contains(&sev) {
                        counts[sev as usize] += 1;
                    }
                }
            }
            renderer.text(&format!(
                "Critical: {}\nHigh: {}\nMedium: {}\nLow: {}\nInfo: {}",
                counts[4], counts[3], counts[2], counts[1], counts[0]
            ))?;

            // Enumerate shares for this host from host properties with a `share-` prefix.
            let mut shares_vec: Vec<(String, String)> = report
                .host_properties
                .iter()
                .filter(|p| p.host_id == Some(idx as i32))
                .filter_map(|p| {
                    let name = p.name.as_ref()?;
                    let value = p.value.as_ref()?;
                    if name.starts_with("share-") {
                        Some((
                            name.trim_start_matches("share-").to_string(),
                            value.to_string(),
                        ))
                    } else {
                        None
                    }
                })
                .collect();
            let shares: Vec<(&str, &str)> = shares_vec
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            renderer.text(&shares_template_helper::share_enumeration(&shares))?;
        }
        Ok(())
    }
}
