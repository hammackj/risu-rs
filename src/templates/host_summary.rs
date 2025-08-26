use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{
    template_helper::{self, host, shares},
    Template,
};

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
            renderer.text(&host::host_heading(host))?;
            renderer.text(&host::host_label(host))?;

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
            let sev_fields = [
                template_helper::field("Critical", &counts[4].to_string()),
                template_helper::field("High", &counts[3].to_string()),
                template_helper::field("Medium", &counts[2].to_string()),
                template_helper::field("Low", &counts[1].to_string()),
                template_helper::field("Info", &counts[0].to_string()),
            ]
            .join("\n");
            renderer.text(&sev_fields)?;

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
            renderer.text(&shares::share_enumeration(&shares))?;
        }
        Ok(())
    }
}
