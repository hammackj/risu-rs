use std::collections::HashMap;
use std::error::Error;

use crate::models::Item;
use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Port of the Ruby `findings_host.rb` template.
pub struct FindingsHostTemplate;

impl Template for FindingsHostTemplate {
    fn name(&self) -> &str {
        "findings_host"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        _args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        renderer.text("Findings Summary by Host Report")?;

        for host in &report.hosts {
            let items: Vec<&Item> = report
                .items
                .iter()
                .filter(|i| i.host_id == Some(host.id) && i.severity.unwrap_or(0) >= 2)
                .collect();
            if items.is_empty() {
                continue;
            }
            let host_name = host
                .ip
                .clone()
                .or(host.fqdn.clone())
                .unwrap_or_else(|| "unknown".into());
            renderer.text(&host_name)?;

            for (label, sev) in [
                ("Critical Findings", 4),
                ("High Findings", 3),
                ("Medium Findings", 2),
            ] {
                let sev_items: Vec<&Item> = items
                    .iter()
                    .copied()
                    .filter(|i| i.severity == Some(sev))
                    .collect();
                if sev_items.is_empty() {
                    continue;
                }
                renderer.text(label)?;
                for item in sev_items {
                    let name = item
                        .plugin_name
                        .clone()
                        .unwrap_or_else(|| format!("Plugin {}", item.plugin_id.unwrap_or(0)));
                    renderer.text(&name)?;
                }
            }
            renderer.text("")?;
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
    name: "findings_host",
    author: "hammackj",
    renderer: "text",
};
