use std::collections::{BTreeMap, HashMap};
use std::error::Error;

use crate::models::ServiceDescription;
use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{Template, template_helper::host};

/// Inventory of detected network services grouped by host.
pub struct ServiceInventoryTemplate;

impl Template for ServiceInventoryTemplate {
    fn name(&self) -> &str {
        "service_inventory"
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
            .unwrap_or("Service Inventory");
        renderer.heading(1, title)?;

        // Group service descriptions by host id for deterministic output.
        let mut by_host: BTreeMap<i32, Vec<&ServiceDescription>> = BTreeMap::new();
        for sd in &report.service_descriptions {
            if let Some(hid) = sd.host_id {
                by_host.entry(hid).or_default().push(sd);
            }
        }

        for (hid, mut services) in by_host {
            let label = report
                .hosts
                .get(hid as usize)
                .map(host::host_label)
                .unwrap_or_else(|| format!("Host {hid}"));
            renderer.heading(2, &label)?;
            renderer.text("Service,Port,Banner")?;
            services.sort_by_key(|s| s.port.unwrap_or(0));
            for svc in services {
                let name = svc.svc_name.as_deref().unwrap_or("");
                let port = svc.port.map(|p| p.to_string()).unwrap_or_default();
                let banner = svc
                    .description
                    .as_deref()
                    .unwrap_or("")
                    .replace('\n', " ")
                    .trim()
                    .to_string();
                renderer.text(&format!("{name},{port},{banner}"))?;
            }
        }

        Ok(())
    }
}
