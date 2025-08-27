use std::collections::{BTreeMap, HashMap};
use std::error::Error;

use crate::models::Item;
use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// List hosts with unquoted service paths (plugin ID 58670).
pub struct MicrosoftWindowsUnquotedServicePathEnumerationTemplate;

impl Template for MicrosoftWindowsUnquotedServicePathEnumerationTemplate {
    fn name(&self) -> &str {
        "microsoft_windows_unquoted_service_path_enumeration"
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
            .unwrap_or("Microsoft Windows Unquoted Service Path Enumeration");
        renderer.heading(1, title)?;

        const PLUGIN_ID: i32 = 58670;

        let mut by_host: BTreeMap<String, Vec<&Item>> = BTreeMap::new();
        for item in report
            .items
            .iter()
            .filter(|i| i.plugin_id == Some(PLUGIN_ID))
        {
            let label = item
                .host_id
                .and_then(|hid| report.hosts.iter().find(|h| h.id == hid))
                .or_else(|| {
                    if report.hosts.len() == 1 {
                        report.hosts.get(0)
                    } else {
                        None
                    }
                })
                .and_then(|h| h.name.clone().or(h.fqdn.clone()).or(h.ip.clone()))
                .unwrap_or_else(|| "unknown".into());
            by_host.entry(label).or_default().push(item);
        }

        if by_host.is_empty() {
            renderer.text("No hosts with unquoted service paths were detected.")?;
            return Ok(());
        }

        for (host, items) in by_host {
            renderer.heading(2, &host)?;
            for item in items {
                if let Some(output) = &item.plugin_output {
                    for line in output.lines() {
                        let line = line.trim();
                        if !line.is_empty() {
                            renderer.text(line)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
