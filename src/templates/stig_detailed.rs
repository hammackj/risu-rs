use std::collections::HashMap;
use std::error::Error;

use crate::models::Item;
use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Return the STIG category for a given plugin ID.
///
/// Values are based on the STIG data set.
pub fn category_for_plugin(pid: i32) -> Option<&'static str> {
    match pid {
        1 => Some("Category I"),
        2 => Some("Category II"),
        3 => Some("Category III"),
        _ => None,
    }
}

/// Detailed STIG findings grouped by host and category.
pub struct StigDetailedTemplate;

impl Template for StigDetailedTemplate {
    fn name(&self) -> &str {
        "stig_detailed"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        _args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        renderer.text("STIG Detailed Findings")?;

        for host in &report.hosts {
            let host_name = host
                .name
                .as_ref()
                .or(host.fqdn.as_ref())
                .or(host.ip.as_ref())
                .or(host.netbios.as_ref())
                .cloned()
                .unwrap_or_else(|| "Unknown host".to_string());
            renderer.heading(1, &host_name)?;

            let mut cat_map: HashMap<&'static str, Vec<&Item>> = HashMap::new();
            for item in &report.items {
                if let Some(pid) = item.plugin_id {
                    if let Some(cat) = category_for_plugin(pid) {
                        cat_map.entry(cat).or_default().push(item);
                    }
                }
            }

            for cat in ["Category I", "Category II", "Category III"] {
                if let Some(list) = cat_map.get(cat) {
                    if list.is_empty() {
                        continue;
                    }
                    renderer.text(cat)?;
                    renderer.text("Plugin ID, Name, Solution")?;
                    for item in list {
                        let id = item.plugin_id.unwrap_or(0);
                        let name = item
                            .plugin_name
                            .clone()
                            .unwrap_or_else(|| format!("Plugin {id}"));
                        let solution = item.solution.clone().unwrap_or_default();
                        renderer.text(&format!("{id}, {name}, {solution}"))?;
                    }
                }
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
    name: "stig_detailed",
    author: "chatgpt",
    renderer: "text",
};

