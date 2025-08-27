use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{template_helper, Template};

/// Report listing the most common high or critical findings across hosts.
pub struct SansTopTemplate;

impl Template for SansTopTemplate {
    fn name(&self) -> &str {
        "sans_top"
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
            .unwrap_or("Top Vulnerabilities");
        renderer.heading(1, title)?;

        let limit = args
            .get("top")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(25);

        // Count occurrences of each high or critical plugin across all items.
        let mut counts: HashMap<i32, u32> = HashMap::new();
        for item in &report.items {
            if let (Some(sev), Some(id)) = (item.severity, item.plugin_id) {
                if sev >= 3 {
                    *counts.entry(id).or_insert(0) += 1;
                }
            }
        }

        // Map plugin IDs to names and sort by count descending.
        let mut entries: Vec<(i32, String, u32)> = counts
            .into_iter()
            .map(|(id, count)| {
                let name = report
                    .plugins
                    .iter()
                    .find(|p| p.plugin_id == Some(id))
                    .and_then(|p| p.plugin_name.clone())
                    .unwrap_or_else(|| format!("Plugin {id}"));
                (id, name, count)
            })
            .collect();
        entries.sort_by(|a, b| b.2.cmp(&a.2));
        entries.truncate(limit);

        let lines: Vec<String> = entries
            .iter()
            .map(|(id, name, count)| format!("{name} ({id}): {count}"))
            .collect();
        renderer.text(&template_helper::heading(2, "Top Plugins"))?;
        renderer.text(&template_helper::bullet_list(&lines))?;
        Ok(())
    }
}
