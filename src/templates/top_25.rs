use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{template_helper, Template};

/// Report listing the most common findings across hosts.
pub struct Top25Template;

impl Template for Top25Template {
    fn name(&self) -> &str {
        "top_25"
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
            .unwrap_or("Top 25 Vulnerabilities");
        renderer.heading(1, title)?;

        // Count occurrences of each plugin across all items.
        let mut counts: std::collections::HashMap<i32, u32> = std::collections::HashMap::new();
        for item in &report.items {
            if let Some(id) = item.plugin_id {
                *counts.entry(id).or_insert(0) += 1;
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
        entries.truncate(25);

        let lines: Vec<String> = entries
            .iter()
            .map(|(id, name, count)| format!("{name} ({id}): {count}"))
            .collect();
        renderer.text(&template_helper::heading(2, "Top Plugins"))?;
        renderer.text(&template_helper::bullet_list(&lines))?;
        Ok(())
    }
}
