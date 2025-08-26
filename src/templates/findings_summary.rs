use std::collections::{BTreeMap, HashMap};
use std::error::Error;

use crate::models::Item;
use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Port of the Ruby `findings_summary.rb` template.
pub struct FindingsSummaryTemplate;

impl Template for FindingsSummaryTemplate {
    fn name(&self) -> &str {
        "findings_summary"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        _args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        renderer.text("Findings Summary Report")?;

        let mut by_sev: BTreeMap<i32, Vec<&Item>> = BTreeMap::new();
        for item in &report.items {
            if let Some(sev) = item.severity {
                by_sev.entry(sev).or_default().push(item);
            }
        }

        for (sev, items) in by_sev.iter().rev() {
            let heading = match sev {
                4 => "Critical Findings",
                3 => "High Findings",
                2 => "Medium Findings",
                1 => "Low Findings",
                _ => "Informational Findings",
            };
            if items.is_empty() {
                continue;
            }
            renderer.text(heading)?;
            let mut counts: BTreeMap<i32, (String, i32)> = BTreeMap::new();
            for item in items.iter() {
                let item = *item;
                let pid = item.plugin_id.unwrap_or(0);
                let name = item
                    .plugin_name
                    .clone()
                    .unwrap_or_else(|| format!("Plugin {pid}"));
                counts
                    .entry(pid)
                    .and_modify(|e| e.1 += 1)
                    .or_insert((name, 1));
            }
            for (_pid, (name, count)) in counts {
                renderer.text(&format!("{count} - {name}"))?;
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
    name: "findings_summary",
    author: "hammackj",
    renderer: "text",
};
