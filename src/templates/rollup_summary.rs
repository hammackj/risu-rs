use std::collections::{BTreeMap, HashMap};
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Simplified port of the Rollup Summary report from the Ruby implementation.
pub struct RollupSummaryTemplate;

impl Template for RollupSummaryTemplate {
    fn name(&self) -> &str {
        "rollup_summary"
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
            .unwrap_or("Findings Summary Report");
        renderer.text(title)?;

        let mut print_group = |sev: i32, label: &str| -> Result<(), Box<dyn Error>> {
            let mut unique: BTreeMap<i32, String> = BTreeMap::new();
            for item in &report.items {
                if item.rollup_finding == Some(true) {
                    continue;
                }
                if item.severity == Some(sev) {
                    if let Some(pid) = item.plugin_id {
                        let name = item.plugin_name.clone().unwrap_or_default();
                        unique.entry(pid).or_insert(name);
                    }
                }
            }
            if !unique.is_empty() {
                renderer.text(label)?;
                for (pid, name) in unique {
                    if name.is_empty() {
                        renderer.text(&format!("{pid}"))?;
                    } else {
                        renderer.text(&format!("{pid}: {name}"))?;
                    }
                }
                renderer.text("")?;
            }
            Ok(())
        };

        print_group(4, "Critical Findings")?;
        print_group(3, "High Findings")?;
        print_group(2, "Medium Findings")?;
        print_group(1, "Low Findings")?;
        print_group(0, "Informational Findings")?;
        Ok(())
    }
}
