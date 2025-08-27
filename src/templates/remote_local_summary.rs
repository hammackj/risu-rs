use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{template_helper, Template};

/// Report summarizing remote versus local findings.
pub struct RemoteLocalSummaryTemplate;

impl Template for RemoteLocalSummaryTemplate {
    fn name(&self) -> &str {
        "remote_local_summary"
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
            .unwrap_or("Remote vs Local Findings");
        renderer.heading(1, title)?;

        let (remote, local) = template_helper::remote_local_counts(report);
        let total = remote + local;
        let remote_pct = if total > 0 {
            (remote as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        let local_pct = if total > 0 {
            (local as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let lines = [
            template_helper::field("Remote findings", &format!("{remote} ({:.1}%)", remote_pct)),
            template_helper::field("Local findings", &format!("{local} ({:.1}%)", local_pct)),
        ]
        .join("\n");
        renderer.text(&lines)?;
        Ok(())
    }
}
