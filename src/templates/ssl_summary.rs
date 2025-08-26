use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{Template, ssl_template_helper};

/// Summarizes SSL related findings such as weak ciphers and certificate issues.
pub struct SslSummaryTemplate;

impl Template for SslSummaryTemplate {
    fn name(&self) -> &str {
        "ssl_summary"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        _args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        renderer.text("SSL Summary")?;
        let (per_host, global) = ssl_template_helper::ssl_stats(report);
        renderer.text(&format!("Total SSL findings: {}", global.total))?;
        renderer.text(&format!("Weak ciphers: {}", global.weak_ciphers))?;
        renderer.text(&format!("Certificate issues: {}", global.cert_issues))?;
        for (host, stats) in per_host {
            renderer.text(&format!("{host}: {}", stats.total))?;
        }
        Ok(())
    }
}
