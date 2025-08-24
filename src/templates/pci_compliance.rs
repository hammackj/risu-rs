use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Simplified PCI compliance overview template.
pub struct PCIComplianceTemplate;

impl Template for PCIComplianceTemplate {
    fn name(&self) -> &str {
        "pci_compliance"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
    ) -> Result<(), Box<dyn Error>> {
        renderer.heading(1, "PCI / DSS Compliance Overview")?;
        renderer.text(&format!("Total Hosts: {}", report.hosts.len()))?;

        // Naively look for plugin 33929 and classify output containing
        // "passed" or "failed".
        let mut passed = 0;
        let mut failed = 0;
        for item in &report.items {
            if item.plugin_id == Some(33929) {
                if item
                    .plugin_output
                    .as_deref()
                    .map(|o| o.to_lowercase().contains("passed"))
                    .unwrap_or(false)
                {
                    passed += 1;
                } else if item
                    .plugin_output
                    .as_deref()
                    .map(|o| o.to_lowercase().contains("failed"))
                    .unwrap_or(false)
                {
                    failed += 1;
                }
            }
        }

        renderer.text(&format!("Hosts passed: {passed}"))?;
        renderer.text(&format!("Hosts failed: {failed}"))?;
        Ok(())
    }
}
