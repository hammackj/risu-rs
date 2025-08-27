use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Rough port of the Microsoft Patch Summary template.
pub struct MSPatchSummaryTemplate;

impl Template for MSPatchSummaryTemplate {
    fn name(&self) -> &str {
        "ms_patch_summary"
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
            .unwrap_or("Missing Microsoft Patch Summary");
        renderer.text(title)?;
        for patch in &report.patches {
            if let Some(host_id) = patch.host_id {
                if let Some(host) = report.hosts.iter().find(|h| h.id == host_id) {
                    if let Some(name) = &host.name {
                        renderer.text(&format!("Host: {name}"))?;
                    }
                    if let Some(os) = &host.os {
                        renderer.text(&format!("OS: {os}"))?;
                    }
                    if let Some(mac) = &host.mac {
                        renderer.text(&format!("Mac: {mac}"))?;
                    }
                }
            }
            if let Some(pname) = &patch.name {
                renderer.text(&format!("Patch: {pname}"))?;
            }
            if let Some(val) = &patch.value {
                renderer.text(val)?;
            }
            renderer.text("")?;
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
    name: "ms_patch_summary",
    author: "ported",
    renderer: "text",
};
