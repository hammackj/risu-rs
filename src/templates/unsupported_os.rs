use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;
use crate::template::host_template_helper::{unsupported_os_linux, unsupported_os_windows};

/// Template that lists hosts running unsupported operating systems.
pub struct UnsupportedOsTemplate;

impl Template for UnsupportedOsTemplate {
    fn name(&self) -> &str {
        "unsupported_os"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        _args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        renderer.heading(1, "Unsupported Operating Systems")?;

        let windows = unsupported_os_windows(report);
        let linux = unsupported_os_linux(report);

        if windows.is_empty() && linux.is_empty() {
            renderer.text("No unsupported operating systems detected.")?;
            return Ok(());
        }

        if !windows.is_empty() {
            renderer.text(&windows)?;
        }
        if !linux.is_empty() {
            renderer.text(&linux)?;
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
    name: "unsupported_os",
    author: "ported",
    renderer: "text",
};
