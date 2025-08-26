//! Template loading and rendering infrastructure.
//!
//! Implement the [`Template`] trait to create new report generators. Templates
//! can be registered at runtime by placing compiled dynamic libraries in one of
//! the configured template paths. The [`TemplateManager`] handles discovery and
//! selection of templates.

use std::collections::HashMap;
use std::error::Error;

use crate::{graphs, parser::NessusReport, renderer::Renderer};

pub mod create;
pub mod graph_template_helper;
pub mod helpers;
pub mod host_template_helper;
pub mod malware_template_helper;
pub mod scan_helper;
pub mod shares_template_helper;
pub mod ssl_template_helper;
pub mod template_helper;
pub mod templater;
pub mod manager;

pub use manager::TemplateManager;

/// Trait implemented by report templates.
pub trait Template {
    /// Name used to reference the template.
    fn name(&self) -> &str;
    /// Generate output for the given report using the provided renderer.
    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>>;

    /// Determine if a plugin indicates default credentials.
    fn has_default_credentials(&self, plugin_id: i32) -> bool {
        crate::template::helpers::has_default_credentials(plugin_id)
    }

    /// Produce a warning section for default credential detections.
    fn default_credentials_section(&self, plugin_ids: &[i32]) -> String {
        crate::template::helpers::default_credentials_section(plugin_ids)
    }

    /// Produce an appendix section for default credential detections.
    fn default_credentials_appendix_section(&self, plugin_ids: &[i32]) -> String {
        crate::template::helpers::default_credentials_appendix_section(plugin_ids)
    }
}

/// Very small built-in template demonstrating renderer usage.
pub struct SimpleTemplate;

impl Template for SimpleTemplate {
    fn name(&self) -> &str {
        "simple"
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
            .unwrap_or("Simple Report");
        renderer.heading(1, title)?;
        renderer.text(&format!("Hosts: {}", report.hosts.len()))?;

        // Generate example graphs in the system temporary directory.
        let tmp = std::env::temp_dir();
        if let Ok(p) = graphs::os_distribution(report, &tmp) {
            renderer.text(&format!("OS distribution chart: {}", p.display()))?;
        }
        if let Ok(p) = graphs::top_vulnerabilities(report, &tmp, 5) {
            renderer.text(&format!("Top vulnerabilities chart: {}", p.display()))?;
        }
        Ok(())
    }
}
