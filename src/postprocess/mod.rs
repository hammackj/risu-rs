//! Framework for post-processing plugins applied to parsed reports.
//!
//! Plugins implement [`PostProcess`] and register themselves using the
//! [`inventory`] crate. They run sequentially on the [`NessusReport`] after
//! parsing to adjust or enrich data.

use crate::parser::NessusReport;
use tracing::info;

/// Information about a post-processing plugin.
pub struct PostProcessInfo {
    pub name: &'static str,
    pub order: u32,
}

/// Trait implemented by post-processing plugins.
pub trait PostProcess: Sync + Send {
    /// Return metadata about the plugin.
    fn info(&self) -> PostProcessInfo;
    /// Execute the plugin on the report.
    fn run(&self, report: &mut NessusReport);
}

/// Wrapper type used for inventory registration.
pub struct PluginEntry {
    pub plugin: &'static dyn PostProcess,
}

inventory::collect!(PluginEntry);

/// Registry that stores and executes post-processing plugins.
pub struct Registry {
    plugins: Vec<&'static dyn PostProcess>,
}

impl Registry {
    /// Discover all statically registered plugins and order them.
    pub fn discover() -> Self {
        let mut plugins: Vec<&'static dyn PostProcess> = inventory::iter::<PluginEntry>
            .into_iter()
            .map(|e| e.plugin)
            .collect();
        plugins.sort_by_key(|p| p.info().order);
        Self { plugins }
    }

    /// Run all plugins in order.
    pub fn run(&self, report: &mut NessusReport) {
        for plugin in &self.plugins {
            info!("Running post-process plugin: {}", plugin.info().name);
            plugin.run(report);
        }
        info!(
            "Post-processed report v{} ({} hosts, {} items, {} plugins)",
            report.version,
            report.hosts.len(),
            report.items.len(),
            report.plugins.len()
        );
    }
}

/// Convenience helper to run all discovered plugins on a report.
pub fn process(report: &mut NessusReport) {
    let registry = Registry::discover();
    registry.run(report);
}

mod fix_ips;
mod sort_hosts;
