//! Template loading and rendering infrastructure.
//!
//! Implement the [`Template`] trait to create new report generators. Templates
//! can be registered at runtime by placing compiled dynamic libraries in one of
//! the configured template paths. The [`TemplateManager`] handles discovery and
//! selection of templates.

use std::{collections::HashMap, error::Error, fs, path::PathBuf};

use libloading::{Library, Symbol};

use crate::{graphs, parser::NessusReport, renderer::Renderer};

pub mod create;
pub mod helpers;

/// Trait implemented by report templates.
pub trait Template {
    /// Name used to reference the template.
    fn name(&self) -> &str;
    /// Generate output for the given report using the provided renderer.
    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
    ) -> Result<(), Box<dyn Error>>;
}

/// Manages discovery and loading of compiled template modules.
pub struct TemplateManager {
    templates: HashMap<String, Box<dyn Template>>,
    _libs: Vec<Library>,
    paths: Vec<PathBuf>,
}

impl TemplateManager {
    /// Create a new manager that searches the provided paths.
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self {
            templates: HashMap::new(),
            _libs: Vec::new(),
            paths,
        }
    }

    /// Load templates from all configured paths. Each dynamic library is
    /// expected to expose a `create_template` function returning
    /// `Box<dyn Template>`.
    pub fn load_templates(&mut self) -> Result<(), Box<dyn Error>> {
        for path in &self.paths {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().and_then(|s| s.to_str()) == Some("so") {
                        unsafe {
                            let lib = Library::new(&p)?;
                            let ctor: Symbol<unsafe fn() -> Box<dyn Template>> =
                                lib.get(b"create_template")?;
                            let tmpl = ctor();
                            let name = tmpl.name().to_string();
                            self.templates.insert(name, tmpl);
                            self._libs.push(lib);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Register a template instance manually.
    pub fn register(&mut self, tmpl: Box<dyn Template>) {
        let name = tmpl.name().to_string();
        self.templates.insert(name, tmpl);
    }

    /// Retrieve a template by name.
    pub fn get(&self, name: &str) -> Option<&Box<dyn Template>> {
        self.templates.get(name)
    }

    /// List available template names.
    pub fn available(&self) -> Vec<String> {
        self.templates.keys().cloned().collect()
    }

    /// Display all available template names.
    pub fn display(&self) {
        for name in self.available() {
            println!("{}", name);
        }
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
    ) -> Result<(), Box<dyn Error>> {
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
