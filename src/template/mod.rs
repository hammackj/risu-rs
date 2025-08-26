//! Template loading and rendering infrastructure.
//!
//! Implement the [`Template`] trait to create new report generators. Templates
//! can be registered at runtime by placing compiled dynamic libraries in one of
//! the configured template paths. The [`TemplateManager`] handles discovery and
//! selection of templates.

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fs,
    path::PathBuf,
};

use libloading::{Library, Symbol};

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

/// Manages discovery and loading of compiled template modules.
pub struct TemplateManager {
    templates: HashMap<String, Box<dyn Template>>,
    _libs: Vec<Library>,
    paths: Vec<PathBuf>,
}

impl TemplateManager {
    /// Create a new manager that searches the provided paths along with
    /// default locations.
    pub fn new(paths: Vec<PathBuf>) -> Self {
        let mut search_paths = Vec::new();

        // 1. Templates bundled with the executable.
        if let Ok(mut exe_path) = std::env::current_exe() {
            exe_path.pop();
            search_paths.push(exe_path.join("templates"));
        }

        // 2. The current working directory.
        if let Ok(cwd) = std::env::current_dir() {
            search_paths.push(cwd);
        }

        // 3. User-specific template directory ($HOME/.risu/templates).
        if let Some(home) = std::env::var_os("HOME") {
            search_paths.push(PathBuf::from(home).join(".risu").join("templates"));
        }

        // Append any additional provided paths.
        search_paths.extend(paths);

        // Deduplicate paths while preserving order.
        let mut seen = HashSet::new();
        search_paths.retain(|p| seen.insert(p.clone()));

        Self {
            templates: HashMap::new(),
            _libs: Vec::new(),
            paths: search_paths,
        }
    }

    fn validate(&self, tmpl: &dyn Template) -> Result<(), String> {
        let name = tmpl.name();
        if name.trim().is_empty() {
            return Err("template name cannot be empty".into());
        }
        if self.templates.contains_key(name) {
            return Err(format!("template '{}' already registered", name));
        }
        Ok(())
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
                            match Library::new(&p) {
                                Ok(lib) => {
                                    let ctor = lib.get::<Symbol<unsafe fn() -> Box<dyn Template>>>(
                                        b"create_template",
                                    );
                                    match ctor {
                                        Ok(ctor) => {
                                            let tmpl = ctor();
                                            if let Err(e) = self.validate(tmpl.as_ref()) {
                                                eprintln!(
                                                    "invalid template module '{}': {}",
                                                    p.display(),
                                                    e
                                                );
                                            } else {
                                                let name = tmpl.name().to_string();
                                                self.templates.insert(name, tmpl);
                                                self._libs.push(lib);
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "invalid template module '{}': {}",
                                                p.display(),
                                                e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("failed to load template '{}': {}", p.display(), e);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Register a template instance manually.
    pub fn register(&mut self, tmpl: Box<dyn Template>) {
        if let Err(e) = self.validate(tmpl.as_ref()) {
            eprintln!("invalid template '{}': {}", tmpl.name(), e);
        } else {
            let name = tmpl.name().to_string();
            self.templates.insert(name, tmpl);
        }
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
