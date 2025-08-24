use std::{collections::HashMap, error::Error, fs, io::Write, path::PathBuf};

use libloading::{Library, Symbol};
use printpdf::*;

use crate::parser::NessusReport;

/// Trait implemented by report templates.
pub trait Template {
    /// Name used to reference the template.
    fn name(&self) -> &str;
    /// Generate output for the given report into the writer.
    fn generate(&self, report: &NessusReport, writer: &mut dyn Write) -> Result<(), Box<dyn Error>>;
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
        Self { templates: HashMap::new(), _libs: Vec::new(), paths }
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
}

/// Very small built-in template demonstrating `printpdf` usage.
pub struct SimpleTemplate;

impl Template for SimpleTemplate {
    fn name(&self) -> &str {
        "simple"
    }

    fn generate(&self, report: &NessusReport, writer: &mut dyn Write) -> Result<(), Box<dyn Error>> {
        let (doc, page1, layer1) = PdfDocument::new("Report", Mm(210.0), Mm(297.0), "Layer 1");
        let layer = doc.get_page(page1).get_layer(layer1);
        let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
        let text = format!("Hosts: {}", report.hosts.len());
        layer.use_text(text, 14, Mm(10.0), Mm(287.0), &font);
        doc.save(writer)?;
        Ok(())
    }
}
