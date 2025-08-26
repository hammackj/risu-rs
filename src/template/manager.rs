use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fs,
    path::PathBuf,
};

use libloading::{Library, Symbol};

use super::Template;

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

        // 1. Built-in templates shipped with the source tree (src/templates).
        let built_in = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("templates");
        search_paths.push(built_in);

        // 2. The current working directory (non-recursive).
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
