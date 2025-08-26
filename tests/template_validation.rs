use risu_rs::parser::NessusReport;
use risu_rs::renderer::Renderer;
use risu_rs::template::{Template, TemplateManager};
use std::collections::HashMap;

struct NoName;

impl Template for NoName {
    fn name(&self) -> &str {
        ""
    }

    fn generate(
        &self,
        _report: &NessusReport,
        _renderer: &mut dyn Renderer,
        _args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

struct DupTemplate;

impl Template for DupTemplate {
    fn name(&self) -> &str {
        "dup"
    }

    fn generate(
        &self,
        _report: &NessusReport,
        _renderer: &mut dyn Renderer,
        _args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

#[test]
fn rejects_template_without_name() {
    let mut mgr = TemplateManager::new(vec![]);
    mgr.register(Box::new(NoName));
    assert!(mgr.available().is_empty());
}

#[test]
fn rejects_duplicate_template() {
    let mut mgr = TemplateManager::new(vec![]);
    mgr.register(Box::new(DupTemplate));
    mgr.register(Box::new(DupTemplate));
    assert_eq!(mgr.available().len(), 1);
}
