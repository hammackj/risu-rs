use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Basic example template ported from the original Ruby implementation.
pub struct TemplateTemplate;

impl Template for TemplateTemplate {
    fn name(&self) -> &str {
        "template"
    }

    fn generate(
        &self,
        _report: &NessusReport,
        renderer: &mut dyn Renderer,
    ) -> Result<(), Box<dyn Error>> {
        renderer.text("Template")?;
        Ok(())
    }
}
