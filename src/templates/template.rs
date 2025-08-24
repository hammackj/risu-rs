use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{self, Template};
use crate::templates::assets;

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
        renderer.heading(1, "Template")?;
        // Demonstrate embedding an image from the bundled assets directory.
        // The image bytes are included in the binary and encoded as a data URI
        // for renderers that accept inline images.
        let logo_data_uri = template::helpers::embed_graph(assets::logo_png())?;
        renderer.text(&logo_data_uri)?;
        Ok(())
    }
}
