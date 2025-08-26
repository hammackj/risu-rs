use std::collections::HashMap;
use std::error::Error;

use base64::{engine::general_purpose, Engine};

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;
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
        args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        let title = args.get("title").map(String::as_str).unwrap_or("Template");
        renderer.heading(1, title)?;
        // Demonstrate embedding an image from the bundled assets directory.
        // The image bytes are included in the binary and encoded as a data URI
        // for renderers that accept inline images.
        let encoded = general_purpose::STANDARD.encode(assets::nessus_logo_jpg());
        let logo_data_uri = format!("data:image/jpeg;base64,{encoded}");
        renderer.text(&logo_data_uri)?;
        Ok(())
    }
}
