use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io;
use std::path::PathBuf;

use diesel::sqlite::SqliteConnection;

use crate::{
    parser::NessusReport,
    renderer::{self, Renderer},
    template::TemplateManager,
};

/// Helper type that orchestrates template rendering.
pub struct Templater<'a> {
    template_name: String,
    #[allow(unused)]
    conn: &'a mut SqliteConnection,
    output: PathBuf,
    manager: TemplateManager,
}

impl<'a> Templater<'a> {
    /// Create a new templater.
    pub fn new(
        template_name: String,
        conn: &'a mut SqliteConnection,
        output: PathBuf,
        manager: TemplateManager,
    ) -> Self {
        Self {
            template_name,
            conn,
            output,
            manager,
        }
    }

    /// Generate output for the provided report using the selected template.
    pub fn generate(
        &mut self,
        report: &NessusReport,
        renderer_choice: Option<&str>,
        args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        let tmpl = self.manager.get(&self.template_name).ok_or_else(|| {
            format!(
                "unknown template '{}'. available: {:?}",
                self.template_name,
                self.manager.available()
            )
        })?;

        let title_arg = args
            .get("title")
            .cloned()
            .unwrap_or_else(|| "Report".to_string());

        let mut rend: Box<dyn Renderer> = match renderer_choice {
            Some("csv") => Box::new(renderer::CsvRenderer::new()),
            Some("nil") => Box::new(renderer::NilRenderer::new()),
            Some("pdf") => Box::new(renderer::PdfRenderer::new(&title_arg)),
            Some("typst") => Box::new(renderer::TypstRenderer::new()),
            Some("rtf") => Box::new(renderer::RtfRenderer::new()),
            None => match self.output.extension().and_then(|s| s.to_str()) {
                Some("csv") => Box::new(renderer::CsvRenderer::new()),
                Some("rtf") => Box::new(renderer::RtfRenderer::new()),
                Some("typ") => Box::new(renderer::TypstRenderer::new()),
                _ => Box::new(renderer::PdfRenderer::new(&title_arg)),
            },
            Some(other) => {
                return Err(format!("unsupported renderer '{other}'").into());
            }
        };

        tmpl.generate(report, rend.as_mut(), args)?;

        if renderer_choice != Some("nil") {
            let mut f = File::create(&self.output)?;
            rend.save(&mut f)?;
        } else {
            rend.save(&mut io::sink())?;
        }
        Ok(())
    }
}
