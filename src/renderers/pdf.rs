use std::{error::Error, io::Write};

use printpdf::{
    BuiltinFont, IndirectFontRef, Mm, PdfDocument, PdfDocumentReference, PdfLayerReference,
    PdfPageIndex,
};
use base64::engine::general_purpose;
use base64::Engine;

use super::Renderer;
use printpdf::image_crate::GenericImageView;

/// Renderer that produces PDF documents using the `printpdf` crate.
pub struct PdfRenderer {
    doc: Option<PdfDocumentReference>,
    toc_layer: PdfLayerReference,
    layer: PdfLayerReference,
    font: IndirectFontRef,
    cursor_y: Mm,
    headings: Vec<(usize, String, usize)>,
    page: PdfPageIndex,
    page_num: usize,
}

impl PdfRenderer {
    /// Create a new PDF renderer with the given document title.
    pub fn new(title: &str) -> Self {
        let (doc, toc_page, toc_layer) = PdfDocument::new(title, Mm(210.0), Mm(297.0), "Layer 1");
        let font = doc
            .add_builtin_font(BuiltinFont::Helvetica)
            .expect("builtin font");
        let (page, layer_idx) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
        let toc_layer = doc.get_page(toc_page).get_layer(toc_layer);
        let layer = doc.get_page(page).get_layer(layer_idx);
        Self {
            doc: Some(doc),
            toc_layer,
            layer,
            font,
            cursor_y: Mm(287.0),
            headings: Vec::new(),
            page,
            page_num: 2,
        }
    }
}

impl Renderer for PdfRenderer {
    fn text(&mut self, text: &str) -> Result<(), Box<dyn Error>> {
        // Detect data URI images and embed them instead of printing the string.
        if let Some(pos) = text.find(",") {
            let (prefix, data) = text.split_at(pos + 1);
            if prefix.starts_with("data:image/") && prefix.contains(";base64,") {
                let bytes = general_purpose::STANDARD.decode(data.as_bytes())?;
                let image = printpdf::image_crate::load_from_memory(&bytes)?;
                let (px_w, px_h) = image.dimensions();
                let img = printpdf::Image::from_dynamic_image(&image);
                // Convert pixels to mm assuming 96 DPI
                let mm_w = (px_w as f64) * 25.4 / 96.0;
                let mm_h = (px_h as f64) * 25.4 / 96.0;
                let max_w = 190.0; // page width (210) - margins (10 each)
                let scale = if mm_w > max_w { max_w / mm_w } else { 1.0 };
                let draw_w = Mm(mm_w * scale);
                let draw_h = Mm(mm_h * scale);
                // Move down for image height and add some spacing after
                let y = self.cursor_y - draw_h;
                img.add_to_layer(
                    self.layer.clone(),
                    printpdf::ImageTransform {
                        translate_x: Some(Mm(10.0)),
                        translate_y: Some(y),
                        // Use dpi and uniform scale so size in mm follows our calculation
                        dpi: Some(96.0),
                        scale_x: Some(scale),
                        scale_y: Some(scale),
                        ..Default::default()
                    },
                );
                self.cursor_y = y - Mm(10.0);
                return Ok(());
            }
        }
        // Fallback: plain text
        self.layer
            .use_text(text.to_string(), 14.0, Mm(10.0), self.cursor_y, &self.font);
        self.cursor_y -= Mm(16.0);
        Ok(())
    }

    fn start_new_page(&mut self) -> Result<(), Box<dyn Error>> {
        let doc = self.doc.as_ref().expect("document");
        let (page, layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
        self.layer = doc.get_page(page).get_layer(layer);
        self.page = page;
        self.page_num += 1;
        self.cursor_y = Mm(287.0);
        Ok(())
    }

    fn save(&mut self, writer: &mut dyn Write) -> Result<(), Box<dyn Error>> {
        if let Some(doc) = self.doc.take() {
            let mut toc_y = Mm(287.0);
            self.toc_layer
                .use_text("Table of Contents", 16.0, Mm(10.0), toc_y, &self.font);
            toc_y -= Mm(20.0);
            for (level, title, page) in &self.headings {
                let indent = 10.0 + 10.0 * (*level as f64 - 1.0);
                let entry = format!("{title} ... {page}");
                self.toc_layer
                    .use_text(entry, 14.0, Mm(indent), toc_y, &self.font);
                toc_y -= Mm(16.0);
            }
            let mut buf = std::io::BufWriter::new(writer);
            doc.save(&mut buf)?;
        }
        Ok(())
    }

    fn heading(&mut self, level: usize, text: &str) -> Result<(), Box<dyn Error>> {
        if let Some(doc) = self.doc.as_ref() {
            doc.add_bookmark(text, self.page);
            self.headings.push((level, text.to_string(), self.page_num));
        }
        self.text(text)
    }
}
