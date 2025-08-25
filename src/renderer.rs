use std::{error::Error, io::Write};

use printpdf::{
    BuiltinFont, IndirectFontRef, Mm, PdfDocument, PdfDocumentReference, PdfLayerReference,
    PdfPageIndex,
};

/// Trait implemented by renderers that output to various formats.
pub trait Renderer {
    /// Write free-form text to the current output position.
    fn text(&mut self, text: &str) -> Result<(), Box<dyn Error>>;
    /// Begin a new page in the output, if supported.
    fn start_new_page(&mut self) -> Result<(), Box<dyn Error>>;
    /// Finalize the document and write it to the provided writer.
    fn save(&mut self, writer: &mut dyn Write) -> Result<(), Box<dyn Error>>;
    /// Record a heading for navigation structures.
    fn heading(&mut self, _level: usize, text: &str) -> Result<(), Box<dyn Error>> {
        self.text(text)
    }
}

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

/// Renderer that outputs simple CSV files using the `csv` crate.
pub struct CsvRenderer {
    rows: Vec<String>,
}

impl CsvRenderer {
    /// Create a new CSV renderer.
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }
}

impl Renderer for CsvRenderer {
    fn text(&mut self, text: &str) -> Result<(), Box<dyn Error>> {
        self.rows.push(text.to_string());
        Ok(())
    }

    fn start_new_page(&mut self) -> Result<(), Box<dyn Error>> {
        // CSV output has no pages; this is a no-op.
        Ok(())
    }

    fn save(&mut self, writer: &mut dyn Write) -> Result<(), Box<dyn Error>> {
        let mut wtr = csv::Writer::from_writer(writer);
        for row in &self.rows {
            wtr.write_record(&[row])?;
        }
        wtr.flush()?;
        Ok(())
    }
}

/// Renderer that discards all output. Useful for benchmarking or tests where
/// rendering is unnecessary.
pub struct NilRenderer;

impl NilRenderer {
    /// Create a new `NilRenderer`.
    pub fn new() -> Self {
        Self
    }
}

impl Renderer for NilRenderer {
    fn text(&mut self, _text: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    fn start_new_page(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    fn save(&mut self, _writer: &mut dyn Write) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
