use std::{error::Error, io::Write};

use printpdf::{
    BuiltinFont, IndirectFontRef, Mm, PdfDocument, PdfDocumentReference, PdfLayerReference,
    PdfPageIndex,
};

/// Trait implemented by renderers that output to various formats.
pub trait Renderer {
    /// Write free-form text to the current output position.
    fn text(&mut self, text: &str) -> Result<(), Box<dyn Error>>;
    /// Register a heading which should appear in a table of contents or
    /// bookmark structure. The default implementation simply writes the text
    /// like a normal paragraph.
    fn heading(&mut self, _level: usize, text: &str) -> Result<(), Box<dyn Error>> {
        self.text(text)
    }
    /// Begin a new page in the output, if supported.
    fn start_new_page(&mut self) -> Result<(), Box<dyn Error>>;
    /// Finalize the document and write it to the provided writer.
    fn save(&mut self, writer: &mut dyn Write) -> Result<(), Box<dyn Error>>;
}

/// Renderer that produces PDF documents using the `printpdf` crate.
pub struct PdfRenderer {
    doc: Option<PdfDocumentReference>,
    layer: PdfLayerReference,
    font: IndirectFontRef,
    cursor_y: Mm,
    toc_layer: PdfLayerReference,
    toc_cursor_y: Mm,
    headings: Vec<Heading>,
    current_page: PdfPageIndex,
    current_page_number: usize,
}

struct Heading {
    level: usize,
    title: String,
    page: PdfPageIndex,
    number: usize,
}

impl PdfRenderer {
    /// Create a new PDF renderer with the given document title.
    pub fn new(title: &str) -> Self {
        // Reserve the first page for a table of contents. Actual rendering
        // starts on the second page.
        let (doc, toc_page, toc_layer) = PdfDocument::new(title, Mm(210.0), Mm(297.0), "Layer 1");
        let (first_page, first_layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
        let font = doc
            .add_builtin_font(BuiltinFont::Helvetica)
            .expect("builtin font");
        let toc_layer = doc.get_page(toc_page).get_layer(toc_layer);
        let layer = doc.get_page(first_page).get_layer(first_layer);
        Self {
            doc: Some(doc),
            layer,
            font,
            cursor_y: Mm(287.0),
            toc_layer,
            toc_cursor_y: Mm(287.0),
            headings: Vec::new(),
            current_page: first_page,
            current_page_number: 2, // first page is reserved for ToC
        }
    }
}

impl Renderer for PdfRenderer {
    fn heading(&mut self, level: usize, text: &str) -> Result<(), Box<dyn Error>> {
        let doc = self.doc.as_ref().expect("document");
        doc.add_bookmark(text, self.current_page);
        self.headings.push(Heading {
            level,
            title: text.to_string(),
            page: self.current_page,
            number: self.current_page_number,
        });
        // Render the heading slightly larger than normal text.
        let x = Mm(10.0 + (level as f64 * 5.0));
        self.layer
            .use_text(text.to_string(), 16.0, x, self.cursor_y, &self.font);
        self.cursor_y -= Mm(20.0);
        Ok(())
    }

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
        self.cursor_y = Mm(287.0);
        self.current_page = page;
        self.current_page_number += 1;
        Ok(())
    }

    fn save(&mut self, writer: &mut dyn Write) -> Result<(), Box<dyn Error>> {
        if let Some(doc) = self.doc.take() {
            // Build the table of contents page.
            self.toc_layer.use_text(
                "Table of Contents",
                18.0,
                Mm(10.0),
                self.toc_cursor_y,
                &self.font,
            );
            self.toc_cursor_y -= Mm(24.0);
            for h in &self.headings {
                let indent = h.level as f64 * 5.0;
                let entry = format!("{} ........ {}", h.title, h.number);
                self.toc_layer.use_text(
                    entry,
                    12.0,
                    Mm(10.0 + indent),
                    self.toc_cursor_y,
                    &self.font,
                );
                self.toc_cursor_y -= Mm(14.0);
            }

            let mut buf = std::io::BufWriter::new(writer);
            doc.save(&mut buf)?;
        }
        Ok(())
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
