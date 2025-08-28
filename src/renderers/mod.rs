use std::{error::Error, io::Write};

mod pdf;
mod csv;
mod nil;
mod rtf;

pub use csv::CsvRenderer;
pub use nil::NilRenderer;
pub use pdf::PdfRenderer;
pub use rtf::RtfRenderer;

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
    /// Embed an image provided as a data URI. Default fallback prints the URI.
    fn image_data_uri(&mut self, data_uri: &str) -> Result<(), Box<dyn Error>> {
        self.text(data_uri)
    }
}
