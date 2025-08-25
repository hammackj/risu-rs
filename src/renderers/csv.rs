use std::{error::Error, io::Write};

use super::Renderer;

/// Renderer that outputs simple CSV files using the `csv` crate.
pub struct CsvRenderer {
    rows: Vec<String>,
}

impl CsvRenderer {
    /// Create a new CSV renderer.
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Headers used by the Ruby implementation. The order is significant.
    pub fn headers() -> &'static [&'static str] {
        &[
            "IP Address",
            "FQDN",
            "Netbios Name",
            "MAC Address",
            "Finding",
            "Risk Factor",
            "CVSS Base Score",
            "Solution",
        ]
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

#[cfg(test)]
mod tests {
    use super::CsvRenderer;

    #[test]
    fn headers_match_ruby() {
        let ruby_headers: &[&str] = &["IP Address", "FQDN", "Netbios Name", "MAC Address", "Finding", "Risk Factor", "CVSS Base Score", "Solution"];
        assert_eq!(CsvRenderer::headers(), ruby_headers);
    }
}
