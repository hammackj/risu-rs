use std::{error::Error, io::Write};

use super::Renderer;

/// Renderer that produces RTF documents.
pub struct RtfRenderer {
    content: String,
}

impl RtfRenderer {
    /// Create a new RTF renderer.
    pub fn new() -> Self {
        Self {
            content: String::from("{\\rtf1\\ansi\\deff0\n"),
        }
    }

    fn escape(text: &str) -> String {
        text.replace('\\', "\\\\")
            .replace('{', "\\{")
            .replace('}', "\\}")
    }

    /// Insert a simple table. Each inner slice is a row.
    pub fn table(&mut self, rows: &[Vec<&str>]) -> Result<(), Box<dyn Error>> {
        for row in rows {
            self.content.push_str("\\trowd ");
            let mut cellx = 1000;
            for _ in row {
                self.content.push_str(&format!("\\cellx{}", cellx));
                cellx += 1000;
            }
            for cell in row {
                let esc = Self::escape(cell);
                self.content.push_str(&format!("{esc}\\cell "));
            }
            self.content.push_str("\\row\n");
        }
        Ok(())
    }

    /// Embed an image from raw bytes (PNG/JPEG).
    pub fn image(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();
        self.content
            .push_str(&format!("{{\\pict\\pngblip {hex}}}\\par\n"));
        Ok(())
    }
}

impl Renderer for RtfRenderer {
    fn text(&mut self, text: &str) -> Result<(), Box<dyn Error>> {
        let esc = Self::escape(text);
        self.content.push_str(&format!("{esc}\\par\n"));
        Ok(())
    }

    fn start_new_page(&mut self) -> Result<(), Box<dyn Error>> {
        self.content.push_str("\\page\n");
        Ok(())
    }

    fn save(&mut self, writer: &mut dyn Write) -> Result<(), Box<dyn Error>> {
        self.content.push('}');
        writer.write_all(self.content.as_bytes())?;
        Ok(())
    }

    fn heading(&mut self, _level: usize, text: &str) -> Result<(), Box<dyn Error>> {
        let esc = Self::escape(text);
        self.content.push_str(&format!("{{\\b {esc}\\b0}}\\par\n"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Renderer;
    use super::RtfRenderer;

    #[test]
    fn writes_basic_rtf() {
        let mut r = RtfRenderer::new();
        r.heading(1, "Title").unwrap();
        r.text("Hello").unwrap();
        let mut out = Vec::new();
        r.save(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("{\\rtf1"));
        assert!(s.contains("Title"));
    }
}
