use std::{error::Error, io::Write};

use super::Renderer;

/// Renderer that emits Typst markup for later compilation.
pub struct TypstRenderer {
    content: String,
}

impl TypstRenderer {
    pub fn new() -> Self {
        Self {
            content: String::new(),
        }
    }
}

impl Renderer for TypstRenderer {
    fn text(&mut self, text: &str) -> Result<(), Box<dyn Error>> {
        self.content.push_str(text);
        self.content.push_str("\n\n");
        Ok(())
    }

    fn start_new_page(&mut self) -> Result<(), Box<dyn Error>> {
        self.content.push_str("#pagebreak()\n\n");
        Ok(())
    }

    fn save(&mut self, writer: &mut dyn Write) -> Result<(), Box<dyn Error>> {
        writer.write_all(self.content.as_bytes())?;
        Ok(())
    }

    fn heading(&mut self, level: usize, text: &str) -> Result<(), Box<dyn Error>> {
        let marks = "=".repeat(level.max(1));
        self.content.push_str(&format!("{marks} {text}\n\n"));
        Ok(())
    }

    fn image_data_uri(&mut self, data_uri: &str) -> Result<(), Box<dyn Error>> {
        if let Some(pos) = data_uri.find(',') {
            let (prefix, data) = data_uri.split_at(pos + 1);
            if prefix.starts_with("data:image/") && prefix.contains(";base64,") {
                let format = prefix[11..prefix.find(';').unwrap()].to_string();
                self.content.push_str(&format!(
                    "#image.decode(base64.decode(\"{data}\"), format: \"{format}\")\n\n"
                ));
                return Ok(());
            }
        }
        self.text(data_uri)
    }
}
