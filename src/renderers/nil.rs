use std::{error::Error, io::Write};

use super::Renderer;

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
