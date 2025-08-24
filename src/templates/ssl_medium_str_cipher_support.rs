use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Lists SSL medium strength cipher findings.
pub struct SslMediumStrCipherSupportTemplate;

impl Template for SslMediumStrCipherSupportTemplate {
    fn name(&self) -> &str {
        "ssl_medium_str_cipher_support"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
    ) -> Result<(), Box<dyn Error>> {
        renderer.heading(1, "SSL Medium Strength Cipher Support")?;
        let mut count = 0;
        for item in &report.items {
            if let Some(name) = &item.plugin_name {
                if name.to_lowercase().contains("ssl medium") {
                    count += 1;
                    renderer.text(name)?;
                }
            }
        }
        renderer.text(&format!("Total findings: {count}"))?;
        Ok(())
    }
}
