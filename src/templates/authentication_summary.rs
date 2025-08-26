use std::collections::HashMap;
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{template_helper, Template};

/// Report summarizing counts of authenticated vs unauthenticated hosts.
pub struct AuthenticationSummaryTemplate;

impl Template for AuthenticationSummaryTemplate {
    fn name(&self) -> &str {
        "authentication_summary"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        let title = args
            .get("title")
            .map(String::as_str)
            .unwrap_or("Authentication Summary");
        renderer.heading(1, title)?;

        // Count hosts that were authenticated versus those that were not.
        let (auth, unauth) = template_helper::authenticated_count(report);
        let lines = [
            template_helper::field("Authenticated hosts", &auth.to_string()),
            template_helper::field("Unauthenticated hosts", &unauth.to_string()),
        ]
        .join("\n");
        renderer.text(&lines)?;
        Ok(())
    }
}
