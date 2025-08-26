use regex::Regex;
use std::collections::HashMap;
use std::error::Error;

use crate::models::Item;
use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Port of the Ruby `ms_wsus_findings.rb` template.
pub struct MSWSUSFindingsTemplate;

impl Template for MSWSUSFindingsTemplate {
    fn name(&self) -> &str {
        "ms_wsus_findings"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        _args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        renderer.text("Patch Management: WSUS Report")?;
        let items: Vec<&Item> = report
            .items
            .iter()
            .filter(|i| i.plugin_id == Some(58133))
            .collect();
        let header_re = Regex::new(
            r"\+ WSUS Computer Information\s+FQDN : (.*)\s+IP Address : (.*)\s+Last Sync Time : (.*)\s+Last Reported Status : (.*)\s+Last Sync Result : (.*)"
        ).unwrap();
        let patch_re = Regex::new(
            r"^\d* :(.*)\n    Patch State : (.*)\n    Microsoft KB : (.*)\n    severity : (.*)\n    Bulletin Date : (.*)\n    Patch Link : (.*)\n    Description : (.*)"
        ).unwrap();
        for item in items {
            if let Some(output) = &item.plugin_output {
                if let Some(caps) = header_re.captures(output) {
                    renderer.text(&format!("Host: {} ({})", &caps[2], &caps[1]))?;
                    renderer.text(&format!("Last Sync Time: {}", &caps[3]))?;
                    renderer.text(&format!("Last Reported Status: {}", &caps[4]))?;
                    renderer.text(&format!("Last Sync Result: {}", &caps[5]))?;
                }
                for caps in patch_re.captures_iter(output) {
                    renderer.text(&format!("Name: {}", &caps[1]))?;
                    renderer.text(&format!("State: {}", &caps[2]))?;
                    renderer.text(&format!("Severity: {}", &caps[4]))?;
                    renderer.text(&format!("Release date: {}", &caps[5]))?;
                    renderer.text(&format!("Link: {}", &caps[6]))?;
                    renderer.text(&format!("Description: {}", &caps[7]))?;
                    renderer.text("")?;
                }
            }
        }
        Ok(())
    }
}

/// Metadata about this template.
pub struct Metadata {
    pub name: &'static str,
    pub author: &'static str,
    pub renderer: &'static str,
}

pub static METADATA: Metadata = Metadata {
    name: "ms_wsus_findings",
    author: "hammackj",
    renderer: "text",
};
