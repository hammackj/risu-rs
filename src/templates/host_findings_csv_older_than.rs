use std::collections::HashMap;
use std::error::Error;

use chrono::NaiveDateTime;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::{Template, template_helper};

/// Output critical findings per host older than a cutoff date as CSV rows.
pub struct HostFindingsCsvOlderThanTemplate;

impl Template for HostFindingsCsvOlderThanTemplate {
    fn name(&self) -> &str {
        "host_findings_csv_older_than"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        let cutoff_str = match args.get("cutoff_date") {
            Some(s) => s,
            None => return Err("missing cutoff_date argument".into()),
        };
        let cutoff = NaiveDateTime::parse_from_str(cutoff_str, "%Y-%m-%d %H:%M:%S")?;

        for item in template_helper::items_older_than(report, cutoff) {
            if item.severity.unwrap_or(0) < 4 {
                continue;
            }
            let host = item.host_id.and_then(|hid| report.hosts.get(hid as usize));
            let ip = host.and_then(|h| h.ip.clone()).unwrap_or_default();
            let fqdn = host.and_then(|h| h.fqdn.clone()).unwrap_or_default();
            let netbios = host.and_then(|h| h.netbios.clone()).unwrap_or_default();
            let finding = item.plugin_name.clone().unwrap_or_default();
            let risk = item.risk_factor.clone().unwrap_or_default();
            let row = format!("{ip}, {fqdn}, {netbios}, {finding}, {risk}");
            renderer.text(&row)?;
        }
        Ok(())
    }
}
