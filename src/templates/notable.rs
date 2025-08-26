use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Rough port of the Ruby `notable.rb` template.
///
/// This template enumerates all high risk (severity 3 or 4) plugins and groups
/// the affected hosts beneath each finding. The output mirrors the narrative
/// style of the original Ruby implementation by providing a short description
/// followed by a simple table of impacted hosts.
pub struct NotableTemplate;

impl Template for NotableTemplate {
    fn name(&self) -> &str {
        "notable"
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
            .unwrap_or("Notable Findings");
        renderer.heading(1, title)?;
        renderer.text(
            "The following high risk findings were identified during the assessment:",
        )?;

        // Map of plugin id -> (name, risk, description, set of hosts)
        let mut plugins: BTreeMap<i32, (String, String, String, BTreeSet<String>)> =
            BTreeMap::new();

        for item in &report.items {
            let sev = match item.severity {
                Some(s) => s,
                None => continue,
            };
            if sev < 3 {
                continue;
            }

            let pid = match item.plugin_id {
                Some(p) => p,
                None => continue,
            };

            let name = item
                .plugin_name
                .clone()
                .unwrap_or_else(|| format!("Plugin {pid}"));
            let risk = item
                .risk_factor
                .clone()
                .unwrap_or_else(|| match sev {
                    4 => "Critical".into(),
                    3 => "High".into(),
                    _ => String::new(),
                });
            let description = item.description.clone().unwrap_or_default();

            let host = item
                .host_id
                .and_then(|hid| {
                    report.hosts.get(hid as usize).and_then(|h| {
                        h.fqdn
                            .as_ref()
                            .or(h.ip.as_ref())
                            .or(h.netbios.as_ref())
                            .or(h.name.as_ref())
                            .cloned()
                    })
                })
                .unwrap_or_else(|| "Unknown host".to_string());

            plugins
                .entry(pid)
                .and_modify(|e| {
                    e.3.insert(host.clone());
                })
                .or_insert_with(|| {
                    let mut set = BTreeSet::new();
                    set.insert(host);
                    (name, risk, description, set)
                });
        }

        for (pid, (name, risk, desc, hosts)) in plugins {
            renderer.heading(2, &format!("{name} (Plugin {pid})"))?;
            if !risk.is_empty() {
                renderer.text(&format!("Severity: {risk}"))?;
            }
            if !desc.is_empty() {
                renderer.text(&desc)?;
            }
            renderer.text("Affected Hosts:")?;
            renderer.text("Host")?;
            for host in hosts {
                renderer.text(&host)?;
            }
            renderer.start_new_page()?;
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
    name: "notable",
    author: "ported",
    renderer: "text",
};

