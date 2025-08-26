use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Detailed listing of top findings with affected hosts and descriptions.
pub struct NotableDetailedTemplate;

impl Template for NotableDetailedTemplate {
    fn name(&self) -> &str {
        "notable_detailed"
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
            .unwrap_or("Notable Vulnerabilities");
        renderer.heading(1, title)?;

        // Map plugin id -> (plugin name, set of hosts, description, cvss, solution)
        let mut plugins: BTreeMap<
            i32,
            (
                String,
                BTreeSet<String>,
                String,
                Option<f32>,
                Option<String>,
            ),
        > = BTreeMap::new();

        for item in &report.items {
            let sev = item.severity.unwrap_or(0);
            if sev < 3 {
                continue;
            }
            let pid = match item.plugin_id {
                Some(p) => p,
                None => continue,
            };
            let host = item
                .host_id
                .and_then(|hid| report.hosts.get(hid as usize))
                .and_then(|h| {
                    h.name
                        .as_ref()
                        .or(h.fqdn.as_ref())
                        .or(h.ip.as_ref())
                        .or(h.netbios.as_ref())
                        .cloned()
                })
                .unwrap_or_else(|| "Unknown host".to_string());
            let pname = item
                .plugin_name
                .clone()
                .unwrap_or_else(|| format!("Plugin {pid}"));
            let desc = item.description.clone().unwrap_or_default();
            let cvss = item.cvss_base_score;
            let solution = item.solution.clone();

            plugins
                .entry(pid)
                .and_modify(|e| {
                    e.1.insert(host.clone());
                })
                .or_insert_with(|| {
                    let mut set = BTreeSet::new();
                    set.insert(host);
                    (pname, set, desc, cvss, solution)
                });
        }

        let mut vec: Vec<_> = plugins.into_iter().collect();
        vec.sort_by(|a, b| b.1.1.len().cmp(&a.1.1.len()));
        vec.truncate(10);

        let mut counter = 1;
        for (pid, (name, hosts, desc, cvss, solution)) in vec {
            renderer.heading(2, &format!("{counter}: {name} (Plugin {pid})"))?;
            let host_list = hosts.iter().cloned().collect::<Vec<_>>().join(", ");
            renderer.text(&format!("Hosts: {host_list}"))?;
            if !desc.is_empty() {
                renderer.text(&format!("Description: {desc}"))?;
            }
            if let Some(score) = cvss {
                renderer.text(&format!("CVSS Base Score: {score}"))?;
            }
            if let Some(sol) = solution {
                if !sol.is_empty() {
                    renderer.text(&format!("Solution: {sol}"))?;
                }
            }
            counter += 1;
            renderer.start_new_page()?;
        }
        Ok(())
    }
}
