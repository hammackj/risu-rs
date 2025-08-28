use chrono::Local;

use super::{PluginEntry, PostProcess, PostProcessInfo};
use crate::parser::NessusReport;

struct RiskScore;

impl PostProcess for RiskScore {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "risk_score",
            order: 50,
        }
    }

    fn run(&self, report: &mut NessusReport) {
        let today = Local::now().naive_local().date();
        // Calculate item risk scores
        for item in &mut report.items {
            if let Some(pid) = item.plugin_id {
                if let Some(plugin) = report.plugins.iter().find(|p| p.plugin_id == Some(pid)) {
                    let cvss = plugin.cvss_base_score.unwrap_or(1.0) as f64;
                    let vuln_pub_days = plugin
                        .vuln_publication_date
                        .map(|d| (today - d.date()).num_days() as f64)
                        .unwrap_or(1.0);
                    let exploitable_factor = if plugin.exploit_available.as_deref() == Some("true")
                    {
                        0.6
                    } else {
                        1.0
                    };
                    let score = (cvss * vuln_pub_days * 0.8) * exploitable_factor;
                    item.risk_score = Some(score.round() as i32);
                }
            }
        }
        // Calculate plugin risk scores
        for plugin in &mut report.plugins {
            if let Some(pid) = plugin.plugin_id {
                let count = report
                    .items
                    .iter()
                    .filter(|i| i.plugin_id == Some(pid))
                    .count();
                if count > 0 {
                    if let Some(score) = report
                        .items
                        .iter()
                        .find(|i| i.plugin_id == Some(pid))
                        .and_then(|i| i.risk_score)
                    {
                        plugin.risk_score = Some(score * count as i32);
                    }
                }
            }
        }
        // Calculate host risk scores (aggregate per-host item scores)
        let host_count = report.hosts.len();
        for host in &mut report.hosts {
            let sum: i32 = report
                .items
                .iter()
                .filter(|i| i.host_id == Some(host.id) || (i.host_id.is_none() && host_count <= 1))
                .filter_map(|i| i.risk_score)
                .sum();
            host.risk_score = Some(sum);
        }
    }
}

inventory::submit! {
    PluginEntry { plugin: &RiskScore }
}
