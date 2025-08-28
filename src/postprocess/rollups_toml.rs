use super::{PluginEntry, PostProcess, PostProcessInfo};
use crate::parser::NessusReport;
use crate::models::{Item, Plugin};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use tracing::info;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct RollupDef {
    plugin_id: i32,
    plugin_name: String,
    item_name: String,
    description: String,
    plugin_ids: Vec<i32>,
}

#[derive(Debug, Deserialize)]
struct RollupsFile {
    #[serde(default)]
    rollup: Vec<RollupDef>,
}

pub(crate) fn find_rollups_file() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("RISU_ROLLUPS_FILE") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    let cwd = PathBuf::from("rollups.toml");
    if cwd.exists() {
        return Some(cwd);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let user = PathBuf::from(home).join(".risu").join("rollups.toml");
        if user.exists() {
            return Some(user);
        }
    }
    None
}

fn load_defs() -> Vec<RollupDef> {
    let Some(path) = find_rollups_file() else { return Vec::new(); };
    match fs::read_to_string(&path) {
        Ok(txt) => match toml::from_str::<RollupsFile>(&txt) {
            Ok(cfg) => {
                info!("Loaded rollups from {} ({} rules)", path.display(), cfg.rollup.len());
                cfg.rollup
            }
            Err(e) => {
                eprintln!(
                    "Failed to parse rollups file '{}': {}",
                    path.display(),
                    e
                );
                Vec::new()
            }
        },
        Err(e) => {
            eprintln!(
                "Failed to read rollups file '{}': {}",
                path.display(),
                e
            );
            Vec::new()
        }
    }
}

// Core rollup executor: per-host rollup items and metadata enrichment.
fn run_rollup(
    report: &mut NessusReport,
    plugin_id: i32,
    plugin_name: &str,
    item_name: &str,
    description: &str,
    plugin_ids: &[i32],
) {
    // Avoid duplicates
    if report
        .plugins
        .iter()
        .any(|p| p.plugin_id == Some(plugin_id))
    {
        return;
    }

    // Track matches and per-host severities
    let mut found_any = false;
    let mut overall_max_sev = 0;
    let mut per_host_max: HashMap<i32, i32> = HashMap::new();

    for item in &mut report.items {
        if let Some(pid) = item.plugin_id {
            if plugin_ids.contains(&pid) {
                found_any = true;
                if let Some(sev) = item.severity {
                    if sev > overall_max_sev {
                        overall_max_sev = sev;
                    }
                    if let Some(hid) = item.host_id {
                        let e = per_host_max.entry(hid).or_insert(0);
                        if sev > *e {
                            *e = sev;
                        }
                    }
                }
                item.real_severity = item.severity;
                item.severity = Some(-1);
            }
        }
    }
    if !found_any {
        return;
    }

    let mut rollup = Plugin::default();
    rollup.plugin_id = Some(plugin_id);
    rollup.plugin_name = Some(plugin_name.to_string());
    rollup.family_name = Some("Risu Rollup Plugins".to_string());
    rollup.description = Some(description.to_string());
    rollup.plugin_type = Some("Rollup".to_string());
    rollup.rollup = Some(true);
    rollup.synopsis = Some("Software often has vulnerabilities that are corrected in newer versions. It was determined that an older version of the software is installed on this system.".to_string());
    rollup.solution = Some("If possible, update to the latest version of the software.".to_string());

    // Enrich from underlying plugins
    let candidates: Vec<&Plugin> = report
        .plugins
        .iter()
        .filter(|p| p.plugin_id.map_or(false, |id| plugin_ids.contains(&id)))
        .collect();

    let newest_opt: Option<&Plugin> = candidates
        .iter()
        .filter_map(|p| p.plugin_modification_date.map(|d| (*p, d)))
        .max_by_key(|(_, d)| *d)
        .map(|(p, _)| p)
        .or_else(|| candidates.first().copied());
    if let Some(newest) = newest_opt {
        rollup.plugin_version = newest.plugin_version.clone();
        rollup.plugin_publication_date = newest.plugin_publication_date;
        rollup.plugin_modification_date = newest.plugin_modification_date;
    }
    if let Some(oldest_vuln) = candidates
        .iter()
        .filter_map(|p| p.vuln_publication_date)
        .min()
    {
        rollup.vuln_publication_date = Some(oldest_vuln);
    }
    if let Some(best_cvss) = candidates
        .iter()
        .filter_map(|p| p.cvss_base_score.map(|s| (*p, s)))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(p, _)| p)
    {
        rollup.cvss_base_score = best_cvss.cvss_base_score;
        rollup.cvss_vector = best_cvss.cvss_vector.clone();
    }
    let parse_temporal = |s: &str| s.parse::<f32>().ok();
    if let Some(best_temp) = candidates
        .iter()
        .filter_map(|p| p.cvss_temporal_score.as_deref().and_then(|s| parse_temporal(s)).map(|v| (*p, v)))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(p, _)| p)
    {
        rollup.cvss_temporal_score = best_temp.cvss_temporal_score.clone();
        rollup.cvss_temporal_vector = best_temp.cvss_temporal_vector.clone();
    }
    let risk_order = ["Critical", "High", "Medium", "Low", "Info"];
    for rf in risk_order.iter() {
        if candidates
            .iter()
            .any(|p| p.risk_factor.as_deref() == Some(*rf))
        {
            rollup.risk_factor = Some((*rf).to_string());
            break;
        }
    }
    if candidates
        .iter()
        .any(|p| p.exploit_available.as_deref() == Some("true"))
    {
        rollup.exploit_available = Some("true".to_string());
    }
    if candidates
        .iter()
        .any(|p| p.exploit_framework_core.as_deref() == Some("true"))
    {
        rollup.exploit_framework_core = Some("true".to_string());
    }
    if candidates
        .iter()
        .any(|p| p.exploit_framework_metasploit.as_deref() == Some("true"))
    {
        rollup.exploit_framework_metasploit = Some("true".to_string());
    }
    if candidates
        .iter()
        .any(|p| p.exploit_framework_canvas.as_deref() == Some("true"))
    {
        rollup.exploit_framework_canvas = Some("true".to_string());
    }
    if candidates
        .iter()
        .any(|p| p.exploit_framework_exploithub.as_deref() == Some("true"))
    {
        rollup.exploit_framework_exploithub = Some("true".to_string());
    }
    if candidates
        .iter()
        .any(|p| p.exploit_framework_d2_elliot.as_deref() == Some("true"))
    {
        rollup.exploit_framework_d2_elliot = Some("true".to_string());
    }
    if candidates.iter().any(|p| p.in_the_news == Some(true)) {
        rollup.in_the_news = Some(true);
    }
    if candidates
        .iter()
        .any(|p| p.exploited_by_malware.as_deref() == Some("true"))
    {
        rollup.exploited_by_malware = Some("true".to_string());
    }
    if candidates
        .iter()
        .any(|p| p.exploited_by_nessus == Some(true))
    {
        rollup.exploited_by_nessus = Some(true);
    }
    if candidates
        .iter()
        .any(|p| p.unsupported_by_vendor == Some(true))
    {
        rollup.unsupported_by_vendor = Some(true);
    }
    if candidates
        .iter()
        .any(|p| p.default_account == Some(true))
    {
        rollup.default_account = Some(true);
    }

    report.plugins.push(rollup);

    if !per_host_max.is_empty() {
        for (hid, sev) in per_host_max.into_iter() {
            let mut item = Item::default();
            item.host_id = Some(hid);
            item.plugin_id = Some(plugin_id);
            item.plugin_name = Some(item_name.to_string());
            item.severity = Some(sev);
            item.rollup_finding = Some(true);
            report.items.push(item);
        }
    } else {
        let mut item = Item::default();
        item.plugin_id = Some(plugin_id);
        item.plugin_name = Some(item_name.to_string());
        item.severity = Some(overall_max_sev);
        item.rollup_finding = Some(true);
        report.items.push(item);
    }
}

struct TomlRollups;

impl PostProcess for TomlRollups {
    fn info(&self) -> PostProcessInfo {
        // Run before the static, code-generated rollups so those can detect
        // duplicates and skip if TOML has already created a rollup.
        PostProcessInfo { name: "rollups_toml", order: 990 }
    }

    fn run(&self, report: &mut NessusReport) {
        let defs = load_defs();
        if defs.is_empty() {
            return;
        }
        for d in defs {
            run_rollup(
                report,
                d.plugin_id,
                &d.plugin_name,
                &d.item_name,
                &d.description,
                &d.plugin_ids,
            );
        }
    }
}

inventory::submit! {
    PluginEntry { plugin: &TomlRollups }
}
