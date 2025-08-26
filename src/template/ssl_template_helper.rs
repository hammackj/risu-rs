use std::collections::HashMap;

use crate::parser::NessusReport;

/// Statistics about SSL findings.
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct SslStats {
    /// Total number of SSL related findings.
    pub total: usize,
    /// Findings related to weak or medium strength ciphers.
    pub weak_ciphers: usize,
    /// Findings related to certificate problems.
    pub cert_issues: usize,
}

/// Compute SSL related statistics for a report.
///
/// Returns a map of host name to counts along with global totals.
pub fn ssl_stats(report: &NessusReport) -> (HashMap<String, SslStats>, SslStats) {
    let mut per_host: HashMap<String, SslStats> = HashMap::new();
    let mut global = SslStats::default();

    for item in &report.items {
        let Some(name) = item.plugin_name.as_ref() else { continue };
        let lname = name.to_lowercase();
        if !lname.contains("ssl") {
            continue;
        }

        let host_name = item
            .host_id
            .and_then(|hid| {
                report
                    .hosts
                    .iter()
                    .find(|h| h.id == hid)
                    .and_then(|h| h.name.clone())
            })
            .unwrap_or_else(|| "unknown".to_string());

        let stats = per_host.entry(host_name).or_default();
        stats.total += 1;
        global.total += 1;
        if lname.contains("cipher") {
            stats.weak_ciphers += 1;
            global.weak_ciphers += 1;
        }
        if lname.contains("cert") {
            stats.cert_issues += 1;
            global.cert_issues += 1;
        }
    }

    (per_host, global)
}
