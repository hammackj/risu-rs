use std::collections::{BTreeSet, HashMap};

use crate::parser::NessusReport;

/// Convert plugin output from the Nessus Scan Information plugin
/// into a key/value map. Lines are expected to be in the form
/// `Key: value`.
fn scan_info_to_hash(output: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in output.lines() {
        if let Some((k, v)) = line.split_once(':') {
            map.insert(
                k.trim().to_lowercase().replace(' ', "_"),
                v.trim().to_lowercase(),
            );
        }
    }
    map
}

/// Count authenticated vs unauthenticated scans by examining
/// plugin 19506 outputs.
pub fn authenticated_count(report: &NessusReport) -> (usize, usize) {
    let mut auth = 0usize;
    let mut unauth = 0usize;
    for item in &report.items {
        if item.plugin_id == Some(19506) {
            if let Some(ref out) = item.plugin_output {
                let info = scan_info_to_hash(out);
                if let Some(v) = info.get("credentialed_checks") {
                    if v.contains("yes") {
                        auth += 1;
                    } else {
                        unauth += 1;
                    }
                }
            }
        }
    }
    (auth, unauth)
}

/// List discovered services from service descriptions in the report.
pub fn discovered_services(report: &NessusReport) -> BTreeSet<String> {
    report
        .service_descriptions
        .iter()
        .filter_map(|s| {
            let name = s.name.as_ref()?;
            let port = s.port?;
            let proto = s.protocol.as_deref().unwrap_or("");
            Some(format!("{name} {port}/{proto}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_file;
    use std::path::Path;

    #[test]
    fn counts_and_services() {
        let report = parse_file(Path::new("tests/fixtures/scaninfo.nessus")).unwrap();
        let (auth, unauth) = authenticated_count(&report);
        assert_eq!(auth, 1);
        assert_eq!(unauth, 0);
        let services = discovered_services(&report);
        assert!(services.contains("ssh 22/tcp"));
        assert!(services.contains("http 80/tcp"));
    }
}
