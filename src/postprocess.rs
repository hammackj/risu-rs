use crate::parser::NessusReport;

/// Perform post-processing on parsed data
pub fn process(report: &mut NessusReport) {
    fix_ips(report);
    println!(
        "Post-processed report v{} ({} hosts, {} items, {} plugins)",
        report.version,
        report.hosts.len(),
        report.items.len(),
        report.plugins.len()
    );
}

/// Normalize missing IP addresses by falling back to host names.
fn fix_ips(report: &mut NessusReport) {
    for host in &mut report.hosts {
        if host.ip.is_none() {
            if let Some(name) = host.name.clone() {
                host.ip = Some(name);
            }
        }
    }
}

