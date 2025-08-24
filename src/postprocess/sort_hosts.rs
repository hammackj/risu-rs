use std::net::IpAddr;

use crate::parser::NessusReport;
use super::{PostProcess, PostProcessInfo, PluginEntry};

struct SortHosts;

impl PostProcess for SortHosts {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo { name: "sort_hosts", order: 20 }
    }

    fn run(&self, report: &mut NessusReport) {
        report.hosts.sort_by(|a, b| {
            let ia = a.ip.as_ref().and_then(|s| s.parse::<IpAddr>().ok());
            let ib = b.ip.as_ref().and_then(|s| s.parse::<IpAddr>().ok());
            ia.cmp(&ib)
        });
    }
}

inventory::submit! {
    PluginEntry { plugin: &SortHosts }
}
