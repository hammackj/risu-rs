use std::net::IpAddr;

use super::{PluginEntry, PostProcess, PostProcessInfo};
use crate::parser::NessusReport;

struct SortHosts;

impl PostProcess for SortHosts {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "sort_hosts",
            order: 20,
        }
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
