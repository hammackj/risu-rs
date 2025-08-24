use super::{PluginEntry, PostProcess, PostProcessInfo};
use crate::parser::NessusReport;

struct FixIps;

impl PostProcess for FixIps {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "fix_ips",
            order: 10,
        }
    }

    fn run(&self, report: &mut NessusReport) {
        for host in &mut report.hosts {
            if host.ip.is_none() {
                if let Some(name) = host.name.clone() {
                    host.ip = Some(name);
                }
            }
        }
    }
}

inventory::submit! {
    PluginEntry { plugin: &FixIps }
}
