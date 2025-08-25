use super::{PluginEntry, PostProcess, PostProcessInfo};
use crate::parser::NessusReport;

struct DowngradePlugins;

impl PostProcess for DowngradePlugins {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "downgrade_plugins",
            order: 45,
        }
    }

    fn run(&self, report: &mut NessusReport) {
        for (plugin_id, severity) in PLUGINS_TO_SEVERITY {
            for item in &mut report.items {
                if item.plugin_id == Some(*plugin_id) {
                    item.severity = Some(*severity);
                }
            }
        }
    }
}

inventory::submit! {
    PluginEntry { plugin: &DowngradePlugins }
}

const PLUGINS_TO_SEVERITY: &[(i32, i32)] = &[
    (41028, 0), // SNMP Agent Default Community Name (public)
    (10264, 0), // SNMP Agent Default Community Names
    (10081, 0), // FTP Privileged Port Bounce Scan
    (42411, 0), // Microsoft Windows SMB Shares Unprivileged Access
    (66349, 0), // X Server Unauthenticated Access: Screenshot
    (26925, 0), // VNC Server Unauthenticated Access
    (66174, 0), // VNC Server Unauthenticated Access: Screenshot
    (10205, 0), // rlogin Service Detection
    (20007, 2), // SSL Version 2 and 3 Protocol Detection
    (80101, 2), // IPMI v2.0 Password Hash Disclosure
];
