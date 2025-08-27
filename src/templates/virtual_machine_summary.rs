use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;

/// Template that lists virtual machines detected by plugin 20094 grouped by hypervisor type.
pub struct VirtualMachineSummaryTemplate;

impl VirtualMachineSummaryTemplate {
    fn detect_hypervisor(output: Option<&String>) -> &'static str {
        let Some(out) = output else { return "Unknown" };
        let lower = out.to_lowercase();
        if lower.contains("vmware") {
            "VMware"
        } else if lower.contains("hyper-v") || lower.contains("hyperv") {
            "Hyper-V"
        } else if lower.contains("virtualbox") {
            "VirtualBox"
        } else if lower.contains("xen") {
            "Xen"
        } else if lower.contains("kvm") {
            "KVM"
        } else if lower.contains("parallels") {
            "Parallels"
        } else {
            "Unknown"
        }
    }
}

impl Template for VirtualMachineSummaryTemplate {
    fn name(&self) -> &str {
        "virtual_machine_summary"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        _args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        const PLUGIN_ID: i32 = 20094;
        renderer.heading(1, "Virtual Machine Summary")?;
        let mut groups: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
        let vm_items: Vec<_> = report
            .items
            .iter()
            .filter(|it| it.plugin_id == Some(PLUGIN_ID))
            .collect();
        for (idx, item) in vm_items.iter().enumerate() {
            let Some(host) = report.hosts.get(idx) else {
                continue;
            };
            let host_name = host
                .name
                .clone()
                .or(host.fqdn.clone())
                .or(host.ip.clone())
                .or(host.netbios.clone())
                .unwrap_or_else(|| "unknown".into());
            let hv = Self::detect_hypervisor(item.plugin_output.as_ref());
            groups.entry(hv).or_default().insert(host_name);
        }
        if groups.is_empty() {
            renderer.text("No virtual machines detected.")?;
            return Ok(());
        }
        for (hv, hosts) in groups {
            renderer.heading(2, hv)?;
            for host in hosts {
                renderer.text(&host)?;
            }
        }
        Ok(())
    }
}

/// Metadata about this template.
pub struct Metadata {
    pub name: &'static str,
    pub author: &'static str,
    pub renderer: &'static str,
}

pub static METADATA: Metadata = Metadata {
    name: "virtual_machine_summary",
    author: "ported",
    renderer: "text",
};
