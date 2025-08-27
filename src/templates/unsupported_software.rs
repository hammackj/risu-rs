use std::collections::{BTreeMap, HashMap};
use std::error::Error;

use crate::parser::NessusReport;
use crate::renderer::Renderer;
use crate::template::Template;
use crate::template::helpers::unsupported_software_plugins;

/// Template that lists hosts running unsupported software.
pub struct UnsupportedSoftwareTemplate;

impl Template for UnsupportedSoftwareTemplate {
    fn name(&self) -> &str {
        "unsupported_software"
    }

    fn generate(
        &self,
        report: &NessusReport,
        renderer: &mut dyn Renderer,
        _args: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        renderer.heading(1, "Unsupported Software")?;

        let mut by_host: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for host in &report.hosts {
            let mut plugins = Vec::new();
            for item in report.items.iter().filter(|it| it.host_id == Some(host.id)) {
                let Some(pid) = item.plugin_id else { continue };
                if !unsupported_software_plugins.contains(&pid) {
                    continue;
                }
                let name = item
                    .plugin_name
                    .clone()
                    .unwrap_or_else(|| format!("Plugin {pid}"));
                plugins.push(name);
            }
            if !plugins.is_empty() {
                let host_name = host
                    .name
                    .clone()
                    .or(host.fqdn.clone())
                    .or(host.ip.clone())
                    .or(host.netbios.clone())
                    .unwrap_or_else(|| "unknown".into());
                by_host.insert(host_name, plugins);
            }
        }

        if by_host.is_empty() {
            renderer.text("No unsupported software detected.")?;
            return Ok(());
        }

        for (host, plugins) in by_host {
            renderer.heading(2, &host)?;
            for plugin in plugins {
                renderer.text(&plugin)?;
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
    name: "unsupported_software",
    author: "ported",
    renderer: "text",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Host, Item, Report, Scanner};
    use crate::parser::Filters;
    use crate::renderers::Renderer;
    use std::io;

    struct TestRenderer {
        pub out: String,
    }

    impl TestRenderer {
        fn new() -> Self {
            Self { out: String::new() }
        }
    }

    impl Renderer for TestRenderer {
        fn text(&mut self, text: &str) -> Result<(), Box<dyn Error>> {
            self.out.push_str(text);
            self.out.push('\n');
            Ok(())
        }
        fn start_new_page(&mut self) -> Result<(), Box<dyn Error>> {
            Ok(())
        }
        fn save(&mut self, _w: &mut dyn io::Write) -> Result<(), Box<dyn Error>> {
            Ok(())
        }
        fn heading(&mut self, _level: usize, text: &str) -> Result<(), Box<dyn Error>> {
            self.text(text)
        }
    }

    fn host(id: i32, name: &str) -> Host {
        Host {
            id,
            nessus_report_id: None,
            name: Some(name.into()),
            os: None,
            mac: None,
            start: None,
            end: None,
            ip: Some("1.1.1.1".into()),
            fqdn: None,
            netbios: None,
            notes: None,
            risk_score: None,
            user_id: None,
            engagement_id: None,
            scanner_id: None,
        }
    }

    fn item(host_id: i32, plugin_id: i32, name: &str) -> Item {
        Item {
            id: 0,
            host_id: Some(host_id),
            plugin_id: Some(plugin_id),
            attachment_id: None,
            plugin_output: None,
            port: None,
            svc_name: None,
            protocol: None,
            severity: None,
            plugin_name: Some(name.into()),
            description: None,
            solution: None,
            risk_factor: None,
            cvss_base_score: None,
            verified: None,
            cm_compliance_info: None,
            cm_compliance_actual_value: None,
            cm_compliance_check_id: None,
            cm_compliance_policy_value: None,
            cm_compliance_audit_file: None,
            cm_compliance_check_name: None,
            cm_compliance_result: None,
            cm_compliance_output: None,
            cm_compliance_reference: None,
            cm_compliance_see_also: None,
            cm_compliance_solution: None,
            real_severity: None,
            risk_score: None,
            user_id: None,
            engagement_id: None,
            rollup_finding: Some(false),
            scanner_id: None,
        }
    }

    fn report(hosts: Vec<Host>, items: Vec<Item>) -> NessusReport {
        NessusReport {
            report: Report::default(),
            version: String::new(),
            hosts,
            items,
            plugins: Vec::new(),
            patches: Vec::new(),
            attachments: Vec::new(),
            host_properties: Vec::new(),
            service_descriptions: Vec::new(),
            references: Vec::new(),
            policies: Vec::new(),
            policy_plugins: Vec::new(),
            family_selections: Vec::new(),
            plugin_preferences: Vec::new(),
            server_preferences: Vec::new(),
            filters: Filters::default(),
            scanner: Scanner::default(),
        }
    }

    #[test]
    fn host_with_unsupported_plugin_listed() {
        let rpt = report(
            vec![host(0, "vuln"), host(1, "clean")],
            vec![item(0, 55786, "Legacy Software")],
        );
        let mut r = TestRenderer::new();
        UnsupportedSoftwareTemplate
            .generate(&rpt, &mut r, &HashMap::new())
            .unwrap();
        assert!(r.out.contains("vuln"));
        assert!(!r.out.contains("clean"));
    }

    #[test]
    fn clean_report_produces_message() {
        let rpt = report(vec![host(0, "clean")], vec![item(0, 1, "Other")]);
        let mut r = TestRenderer::new();
        UnsupportedSoftwareTemplate
            .generate(&rpt, &mut r, &HashMap::new())
            .unwrap();
        assert!(r.out.contains("No unsupported software detected"));
        assert!(!r.out.contains("clean"));
    }
}
