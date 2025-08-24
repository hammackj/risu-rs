//! Utilities for parsing Nessus XML reports into in-memory models.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use quick_xml::events::Event;
use quick_xml::Reader;
use tracing::{debug, info};

use crate::models::{Attachment, Host, Item, Patch, Plugin};
use crate::models::{HostProperty, ServiceDescription};
use base64::{engine::general_purpose, Engine};
use regex::Regex;

/// Parsed representation of a Nessus report.
#[derive(Default)]
pub struct NessusReport {
    pub version: String,
    pub hosts: Vec<Host>,
    pub items: Vec<Item>,
    pub plugins: Vec<Plugin>,
    pub patches: Vec<Patch>,
    pub attachments: Vec<Attachment>,
    pub host_properties: Vec<HostProperty>,
    pub service_descriptions: Vec<ServiceDescription>,
}

/// Validate and parse a Nessus XML file into ORM models.
pub fn parse_file(path: &Path) -> Result<NessusReport, crate::error::Error> {
    info!("Parsing file: {}", path.display());

    let base_dir: PathBuf = path.parent().unwrap_or(Path::new(".")).to_path_buf();

    let mut reader = Reader::from_file(path)?;
    reader.trim_text(true);

    let mut buf = Vec::new();

    let mut report = NessusReport::default();
    let mut current_host: Option<Host> = None;
    let mut current_tag: Option<String> = None;
    let mut current_patches: Vec<Patch> = Vec::new();
    let mut current_host_properties: Vec<HostProperty> = Vec::new();
    let mut current_service_desc: Vec<ServiceDescription> = Vec::new();
    let mut current_host_item_indices: Vec<usize> = Vec::new();
    let mut current_item_index: Option<usize> = None;
    let mut in_plugin_output = false;
    let mut plugin_output_buf = String::new();

    struct PendingAttachment {
        name: String,
        content_type: Option<String>,
        data: String,
    }

    let mut current_attachment: Option<PendingAttachment> = None;

    let patch_re = Regex::new("(?i)ms\\d{2}-\\d+").unwrap();

    // Track XML elements or attributes we don't explicitly handle so developers
    // can spot schema changes.
    let mut unknown_tags = BTreeSet::new();
    let mut unknown_attrs = BTreeSet::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.name().as_ref() {
                b"NessusClientData_v2" => {
                    for a in e.attributes().flatten() {
                        if a.key.as_ref() == b"version" {
                            report.version = a.unescape_value()?.to_string();
                        } else {
                            unknown_attrs.insert(format!(
                                "NessusClientData_v2 {}",
                                String::from_utf8_lossy(a.key.as_ref())
                            ));
                        }
                    }
                }
                b"ReportHost" => {
                    let mut host = empty_host();
                    for a in e.attributes().flatten() {
                        if a.key.as_ref() == b"name" {
                            host.name = Some(a.unescape_value()?.to_string());
                        } else {
                            unknown_attrs.insert(format!(
                                "ReportHost {}",
                                String::from_utf8_lossy(a.key.as_ref())
                            ));
                        }
                    }
                    current_host = Some(host);
                    current_patches.clear();
                    current_host_properties.clear();
                    current_service_desc.clear();
                    current_host_item_indices.clear();
                }
                b"HostProperties" => {
                    // nothing to do, tags will follow
                }
                b"tag" => {
                    for a in e.attributes().flatten() {
                        if a.key.as_ref() == b"name" {
                            current_tag = Some(a.unescape_value()?.to_string());
                        } else {
                            unknown_attrs
                                .insert(format!("tag {}", String::from_utf8_lossy(a.key.as_ref())));
                        }
                    }
                }
                b"ReportItem" => {
                    let mut item = empty_item();
                    for a in e.attributes().flatten() {
                        match a.key.as_ref() {
                            b"pluginID" => {
                                item.plugin_id =
                                    a.unescape_value().ok().and_then(|v| v.parse().ok());
                            }
                            b"port" => {
                                item.port = a.unescape_value().ok().and_then(|v| v.parse().ok());
                            }
                            b"svc_name" => {
                                item.svc_name = Some(a.unescape_value()?.to_string());
                            }
                            b"protocol" => {
                                item.protocol = Some(a.unescape_value()?.to_string());
                            }
                            b"severity" => {
                                item.severity =
                                    a.unescape_value().ok().and_then(|v| v.parse().ok());
                            }
                            b"pluginName" => {
                                item.plugin_name = Some(a.unescape_value()?.to_string());
                            }
                            _ => {
                                unknown_attrs.insert(format!(
                                    "ReportItem {}",
                                    String::from_utf8_lossy(a.key.as_ref())
                                ));
                            }
                        }
                    }
                    let idx = report.items.len();
                    report.items.push(item);
                    current_host_item_indices.push(idx);
                    current_item_index = Some(idx);
                }
                b"plugin_output" => {
                    in_plugin_output = true;
                    plugin_output_buf.clear();
                }
                b"attachment" => {
                    let mut name = String::new();
                    let mut content_type = None;
                    for a in e.attributes().flatten() {
                        match a.key.as_ref() {
                            b"name" => name = a.unescape_value()?.to_string(),
                            b"type" => {
                                content_type = Some(a.unescape_value()?.to_string())
                            }
                            _ => {
                                unknown_attrs.insert(format!(
                                    "attachment {}",
                                    String::from_utf8_lossy(a.key.as_ref())
                                ));
                            }
                        }
                    }
                    current_attachment = Some(PendingAttachment {
                        name,
                        content_type,
                        data: String::new(),
                    });
                }
                _ => {
                    unknown_tags.insert(String::from_utf8_lossy(e.name().as_ref()).to_string());
                }
            },
            Event::Text(e) => {
                if let Some(att) = &mut current_attachment {
                    att.data.push_str(&e.unescape()?.into_owned());
                } else if in_plugin_output {
                    plugin_output_buf.push_str(&e.unescape()?.into_owned());
                } else if let Some(tag) = &current_tag {
                    if let Some(host) = &mut current_host {
                        let val = e.unescape()?.into_owned();
                        let mut hp = empty_host_property();
                        hp.name = Some(tag.clone());
                        hp.value = Some(val.clone());
                        current_host_properties.push(hp);
                        if patch_re.is_match(tag) {
                            let mut patch = empty_patch();
                            patch.name = Some(tag.clone());
                            patch.value = Some(val);
                            current_patches.push(patch);
                        } else {
                            match tag.as_str() {
                                "host-ip" => host.ip = Some(val),
                                "host-fqdn" => host.fqdn = Some(val),
                                "netbios-name" => host.netbios = Some(val),
                                "operating-system" => host.os = Some(val),
                                _ => {}
                            }
                        }
                    }
                }
            }
            Event::End(e) => match e.name().as_ref() {
                b"tag" => {
                    current_tag = None;
                }
                b"plugin_output" => {
                    in_plugin_output = false;
                    if let Some(idx) = current_item_index {
                        report.items[idx].plugin_output = Some(plugin_output_buf.clone());
                        if report.items[idx].plugin_id == Some(19506) {
                            for mut svc in parse_services(&plugin_output_buf) {
                                svc.item_id = Some(idx as i32);
                                current_service_desc.push(svc);
                            }
                        }
                    }
                }
                b"attachment" => {
                    if let Some(att) = current_attachment.take() {
                        let data = general_purpose::STANDARD
                            .decode(att.data.trim())
                            .unwrap_or_default();
                        let file_path = base_dir.join(&att.name);
                        std::fs::write(&file_path, &data)?;
                        let mut attachment = empty_attachment();
                        attachment.name = Some(att.name);
                        attachment.content_type = att.content_type;
                        attachment.path = Some(file_path.to_string_lossy().to_string());
                        attachment.size = Some(data.len() as i32);
                        let attachment_index = report.attachments.len();
                        report.attachments.push(attachment);
                        if let Some(idx) = current_item_index {
                            report.items[idx].attachment_id = Some(attachment_index as i32);
                        }
                    }
                }
                b"ReportItem" => {
                    current_item_index = None;
                }
                b"ReportHost" => {
                    if let Some(host) = current_host.take() {
                        report.hosts.push(host);
                        let host_index = (report.hosts.len() - 1) as i32;
                        for idx in &current_host_item_indices {
                            report.items[*idx].host_id = Some(host_index);
                        }
                        for mut patch in current_patches.drain(..) {
                            patch.host_id = Some(host_index);
                            report.patches.push(patch);
                        }
                        for mut hp in current_host_properties.drain(..) {
                            hp.host_id = Some(host_index);
                            report.host_properties.push(hp);
                        }
                        for mut sd in current_service_desc.drain(..) {
                            sd.host_id = Some(host_index);
                            report.service_descriptions.push(sd);
                        }
                    }
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    // very naive plugin collection: deduplicate by plugin_id from items
    for item in &report.items {
        if let Some(pid) = item.plugin_id {
            if !report.plugins.iter().any(|p| p.plugin_id == Some(pid)) {
                let mut plugin = empty_plugin();
                plugin.plugin_id = Some(pid);
                plugin.plugin_name = item.plugin_name.clone();
                report.plugins.push(plugin);
            }
        }
    }

    if !unknown_tags.is_empty() {
        debug!("Unknown XML tags encountered: {:?}", unknown_tags);
    }
    if !unknown_attrs.is_empty() {
        debug!("Unknown XML attributes encountered: {:?}", unknown_attrs);
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_report() {
        let path = std::path::Path::new("tests/fixtures/sample.nessus");
        let report = parse_file(path).expect("parse sample");
        assert_eq!(report.version, "2.0");
        assert_eq!(report.hosts.len(), 1);
        assert_eq!(report.hosts[0].ip.as_deref(), Some("192.168.0.1"));
        assert_eq!(report.plugins.len(), 1);
        assert_eq!(report.patches.len(), 1);
        assert_eq!(report.patches[0].name.as_deref(), Some("MS12-001"));
        assert_eq!(report.patches[0].value.as_deref(), Some("KB123456"));
    }

    #[test]
    fn parses_host_properties_and_services() {
        let path = std::path::Path::new("tests/fixtures/scaninfo.nessus");
        let report = parse_file(path).expect("parse scaninfo");
        assert_eq!(report.hosts.len(), 1);
        assert_eq!(report.host_properties.len(), 2);
        assert_eq!(report.service_descriptions.len(), 2);
        // host properties linked
        for hp in &report.host_properties {
            assert_eq!(hp.host_id, Some(0));
        }
        // service descriptions parsed
        let names: Vec<_> = report
            .service_descriptions
            .iter()
            .filter_map(|s| s.name.clone())
            .collect();
        assert!(names.contains(&"ssh".to_string()));
        assert!(names.contains(&"http".to_string()));
        // item plugin output captured
        assert!(report.items[0]
            .plugin_output
            .as_ref()
            .unwrap()
            .contains("Credentialed Checks"));
    }

    #[test]
    fn parses_attachment_block() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("attach.nessus");
        let xml = r#"<NessusClientData_v2>
<ReportHost name='h'>
<HostProperties></HostProperties>
<ReportItem pluginID='1' severity='0' pluginName='plug'>
<attachment name='a.txt' type='text/plain'>aGVsbG8=</attachment>
</ReportItem>
</ReportHost>
</NessusClientData_v2>"#;
        std::fs::write(&file_path, xml).unwrap();
        let report = parse_file(&file_path).expect("parse");
        assert_eq!(report.attachments.len(), 1);
        assert_eq!(report.attachments[0].name.as_deref(), Some("a.txt"));
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].attachment_id, Some(0));
        let saved = dir.path().join("a.txt");
        assert!(saved.exists());
        let data = std::fs::read(saved).unwrap();
        assert_eq!(data, b"hello");
    }
}

fn empty_host() -> Host {
    Host {
        id: 0,
        nessus_report_id: None,
        name: None,
        os: None,
        mac: None,
        start: None,
        end: None,
        ip: None,
        fqdn: None,
        netbios: None,
        notes: None,
        risk_score: None,
        user_id: None,
        engagement_id: None,
    }
}

fn empty_item() -> Item {
    Item {
        id: 0,
        host_id: None,
        plugin_id: None,
        attachment_id: None,
        plugin_output: None,
        port: None,
        svc_name: None,
        protocol: None,
        severity: None,
        plugin_name: None,
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
    }
}

fn empty_attachment() -> Attachment {
    Attachment {
        id: 0,
        name: None,
        content_type: None,
        path: None,
        size: None,
    }
}

fn empty_plugin() -> Plugin {
    Plugin {
        id: 0,
        plugin_id: None,
        plugin_name: None,
        family_name: None,
        description: None,
        plugin_version: None,
        plugin_publication_date: None,
        plugin_modification_date: None,
        vuln_publication_date: None,
        cvss_vector: None,
        cvss_base_score: None,
        cvss_temporal_score: None,
        cvss_temporal_vector: None,
        exploitability_ease: None,
        exploit_framework_core: None,
        exploit_framework_metasploit: None,
        metasploit_name: None,
        exploit_framework_canvas: None,
        canvas_package: None,
        exploit_available: None,
        risk_factor: None,
        solution: None,
        synopsis: None,
        plugin_type: None,
        exploit_framework_exploithub: None,
        exploithub_sku: None,
        stig_severity: None,
        fname: None,
        always_run: None,
        script_version: None,
        d2_elliot_name: None,
        exploit_framework_d2_elliot: None,
        exploited_by_malware: None,
        rollup: None,
        risk_score: None,
        compliance: None,
        root_cause: None,
        agent: None,
        potential_vulnerability: None,
        in_the_news: None,
        exploited_by_nessus: None,
        unsupported_by_vendor: None,
        default_account: None,
        user_id: None,
        engagement_id: None,
        policy_id: None,
    }
}

fn empty_patch() -> Patch {
    Patch {
        id: 0,
        host_id: None,
        name: None,
        value: None,
        user_id: None,
        engagement_id: None,
    }
}

fn empty_host_property() -> HostProperty {
    HostProperty {
        id: 0,
        host_id: None,
        name: None,
        value: None,
        user_id: None,
        engagement_id: None,
    }
}

fn empty_service_description() -> ServiceDescription {
    ServiceDescription {
        id: 0,
        host_id: None,
        item_id: None,
        name: None,
        port: None,
        protocol: None,
        description: None,
        user_id: None,
        engagement_id: None,
    }
}

fn parse_services(output: &str) -> Vec<ServiceDescription> {
    let re = Regex::new(r"(?m)^(?P<port>\d+)/(?P<proto>\w+)\s+\w+\s+(?P<name>[\w\-\.]+)").unwrap();
    let mut services = Vec::new();
    for caps in re.captures_iter(output) {
        let mut svc = empty_service_description();
        if let Ok(port) = caps["port"].parse::<i32>() {
            svc.port = Some(port);
        }
        if let Some(proto) = caps.name("proto") {
            svc.protocol = Some(proto.as_str().to_string());
        }
        if let Some(name) = caps.name("name") {
            svc.name = Some(name.as_str().to_string());
        }
        services.push(svc);
    }
    services
}
