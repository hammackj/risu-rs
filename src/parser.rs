//! Utilities for parsing Nessus XML reports into in-memory models.

use std::collections::BTreeSet;
use std::path::Path;

use quick_xml::Reader;
use quick_xml::events::Event;
use tracing::{debug, info};

use crate::models::{Host, Item, Patch, Plugin, Reference};
use regex::Regex;

/// Parsed representation of a Nessus report.
#[derive(Default)]
pub struct NessusReport {
    pub version: String,
    pub hosts: Vec<Host>,
    pub items: Vec<Item>,
    pub plugins: Vec<Plugin>,
    pub patches: Vec<Patch>,
    pub references: Vec<Reference>,
}

/// Validate and parse a Nessus XML file into ORM models.
pub fn parse_file(path: &Path) -> Result<NessusReport, crate::error::Error> {
    info!("Parsing file: {}", path.display());

    let mut reader = Reader::from_file(path)?;
    reader.trim_text(true);

    let mut buf = Vec::new();

    let mut report = NessusReport::default();
    let mut current_host: Option<Host> = None;
    let mut current_tag: Option<String> = None;
    let mut current_ref: Option<Reference> = None;
    let mut current_patches: Vec<Patch> = Vec::new();
    let mut current_item: Option<usize> = None;

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
                    report.items.push(item);
                    current_item = Some(report.items.len() - 1);
                }
                b"xref" | b"ref" => {
                    if let Some(idx) = current_item {
                        let mut r = Reference::default();
                        r.plugin_id = report.items[idx].plugin_id;
                        for a in e.attributes().flatten() {
                            if a.key.as_ref() == b"source" {
                                r.source = Some(a.unescape_value()?.to_string());
                            } else {
                                unknown_attrs.insert(format!(
                                    "{} {}",
                                    String::from_utf8_lossy(e.name().as_ref()),
                                    String::from_utf8_lossy(a.key.as_ref())
                                ));
                            }
                        }
                        current_ref = Some(r);
                    }
                }
                _ => {
                    unknown_tags.insert(String::from_utf8_lossy(e.name().as_ref()).to_string());
                }
            },
            Event::Text(e) => {
                let val = e.unescape()?.into_owned();
                if let Some(ref mut r) = current_ref {
                    if r.source.is_none() {
                        if let Some((s, v)) = val.split_once(':') {
                            r.source = Some(s.to_string());
                            r.reference = Some(v.to_string());
                        } else {
                            r.reference = Some(val);
                        }
                    } else {
                        r.reference = Some(val);
                    }
                } else if let Some(tag) = &current_tag {
                    if let Some(host) = &mut current_host {
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
                b"ReportHost" => {
                    if let Some(host) = current_host.take() {
                        report.hosts.push(host);
                        let host_index = (report.hosts.len() - 1) as i32;
                        for mut patch in current_patches.drain(..) {
                            patch.host_id = Some(host_index);
                            report.patches.push(patch);
                        }
                    }
                }
                b"ReportItem" => {
                    current_item = None;
                }
                b"xref" | b"ref" => {
                    if let Some(r) = current_ref.take() {
                        report.references.push(r);
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
        assert_eq!(report.references.len(), 2);
        let cves = report.items[0].cves(&report);
        assert_eq!(cves, vec!["CVE-2023-9999"]);
        let bids = report.items[0].bids(&report);
        assert_eq!(bids, vec!["12345"]);
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

impl Item {
    /// All references associated with this item via its plugin ID.
    pub fn references<'a>(&self, report: &'a NessusReport) -> Vec<&'a Reference> {
        match self.plugin_id {
            Some(pid) => report
                .references
                .iter()
                .filter(|r| r.plugin_id == Some(pid))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Convenience helper returning CVE identifiers for this item.
    pub fn cves<'a>(&self, report: &'a NessusReport) -> Vec<&'a str> {
        self.references(report)
            .into_iter()
            .filter_map(|r| {
                if r.source.as_deref() == Some("CVE") {
                    r.reference.as_deref()
                } else {
                    None
                }
            })
            .collect()
    }

    /// Convenience helper returning BID identifiers for this item.
    pub fn bids<'a>(&self, report: &'a NessusReport) -> Vec<&'a str> {
        self.references(report)
            .into_iter()
            .filter_map(|r| {
                if r.source.as_deref() == Some("BID") {
                    r.reference.as_deref()
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Plugin {
    /// All references for this plugin.
    pub fn references<'a>(&self, report: &'a NessusReport) -> Vec<&'a Reference> {
        match self.plugin_id {
            Some(pid) => report
                .references
                .iter()
                .filter(|r| r.plugin_id == Some(pid))
                .collect(),
            None => Vec::new(),
        }
    }

    pub fn cves<'a>(&self, report: &'a NessusReport) -> Vec<&'a str> {
        self.references(report)
            .into_iter()
            .filter_map(|r| {
                if r.source.as_deref() == Some("CVE") {
                    r.reference.as_deref()
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn bids<'a>(&self, report: &'a NessusReport) -> Vec<&'a str> {
        self.references(report)
            .into_iter()
            .filter_map(|r| {
                if r.source.as_deref() == Some("BID") {
                    r.reference.as_deref()
                } else {
                    None
                }
            })
            .collect()
    }
}
