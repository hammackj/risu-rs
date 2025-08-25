//! Utilities for parsing vulnerability scan reports into in-memory models.

mod nexpose;
mod simple_nexpose;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use quick_xml::Reader;
use quick_xml::events::Event;
use tracing::{debug, info};

use crate::models::{
    Attachment, FamilySelection, Host, HostProperty, Item, Patch, Plugin, PluginPreference, Policy,
    PolicyPlugin, Reference, ServerPreference, ServiceDescription,
};
use base64::{Engine, engine::general_purpose};
use chrono::NaiveDateTime;
use lazy_static::lazy_static;
use regex::Regex;

/// XML element names that map directly to reference sources.
const VALID_REFERENCE_ELEMENTS: &[&str] = &[
    "cve", "bid", "cert", "osvdb", "iava", "edb", "rhsa", "secunia",
];

/// Host property names that are recognized and handled specially.
const VALID_HOST_PROPERTIES: &[&str] = &[
    "host-ip",
    "host-fqdn",
    "netbios-name",
    "operating-system",
    "mac-address",
    "HOST_START",
    "HOST_END",
];

lazy_static! {
    static ref PATCH_RE: Regex = Regex::new("(?i)ms\\d{2}-\\d+").unwrap();
    static ref TRACEROUTE_HOP_RE: Regex = Regex::new(r"^traceroute_hop_\\d+$").unwrap();
    static ref PCIDSS_RE: Regex = Regex::new(r"^pcidss:.*$").unwrap();
}

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
    pub references: Vec<Reference>,
    pub policies: Vec<Policy>,
    pub policy_plugins: Vec<PolicyPlugin>,
    pub family_selections: Vec<FamilySelection>,
    pub plugin_preferences: Vec<PluginPreference>,
    pub server_preferences: Vec<ServerPreference>,
}

/// Detect file type and parse accordingly.
pub fn parse_file(path: &Path) -> Result<NessusReport, crate::error::Error> {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .as_deref()
    {
        Some("csv") => {
            let report = simple_nexpose::parse_file(path)?;
            Ok(report.into())
        }
        Some("xml") => {
            if nexpose::nexpose_document::is_nexpose(path)? {
                nexpose::nexpose_document::parse_file(path)
            } else {
                parse_nessus(path)
            }
        }
        _ => parse_nessus(path),
    }
}

/// Validate and parse a Nessus XML file into ORM models.
fn parse_nessus(path: &Path) -> Result<NessusReport, crate::error::Error> {
    info!("Parsing file: {}", path.display());

    let mut reader = Reader::from_file(path)?;
    reader.trim_text(true);

    let mut buf = Vec::new();

    let mut report = NessusReport::default();
    let mut current_host: Option<Host> = None;
    let mut current_tag: Option<String> = None;
    let mut current_patches: Vec<Patch> = Vec::new();
    let mut current_host_properties: Vec<HostProperty> = Vec::new();
    let mut current_service_descriptions: Vec<ServiceDescription> = Vec::new();
    let mut pending_service_description: Option<ServiceDescription> = None;
    let mut current_plugin_output: Option<String> = None;
    let mut current_item_index: Option<i32> = None;
    let mut current_item_tag: Option<String> = None;
    let base_dir: PathBuf = path.parent().unwrap_or(Path::new(".")).to_path_buf();

    struct PendingAttachment {
        name: String,
        content_type: Option<String>,
        data: String,
    }

    let mut current_attachment: Option<PendingAttachment> = None;

    struct PendingReference {
        source: Option<String>,
        value: String,
    }

    let mut current_reference: Option<PendingReference> = None;

    // Track XML elements, host-property names, or attributes we don't explicitly
    // handle so developers can spot schema changes.
    let mut unknown_elements = BTreeSet::new();
    let mut unknown_host_props = BTreeSet::new();
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
                b"Policy" => {
                    let (
                        policy,
                        mut policy_plugins,
                        mut family_selections,
                        mut plugin_preferences,
                        mut server_preferences,
                    ) = parse_policy(&mut reader, &mut buf)?;
                    report.policies.push(policy);
                    report.policy_plugins.append(&mut policy_plugins);
                    report.family_selections.append(&mut family_selections);
                    report.plugin_preferences.append(&mut plugin_preferences);
                    report.server_preferences.append(&mut server_preferences);
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
                }
                b"HostProperties" => {
                    // nothing to do, tags will follow
                }
                b"tag" => {
                    for a in e.attributes().flatten() {
                        if a.key.as_ref() == b"name" {
                            let name = a.unescape_value()?.to_string();
                            if !VALID_HOST_PROPERTIES.contains(&name.as_str())
                                && !PATCH_RE.is_match(&name)
                                && !TRACEROUTE_HOP_RE.is_match(&name)
                                && !PCIDSS_RE.is_match(&name)
                            {
                                unknown_host_props.insert(name.clone());
                            }
                            current_tag = Some(name);
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
                    current_item_index = Some((report.items.len() - 1) as i32);
                    if let Some(pid) = report.items.last().and_then(|it| it.plugin_id) {
                        if let Some(plugin) =
                            report.plugins.iter_mut().find(|p| p.plugin_id == Some(pid))
                        {
                            if plugin.plugin_name.is_none() {
                                plugin.plugin_name =
                                    report.items.last().and_then(|it| it.plugin_name.clone());
                            }
                        } else {
                            let mut plugin = empty_plugin();
                            plugin.plugin_id = Some(pid);
                            plugin.plugin_name =
                                report.items.last().and_then(|it| it.plugin_name.clone());
                            report.plugins.push(plugin);
                        }
                        if pid == 22964 {
                            let mut sd = ServiceDescription::default();
                            sd.item_id = current_item_index;
                            sd.port = report.items.last().and_then(|it| it.port);
                            sd.svc_name = report.items.last().and_then(|it| it.svc_name.clone());
                            sd.protocol = report.items.last().and_then(|it| it.protocol.clone());
                            pending_service_description = Some(sd);
                        }
                    }
                }
                b"attachment" => {
                    let mut name = String::new();
                    let mut content_type = None;
                    for a in e.attributes().flatten() {
                        match a.key.as_ref() {
                            b"name" => name = a.unescape_value()?.to_string(),
                            b"type" => content_type = Some(a.unescape_value()?.to_string()),
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
                b"ref" => {
                    let mut src = None;
                    for a in e.attributes().flatten() {
                        if a.key.as_ref() == b"source" {
                            src = Some(a.unescape_value()?.to_string());
                        } else {
                            unknown_attrs
                                .insert(format!("ref {}", String::from_utf8_lossy(a.key.as_ref())));
                        }
                    }
                    current_reference = Some(PendingReference {
                        source: src,
                        value: String::new(),
                    });
                }
                b"xref" => {
                    current_reference = Some(PendingReference {
                        source: None,
                        value: String::new(),
                    });
                }
                b"plugin_output" => {
                    current_plugin_output = Some(String::new());
                }
                b"description"
                | b"solution"
                | b"risk_factor"
                | b"cvss_base_score"
                | b"cm:compliance-info"
                | b"cm:compliance-actual-value"
                | b"cm:compliance-check-id"
                | b"cm:compliance-policy-value"
                | b"cm:compliance-audit-file"
                | b"cm:compliance-check-name"
                | b"cm:compliance-result"
                | b"cm:compliance-output"
                | b"cm:compliance-reference"
                | b"cm:compliance-see-also"
                | b"cm:compliance-solution"
                | b"cm:compliance"
                | b"cm:root-cause"
                | b"cm:agent"
                | b"cm:potential-vulnerability"
                | b"cm:in-the-news"
                | b"cm:exploited-by-nessus"
                | b"cm:unsupported-by-vendor"
                | b"cm:default-account" => {
                    if current_item_index.is_some() {
                        current_item_tag =
                            Some(String::from_utf8_lossy(e.name().as_ref()).to_string());
                    } else {
                        unknown_elements
                            .insert(String::from_utf8_lossy(e.name().as_ref()).to_string());
                    }
                }
                _ => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if VALID_REFERENCE_ELEMENTS.contains(&name.as_str()) {
                        if current_item_index.is_some() {
                            current_reference = Some(PendingReference {
                                source: Some(name.to_uppercase()),
                                value: String::new(),
                            });
                        } else {
                            unknown_elements.insert(name);
                        }
                    } else {
                        unknown_elements.insert(name);
                    }
                }
            },
            Event::Text(e) => {
                if let Some(r) = &mut current_reference {
                    r.value.push_str(&e.unescape()?.into_owned());
                } else if let Some(att) = &mut current_attachment {
                    att.data.push_str(&e.unescape()?.into_owned());
                } else if let Some(out) = &mut current_plugin_output {
                    out.push_str(&e.unescape()?.into_owned());
                } else if let Some(field) = &current_item_tag {
                    let text = e.unescape()?.into_owned();
                    if let Some(idx) = current_item_index {
                        if let Some(item) = report.items.get_mut(idx as usize) {
                            match field.as_str() {
                                "description" => {
                                    item.description = Some(text.clone());
                                    if let Some(pid) = item.plugin_id {
                                        if let Some(plugin) = report
                                            .plugins
                                            .iter_mut()
                                            .find(|p| p.plugin_id == Some(pid))
                                        {
                                            if plugin.description.is_none() {
                                                plugin.description = Some(text.clone());
                                            }
                                        }
                                    }
                                }
                                "solution" => {
                                    item.solution = Some(text.clone());
                                    if let Some(pid) = item.plugin_id {
                                        if let Some(plugin) = report
                                            .plugins
                                            .iter_mut()
                                            .find(|p| p.plugin_id == Some(pid))
                                        {
                                            if plugin.solution.is_none() {
                                                plugin.solution = Some(text.clone());
                                            }
                                        }
                                    }
                                }
                                "risk_factor" => {
                                    item.risk_factor = Some(text.clone());
                                    if let Some(pid) = item.plugin_id {
                                        if let Some(plugin) = report
                                            .plugins
                                            .iter_mut()
                                            .find(|p| p.plugin_id == Some(pid))
                                        {
                                            if plugin.risk_factor.is_none() {
                                                plugin.risk_factor = Some(text.clone());
                                            }
                                        }
                                    }
                                }
                                "cvss_base_score" => {
                                    if let Ok(score) = text.parse::<f32>() {
                                        item.cvss_base_score = Some(score);
                                        if let Some(pid) = item.plugin_id {
                                            if let Some(plugin) = report
                                                .plugins
                                                .iter_mut()
                                                .find(|p| p.plugin_id == Some(pid))
                                            {
                                                if plugin.cvss_base_score.is_none() {
                                                    plugin.cvss_base_score = Some(score);
                                                }
                                            }
                                        }
                                    }
                                }
                                "cm:compliance-info" => {
                                    item.cm_compliance_info = Some(text.clone());
                                }
                                "cm:compliance-actual-value" => {
                                    item.cm_compliance_actual_value = Some(text.clone());
                                }
                                "cm:compliance-check-id" => {
                                    item.cm_compliance_check_id = Some(text.clone());
                                }
                                "cm:compliance-policy-value" => {
                                    item.cm_compliance_policy_value = Some(text.clone());
                                }
                                "cm:compliance-audit-file" => {
                                    item.cm_compliance_audit_file = Some(text.clone());
                                }
                                "cm:compliance-check-name" => {
                                    item.cm_compliance_check_name = Some(text.clone());
                                }
                                "cm:compliance-result" => {
                                    item.cm_compliance_result = Some(text.clone());
                                }
                                "cm:compliance-output" => {
                                    item.cm_compliance_output = Some(text.clone());
                                }
                                "cm:compliance-reference" => {
                                    item.cm_compliance_reference = Some(text.clone());
                                }
                                "cm:compliance-see-also" => {
                                    item.cm_compliance_see_also = Some(text.clone());
                                }
                                "cm:compliance-solution" => {
                                    item.cm_compliance_solution = Some(text.clone());
                                }
                                "cm:compliance" => {
                                    if let Some(pid) = item.plugin_id {
                                        if let Some(plugin) = report
                                            .plugins
                                            .iter_mut()
                                            .find(|p| p.plugin_id == Some(pid))
                                        {
                                            if plugin.compliance.is_none() {
                                                plugin.compliance = Some(text.clone());
                                            }
                                        }
                                    }
                                }
                                "cm:root-cause" => {
                                    if let Some(pid) = item.plugin_id {
                                        if let Some(plugin) = report
                                            .plugins
                                            .iter_mut()
                                            .find(|p| p.plugin_id == Some(pid))
                                        {
                                            if plugin.root_cause.is_none() {
                                                plugin.root_cause = Some(text.clone());
                                            }
                                        }
                                    }
                                }
                                "cm:agent" => {
                                    if let Some(pid) = item.plugin_id {
                                        if let Some(plugin) = report
                                            .plugins
                                            .iter_mut()
                                            .find(|p| p.plugin_id == Some(pid))
                                        {
                                            if plugin.agent.is_none() {
                                                plugin.agent = Some(text.clone());
                                            }
                                        }
                                    }
                                }
                                "cm:potential-vulnerability" => {
                                    if let Some(pid) = item.plugin_id {
                                        if let Some(plugin) = report
                                            .plugins
                                            .iter_mut()
                                            .find(|p| p.plugin_id == Some(pid))
                                        {
                                            if plugin.potential_vulnerability.is_none() {
                                                plugin.potential_vulnerability =
                                                    if text.eq_ignore_ascii_case("true") {
                                                        Some(true)
                                                    } else if text.eq_ignore_ascii_case("false") {
                                                        Some(false)
                                                    } else {
                                                        None
                                                    };
                                            }
                                        }
                                    }
                                }
                                "cm:in-the-news" => {
                                    if let Some(pid) = item.plugin_id {
                                        if let Some(plugin) = report
                                            .plugins
                                            .iter_mut()
                                            .find(|p| p.plugin_id == Some(pid))
                                        {
                                            if plugin.in_the_news.is_none() {
                                                plugin.in_the_news =
                                                    if text.eq_ignore_ascii_case("true") {
                                                        Some(true)
                                                    } else if text.eq_ignore_ascii_case("false") {
                                                        Some(false)
                                                    } else {
                                                        None
                                                    };
                                            }
                                        }
                                    }
                                }
                                "cm:exploited-by-nessus" => {
                                    if let Some(pid) = item.plugin_id {
                                        if let Some(plugin) = report
                                            .plugins
                                            .iter_mut()
                                            .find(|p| p.plugin_id == Some(pid))
                                        {
                                            if plugin.exploited_by_nessus.is_none() {
                                                plugin.exploited_by_nessus =
                                                    if text.eq_ignore_ascii_case("true") {
                                                        Some(true)
                                                    } else if text.eq_ignore_ascii_case("false") {
                                                        Some(false)
                                                    } else {
                                                        None
                                                    };
                                            }
                                        }
                                    }
                                }
                                "cm:unsupported-by-vendor" => {
                                    if let Some(pid) = item.plugin_id {
                                        if let Some(plugin) = report
                                            .plugins
                                            .iter_mut()
                                            .find(|p| p.plugin_id == Some(pid))
                                        {
                                            if plugin.unsupported_by_vendor.is_none() {
                                                plugin.unsupported_by_vendor =
                                                    if text.eq_ignore_ascii_case("true") {
                                                        Some(true)
                                                    } else if text.eq_ignore_ascii_case("false") {
                                                        Some(false)
                                                    } else {
                                                        None
                                                    };
                                            }
                                        }
                                    }
                                }
                                "cm:default-account" => {
                                    if let Some(pid) = item.plugin_id {
                                        if let Some(plugin) = report
                                            .plugins
                                            .iter_mut()
                                            .find(|p| p.plugin_id == Some(pid))
                                        {
                                            if plugin.default_account.is_none() {
                                                plugin.default_account =
                                                    if text.eq_ignore_ascii_case("true") {
                                                        Some(true)
                                                    } else if text.eq_ignore_ascii_case("false") {
                                                        Some(false)
                                                    } else {
                                                        None
                                                    };
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                } else if let Some(tag) = &current_tag {
                    let val = e.unescape()?.into_owned();
                    if let Some(host) = &mut current_host {
                        if PATCH_RE.is_match(tag) {
                            let mut patch = empty_patch();
                            patch.name = Some(tag.clone());
                            patch.value = Some(val.clone());
                            current_patches.push(patch);
                        } else {
                            match tag.as_str() {
                                "host-ip" => host.ip = Some(val.clone()),
                                "host-fqdn" => host.fqdn = Some(val.clone()),
                                "netbios-name" => host.netbios = Some(val.clone()),
                                "operating-system" => host.os = Some(val.clone()),
                                "mac-address" => host.mac = Some(val.clone()),
                                "HOST_START" => {
                                    if let Ok(dt) =
                                        NaiveDateTime::parse_from_str(&val, "%a %b %d %H:%M:%S %Y")
                                    {
                                        host.start = Some(dt);
                                    }
                                }
                                "HOST_END" => {
                                    if let Ok(dt) =
                                        NaiveDateTime::parse_from_str(&val, "%a %b %d %H:%M:%S %Y")
                                    {
                                        host.end = Some(dt);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    let mut prop = empty_host_property();
                    prop.name = Some(tag.clone());
                    prop.value = Some(val);
                    current_host_properties.push(prop);
                }
            }
            Event::End(e) => match e.name().as_ref() {
                b"tag" => {
                    current_tag = None;
                }
                b"description" | b"solution" | b"risk_factor" | b"cvss_base_score" => {
                    current_item_tag = None;
                }
                name if name.starts_with(b"cm:") => {
                    current_item_tag = None;
                }
                b"plugin_output" => {
                    if let Some(text) = current_plugin_output.take() {
                        if let Some(idx) = current_item_index {
                            if let Some(item) = report.items.get_mut(idx as usize) {
                                item.plugin_output = Some(text.clone());
                                if let Some(sd) = &mut pending_service_description {
                                    sd.description = Some(text);
                                }
                            }
                        }
                    }
                }
                b"ReportItem" => {
                    if let Some(sd) = pending_service_description.take() {
                        current_service_descriptions.push(sd);
                    }
                    current_item_index = None;
                    current_item_tag = None;
                }
                b"ReportHost" => {
                    if let Some(host) = current_host.take() {
                        report.hosts.push(host);
                        let host_index = (report.hosts.len() - 1) as i32;
                        for mut patch in current_patches.drain(..) {
                            patch.host_id = Some(host_index);
                            report.patches.push(patch);
                        }
                        for mut prop in current_host_properties.drain(..) {
                            prop.host_id = Some(host_index);
                            report.host_properties.push(prop);
                        }
                        for mut sd in current_service_descriptions.drain(..) {
                            sd.host_id = Some(host_index);
                            report.service_descriptions.push(sd);
                        }
                    }
                }
                b"attachment" => {
                    if let Some(att) = current_attachment.take() {
                        let bytes = general_purpose::STANDARD
                            .decode(att.data.as_bytes())
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        let file_path = base_dir.join(&att.name);
                        fs::write(&file_path, &bytes)?;
                        let mut attachment = Attachment::default();
                        attachment.name = Some(att.name);
                        attachment.content_type = att.content_type;
                        attachment.path = Some(file_path.to_string_lossy().to_string());
                        attachment.size = Some(bytes.len() as i32);
                        let id = report.attachments.len() as i32;
                        report.attachments.push(attachment);
                        if let Some(item) = report.items.last_mut() {
                            item.attachment_id = Some(id);
                        }
                    }
                }
                b"ref" | b"xref" => {
                    if let Some(p) = current_reference.take() {
                        let mut reference = Reference::default();
                        if let Some(idx) = current_item_index {
                            reference.item_id = Some(idx);
                            reference.plugin_id =
                                report.items.get(idx as usize).and_then(|it| it.plugin_id);
                        }
                        let mut src = p.source;
                        if src.is_none() {
                            let v_upper = p.value.to_uppercase();
                            if v_upper.starts_with("CVE") {
                                src = Some("CVE".to_string());
                            } else if v_upper.starts_with("BID") {
                                src = Some("BID".to_string());
                            }
                        }
                        reference.source = src;
                        reference.value = Some(p.value.trim().to_string());
                        report.references.push(reference);
                    }
                }
                _ if VALID_REFERENCE_ELEMENTS
                    .iter()
                    .any(|t| e.name().as_ref() == t.as_bytes()) =>
                {
                    if let Some(p) = current_reference.take() {
                        let mut reference = Reference::default();
                        if let Some(idx) = current_item_index {
                            reference.item_id = Some(idx);
                            reference.plugin_id =
                                report.items.get(idx as usize).and_then(|it| it.plugin_id);
                        }
                        let mut src = p.source;
                        if src.is_none() {
                            let v_upper = p.value.to_uppercase();
                            if v_upper.starts_with("CVE") {
                                src = Some("CVE".to_string());
                            } else if v_upper.starts_with("BID") {
                                src = Some("BID".to_string());
                            }
                        }
                        reference.source = src;
                        reference.value = Some(p.value.trim().to_string());
                        report.references.push(reference);
                    }
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    if !unknown_elements.is_empty() {
        debug!("Unknown XML elements encountered: {:?}", unknown_elements);
    }
    if !unknown_host_props.is_empty() {
        debug!(
            "Unknown host properties encountered: {:?}",
            unknown_host_props
        );
    }
    if !unknown_attrs.is_empty() {
        debug!("Unknown XML attributes encountered: {:?}", unknown_attrs);
    }

    Ok(report)
}

fn parse_policy<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<
    (
        Policy,
        Vec<PolicyPlugin>,
        Vec<FamilySelection>,
        Vec<PluginPreference>,
        Vec<ServerPreference>,
    ),
    crate::error::Error,
> {
    let mut policy = Policy::default();
    let mut policy_plugins = Vec::new();
    let mut family_selections = Vec::new();
    let mut plugin_preferences = Vec::new();
    let mut server_preferences = Vec::new();

    let mut current_tag: Option<String> = None;
    let mut current_plugin: Option<PolicyPlugin> = None;
    let mut current_family: Option<FamilySelection> = None;
    let mut current_pref: Option<PluginPreference> = None;
    let mut current_server_pref: Option<ServerPreference> = None;

    loop {
        match reader.read_event_into(buf)? {
            Event::Start(e) => match e.name().as_ref() {
                b"policyName" | b"policyComments" => {
                    current_tag = Some(String::from_utf8_lossy(e.name().as_ref()).to_string());
                }
                b"PluginItem" => current_plugin = Some(PolicyPlugin::default()),
                b"PluginID" | b"PluginName" | b"PluginFamily" | b"Status" => {
                    current_tag = Some(String::from_utf8_lossy(e.name().as_ref()).to_string());
                }
                b"FamilyItem" => current_family = Some(FamilySelection::default()),
                b"FamilyName" => {
                    current_tag = Some("FamilyName".to_string());
                }
                b"item" => current_pref = Some(PluginPreference::default()),
                b"pluginId" | b"fullname" | b"preferenceName" | b"preferenceType"
                | b"selectedValue" => {
                    current_tag = Some(String::from_utf8_lossy(e.name().as_ref()).to_string());
                }
                b"preference" => current_server_pref = Some(ServerPreference::default()),
                b"name" | b"value" => {
                    current_tag = Some(String::from_utf8_lossy(e.name().as_ref()).to_string());
                }
                _ => {}
            },
            Event::Text(e) => {
                if let Some(tag) = &current_tag {
                    let txt = e.unescape()?.into_owned();
                    if let Some(plg) = &mut current_plugin {
                        match tag.as_str() {
                            "PluginID" => plg.plugin_id = txt.parse().ok(),
                            "PluginName" => plg.plugin_name = Some(txt),
                            "PluginFamily" => plg.family_name = Some(txt),
                            "Status" => plg.status = Some(txt),
                            _ => {}
                        }
                    } else if let Some(fam) = &mut current_family {
                        match tag.as_str() {
                            "FamilyName" => fam.family_name = Some(txt),
                            "Status" => fam.status = Some(txt),
                            _ => {}
                        }
                    } else if let Some(pref) = &mut current_pref {
                        match tag.as_str() {
                            "pluginId" => pref.plugin_id = txt.parse().ok(),
                            "fullname" => pref.fullname = Some(txt),
                            "preferenceName" => pref.preference_name = Some(txt),
                            "preferenceType" => pref.preference_type = Some(txt),
                            "selectedValue" => pref.selected_value = Some(txt),
                            _ => {}
                        }
                    } else if let Some(sp) = &mut current_server_pref {
                        match tag.as_str() {
                            "name" => sp.name = Some(txt),
                            "value" => sp.value = Some(txt),
                            _ => {}
                        }
                    } else {
                        match tag.as_str() {
                            "policyName" => policy.name = Some(txt),
                            "policyComments" => policy.comments = Some(txt),
                            _ => {}
                        }
                    }
                }
            }
            Event::End(e) => match e.name().as_ref() {
                b"policyName" | b"policyComments" | b"PluginID" | b"PluginName"
                | b"PluginFamily" | b"Status" | b"FamilyName" | b"pluginId" | b"fullname"
                | b"preferenceName" | b"preferenceType" | b"selectedValue" | b"name" | b"value" => {
                    current_tag = None
                }
                b"PluginItem" => {
                    if let Some(p) = current_plugin.take() {
                        policy_plugins.push(p);
                    }
                }
                b"FamilyItem" => {
                    if let Some(f) = current_family.take() {
                        family_selections.push(f);
                    }
                }
                b"item" => {
                    if let Some(p) = current_pref.take() {
                        plugin_preferences.push(p);
                    }
                }
                b"preference" => {
                    if let Some(p) = current_server_pref.take() {
                        server_preferences.push(p);
                    }
                }
                b"Policy" => break,
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    Ok((
        policy,
        policy_plugins,
        family_selections,
        plugin_preferences,
        server_preferences,
    ))
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
        assert_eq!(report.host_properties.len(), 13);
        assert!(
            report
                .host_properties
                .iter()
                .any(|p| p.name.as_deref() == Some("host-ip")
                    && p.value.as_deref() == Some("192.168.0.1"))
        );
        assert!(
            report
                .host_properties
                .iter()
                .any(|p| p.name.as_deref() == Some("operating-system")
                    && p.value.as_deref() == Some("Linux"))
        );
        assert!(report.host_properties.iter().any(
            |p| p.name.as_deref() == Some("MS12-001") && p.value.as_deref() == Some("KB123456")
        ));
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

    #[test]
    fn routes_csv_to_simple_parser() {
        let path = std::path::Path::new("tests/fixtures/sample_nexpose.csv");
        let report = parse_file(path).expect("parse csv");
        assert_eq!(report.hosts.len(), 2);
        assert_eq!(report.items.len(), 3);
        assert_eq!(report.plugins.len(), 2);
    }

    #[test]
    fn parses_service_descriptions() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("svc.nessus");
        let xml = r#"<NessusClientData_v2>
<ReportHost name='h'>
<HostProperties></HostProperties>
<ReportItem pluginID='22964' port='80' svc_name='http' protocol='tcp' severity='0' pluginName='Service Detection'>
<plugin_output>Apache httpd</plugin_output>
</ReportItem>
</ReportHost>
</NessusClientData_v2>"#;
        std::fs::write(&file_path, xml).unwrap();
        let report = parse_file(&file_path).expect("parse");
        assert_eq!(report.service_descriptions.len(), 1);
        assert_eq!(
            report.service_descriptions[0].description.as_deref(),
            Some("Apache httpd")
        );
        assert_eq!(report.service_descriptions[0].port, Some(80));
        assert_eq!(
            report.service_descriptions[0].svc_name.as_deref(),
            Some("http")
        );
    }

    #[test]
    fn captures_mixed_reference_tags() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("refs.nessus");
        let xml = r#"<NessusClientData_v2><ReportHost name='h'><HostProperties></HostProperties><ReportItem pluginID='1' severity='0' pluginName='plug'><ref source='CVE'>CVE-2023-1111</ref><xref>BID-7654</xref><cve>CVE-2023-2222</cve><osvdb>12345</osvdb></ReportItem></ReportHost></NessusClientData_v2>"#;
        std::fs::write(&file_path, xml).unwrap();
        let report = parse_file(&file_path).expect("parse");
        assert_eq!(report.references.len(), 4);
        assert!(
            report
                .references
                .iter()
                .any(|r| r.source.as_deref() == Some("CVE")
                    && r.value.as_deref() == Some("CVE-2023-1111"))
        );
        assert!(
            report
                .references
                .iter()
                .any(|r| r.source.as_deref() == Some("BID")
                    && r.value.as_deref() == Some("BID-7654"))
        );
        assert!(
            report
                .references
                .iter()
                .any(|r| r.source.as_deref() == Some("CVE")
                    && r.value.as_deref() == Some("CVE-2023-2222"))
        );
        assert!(
            report.references.iter().any(
                |r| r.source.as_deref() == Some("OSVDB") && r.value.as_deref() == Some("12345")
            )
        );
    }

    #[test]
    fn parses_plugin_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("plugin_attrs.nessus");
        let xml = r#"<NessusClientData_v2><ReportHost name='h'><HostProperties></HostProperties>
<ReportItem pluginID='1' severity='0' pluginName='plug'></ReportItem>
<ReportItem pluginID='1' severity='0' pluginName='plug'>
<description>desc</description>
<solution>fix</solution>
<risk_factor>Medium</risk_factor>
<cvss_base_score>5.0</cvss_base_score>
</ReportItem>
</ReportHost></NessusClientData_v2>"#;
        std::fs::write(&file_path, xml).unwrap();
        let report = parse_file(&file_path).expect("parse");
        assert_eq!(report.items.len(), 2);
        assert_eq!(report.plugins.len(), 1);
        assert_eq!(report.items[1].description.as_deref(), Some("desc"));
        assert_eq!(report.items[1].solution.as_deref(), Some("fix"));
        assert_eq!(report.items[1].risk_factor.as_deref(), Some("Medium"));
        assert_eq!(report.items[1].cvss_base_score, Some(5.0));
        let plugin = &report.plugins[0];
        assert_eq!(plugin.description.as_deref(), Some("desc"));
        assert_eq!(plugin.solution.as_deref(), Some("fix"));
        assert_eq!(plugin.risk_factor.as_deref(), Some("Medium"));
        assert_eq!(plugin.cvss_base_score, Some(5.0));
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
