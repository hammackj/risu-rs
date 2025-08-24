//! Utilities for parsing Nessus XML reports into in-memory models.

use std::collections::BTreeSet;
use std::path::Path;

use quick_xml::Reader;
use quick_xml::events::Event;
use std::io::BufRead;
use tracing::{debug, info};

use crate::models::{
    FamilySelection, Host, IndividualPluginSelection, Item, Patch, Plugin, PluginsPreference,
    Policy, ServerPreference,
};
use regex::Regex;

/// Parsed representation of a Nessus report.
#[derive(Default)]
pub struct NessusReport {
    pub version: String,
    pub hosts: Vec<Host>,
    pub items: Vec<Item>,
    pub plugins: Vec<Plugin>,
    pub patches: Vec<Patch>,
    pub policies: Vec<Policy>,
    pub family_selections: Vec<FamilySelection>,
    pub individual_plugin_selections: Vec<IndividualPluginSelection>,
    pub plugins_preferences: Vec<PluginsPreference>,
    pub server_preferences: Vec<ServerPreference>,
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
    let mut current_patches: Vec<Patch> = Vec::new();

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
                b"Policy" => {
                    let (policy, families, individuals, plugin_prefs, server_prefs) =
                        parse_policy(&mut reader, &mut buf)?;
                    let policy_index = report.policies.len() as i32;
                    report.policies.push(policy);
                    for mut f in families {
                        f.policy_id = Some(policy_index);
                        report.family_selections.push(f);
                    }
                    for mut i in individuals {
                        i.policy_id = Some(policy_index);
                        report.individual_plugin_selections.push(i);
                    }
                    for mut p in plugin_prefs {
                        p.policy_id = Some(policy_index);
                        report.plugins_preferences.push(p);
                    }
                    for mut s in server_prefs {
                        s.policy_id = Some(policy_index);
                        report.server_preferences.push(s);
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
                }
                _ => {
                    unknown_tags.insert(String::from_utf8_lossy(e.name().as_ref()).to_string());
                }
            },
            Event::Text(e) => {
                if let Some(tag) = &current_tag {
                    if let Some(host) = &mut current_host {
                        let val = e.unescape()?.into_owned();
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

fn parse_policy<B: BufRead>(
    reader: &mut Reader<B>,
    buf: &mut Vec<u8>,
) -> Result<
    (
        Policy,
        Vec<FamilySelection>,
        Vec<IndividualPluginSelection>,
        Vec<PluginsPreference>,
        Vec<ServerPreference>,
    ),
    crate::error::Error,
> {
    let mut policy = empty_policy();
    let mut families = Vec::new();
    let mut individuals = Vec::new();
    let mut plugin_prefs = Vec::new();
    let mut server_prefs = Vec::new();

    let mut current_tag: Option<String> = None;
    let mut current_family: Option<FamilySelection> = None;
    let mut current_individual: Option<IndividualPluginSelection> = None;
    let mut current_plugin_pref: Option<PluginsPreference> = None;
    let mut current_server_pref: Option<ServerPreference> = None;

    loop {
        match reader.read_event_into(buf)? {
            Event::Start(e) => match e.name().as_ref() {
                b"policyName" | b"policyComments" | b"policyOwner" | b"visibility" => {
                    current_tag = Some(String::from_utf8_lossy(e.name().as_ref()).to_string());
                }
                b"FamilyItem" => current_family = Some(empty_family_selection()),
                b"PluginItem" => current_individual = Some(empty_individual_plugin_selection()),
                b"item" => current_plugin_pref = Some(empty_plugins_preference()),
                b"preference" => current_server_pref = Some(empty_server_preference()),
                b"FamilyName" | b"Status" | b"PluginId" | b"PluginName" | b"Family" | b"name"
                | b"value" | b"pluginName" | b"pluginId" | b"fullName" | b"preferenceName"
                | b"preferenceType" | b"preferenceValues" | b"selectedValue" => {
                    current_tag = Some(String::from_utf8_lossy(e.name().as_ref()).to_string());
                }
                _ => {}
            },
            Event::Text(e) => {
                if let Some(tag) = &current_tag {
                    let val = e.unescape()?.into_owned();
                    match tag.as_str() {
                        "policyName" => policy.name = Some(val),
                        "policyComments" => policy.comments = Some(val),
                        "policyOwner" => policy.owner = Some(val),
                        "visibility" => policy.visibility = Some(val),
                        "FamilyName" => {
                            if let Some(ref mut f) = current_family {
                                f.family_name = Some(val)
                            }
                        }
                        "Status" => {
                            if let Some(ref mut f) = current_family {
                                f.status = Some(val.clone())
                            }
                            if let Some(ref mut i) = current_individual {
                                i.status = Some(val)
                            }
                        }
                        "PluginId" => {
                            if let Some(ref mut i) = current_individual {
                                i.plugin_id = val.parse().ok()
                            }
                        }
                        "PluginName" => {
                            if let Some(ref mut i) = current_individual {
                                i.plugin_name = Some(val)
                            }
                        }
                        "Family" => {
                            if let Some(ref mut i) = current_individual {
                                i.family = Some(val)
                            }
                        }
                        "name" => {
                            if let Some(ref mut s) = current_server_pref {
                                s.name = Some(val)
                            }
                        }
                        "value" => {
                            if let Some(ref mut s) = current_server_pref {
                                s.value = Some(val)
                            }
                        }
                        "pluginName" => {
                            if let Some(ref mut p) = current_plugin_pref {
                                p.plugin_name = Some(val)
                            }
                        }
                        "pluginId" => {
                            if let Some(ref mut p) = current_plugin_pref {
                                p.plugin_id = val.parse().ok()
                            }
                        }
                        "fullName" => {
                            if let Some(ref mut p) = current_plugin_pref {
                                p.full_name = Some(val)
                            }
                        }
                        "preferenceName" => {
                            if let Some(ref mut p) = current_plugin_pref {
                                p.preference_name = Some(val)
                            }
                        }
                        "preferenceType" => {
                            if let Some(ref mut p) = current_plugin_pref {
                                p.preference_type = Some(val)
                            }
                        }
                        "preferenceValues" => {
                            if let Some(ref mut p) = current_plugin_pref {
                                p.preference_values = Some(val)
                            }
                        }
                        "selectedValue" => {
                            if let Some(ref mut p) = current_plugin_pref {
                                p.selected_values = Some(val)
                            }
                        }
                        _ => {}
                    }
                }
            }
            Event::End(e) => match e.name().as_ref() {
                b"policyName" | b"policyComments" | b"policyOwner" | b"visibility"
                | b"FamilyName" | b"Status" | b"PluginId" | b"PluginName" | b"Family" | b"name"
                | b"value" | b"pluginName" | b"pluginId" | b"fullName" | b"preferenceName"
                | b"preferenceType" | b"preferenceValues" | b"selectedValue" => current_tag = None,
                b"FamilyItem" => {
                    if let Some(f) = current_family.take() {
                        families.push(f);
                    }
                }
                b"PluginItem" => {
                    if let Some(i) = current_individual.take() {
                        individuals.push(i);
                    }
                }
                b"item" => {
                    if let Some(p) = current_plugin_pref.take() {
                        plugin_prefs.push(p);
                    }
                }
                b"preference" => {
                    if let Some(s) = current_server_pref.take() {
                        server_prefs.push(s);
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

    Ok((policy, families, individuals, plugin_prefs, server_prefs))
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

fn empty_policy() -> Policy {
    Policy {
        id: 0,
        name: None,
        comments: None,
        owner: None,
        visibility: None,
    }
}

fn empty_family_selection() -> FamilySelection {
    FamilySelection {
        id: 0,
        policy_id: None,
        family_name: None,
        status: None,
    }
}

fn empty_individual_plugin_selection() -> IndividualPluginSelection {
    IndividualPluginSelection {
        id: 0,
        policy_id: None,
        plugin_id: None,
        plugin_name: None,
        family: None,
        status: None,
    }
}

fn empty_plugins_preference() -> PluginsPreference {
    PluginsPreference {
        id: 0,
        policy_id: None,
        plugin_name: None,
        plugin_id: None,
        full_name: None,
        preference_name: None,
        preference_type: None,
        preference_values: None,
        selected_values: None,
    }
}

fn empty_server_preference() -> ServerPreference {
    ServerPreference {
        id: 0,
        policy_id: None,
        name: None,
        value: None,
    }
}
