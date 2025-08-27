use std::collections::HashMap;
use std::path::Path;

use csv::Reader;
use serde::Deserialize;

use crate::error::Error;
use crate::models::{Host, Item, Plugin, Report, Scanner, ServiceDescription};

/// Parsed representation of a simplified Nexpose CSV export.
#[derive(Default)]
pub struct SimpleNexpose {
    pub hosts: Vec<Host>,
    pub items: Vec<Item>,
    pub plugins: Vec<Plugin>,
    pub service_descriptions: Vec<ServiceDescription>,
}

#[derive(Debug, Deserialize)]
struct Record {
    ip: String,
    plugin_id: i32,
    plugin_name: String,
    #[serde(default)]
    port: Option<i32>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    severity: Option<i32>,
}

/// Parse a simple Nexpose CSV file into in-memory models.
pub fn parse_file(path: &Path) -> Result<SimpleNexpose, Error> {
    let mut rdr = Reader::from_path(path)?;
    let mut report = SimpleNexpose::default();
    let mut host_map: HashMap<String, usize> = HashMap::new();
    let mut plugin_map: HashMap<i32, usize> = HashMap::new();

    for result in rdr.deserialize() {
        let rec: Record = result?;

        if !host_map.contains_key(&rec.ip) {
            let mut host = empty_host();
            host.ip = Some(rec.ip.clone());
            report.hosts.push(host);
            host_map.insert(rec.ip.clone(), report.hosts.len() - 1);
        }

        if !plugin_map.contains_key(&rec.plugin_id) {
            let mut plugin = Plugin::default();
            plugin.plugin_id = Some(rec.plugin_id);
            plugin.plugin_name = Some(rec.plugin_name.clone());
            report.plugins.push(plugin);
            plugin_map.insert(rec.plugin_id, report.plugins.len() - 1);
        }

        let mut item = Item::default();
        item.plugin_id = Some(rec.plugin_id);
        item.plugin_name = Some(rec.plugin_name);
        item.port = rec.port;
        item.protocol = rec.protocol;
        item.severity = rec.severity;
        report.items.push(item);
    }

    Ok(report)
}

impl From<SimpleNexpose> for super::NessusReport {
    fn from(s: SimpleNexpose) -> Self {
        let mut r = super::NessusReport {
            report: Report::default(),
            version: "nexpose-simple".to_string(),
            hosts: s.hosts,
            items: s.items,
            plugins: s.plugins,
            patches: Vec::new(),
            attachments: Vec::new(),
            host_properties: Vec::new(),
            service_descriptions: s.service_descriptions,
            references: Vec::new(),
            policies: Vec::new(),
            policy_plugins: Vec::new(),
            family_selections: Vec::new(),
            plugin_preferences: Vec::new(),
            server_preferences: Vec::new(),
            scanner: Scanner::default(),
            filters: super::Filters::default(),
        };
        r.set_scanner("Nexpose", None);
        r
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
        scanner_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_csv() {
        let path = std::path::Path::new("tests/fixtures/sample_nexpose.csv");
        let report = parse_file(path).expect("parse simple nexpose");
        assert_eq!(report.hosts.len(), 2);
        assert_eq!(report.items.len(), 3);
        assert_eq!(report.plugins.len(), 2);
    }
}
