use std::fs;
use std::io::{Result as IoResult, Write};
use std::sync::{Arc, Mutex};

use risu_rs::parser::parse_file;
use tempfile::tempdir;
use tracing::Level;
use tracing_subscriber::fmt;

struct VecWriter(Arc<Mutex<Vec<u8>>>);

impl Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

#[test]
fn parses_cm_prefixed_tags() {
    let sample = fs::canonicalize("tests/fixtures/cm_tags.nessus").unwrap();
    let report = parse_file(&sample).unwrap();

    let item = report.items.first().expect("item");
    assert_eq!(item.cm_compliance_info.as_deref(), Some("info"));
    assert_eq!(item.cm_compliance_result.as_deref(), Some("Failed"));

    let plugin = report
        .plugins
        .iter()
        .find(|p| p.plugin_id == Some(1))
        .unwrap();
    assert_eq!(plugin.root_cause.as_deref(), Some("rc"));
    assert_eq!(plugin.agent.as_deref(), Some("nessus"));
    assert_eq!(plugin.potential_vulnerability, Some(true));
    assert_eq!(plugin.default_account, Some(false));
}

#[test]
fn parses_traceroute_pcidss_and_logs_unknown() {
    let sample = fs::canonicalize("tests/fixtures/sample.nessus").unwrap();

    let buf = Arc::new(Mutex::new(Vec::new()));
    let make_writer = {
        let buf = buf.clone();
        move || VecWriter(buf.clone())
    };
    let subscriber = fmt()
        .with_max_level(Level::DEBUG)
        .with_writer(make_writer)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let report = parse_file(&sample).unwrap();

    let props: Vec<(String, String)> = report
        .host_properties
        .iter()
        .filter_map(|p| {
            if let (Some(n), Some(v)) = (p.name.clone(), p.value.clone()) {
                Some((n, v))
            } else {
                None
            }
        })
        .collect();

    assert!(props.iter().any(|(n, _)| n == "traceroute_hop_0"));
    assert!(props.iter().any(|(n, _)| n == "pcidss:status"));

    let logs = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("Unknown XML elements encountered"));
    assert!(logs.contains("Unknown host properties encountered"));
    assert!(logs.contains("unknown-tag"));
    assert!(logs.contains("unknown-prop"));
}

#[test]
fn parses_attachments_and_references() {
    let xml = fs::read("tests/fixtures/attachment_ref.nessus").unwrap();
    let dir = tempdir().unwrap();
    let path = dir.path().join("attachment_ref.nessus");
    fs::write(&path, xml).unwrap();

    let report = parse_file(&path).unwrap();
    assert_eq!(report.attachments.len(), 1);
    assert_eq!(report.attachments[0].name.as_deref(), Some("a.txt"));
    assert_eq!(
        report.attachments[0].ahash.as_deref(),
        Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    );
    assert_eq!(report.attachments[0].value.as_deref(), Some("aGVsbG8="));
    assert_eq!(report.items[0].attachment_id, Some(0));
    let saved = dir.path().join("a.txt");
    assert!(saved.exists());
    let data = fs::read(saved).unwrap();
    assert_eq!(data, b"hello");

    let refs: Vec<(Option<String>, Option<String>)> = report
        .references
        .iter()
        .map(|r| (r.source.clone(), r.value.clone()))
        .collect();
    assert!(refs.contains(&(Some("CVE".to_string()), Some("CVE-1234-5678".to_string()),)));
    assert!(refs.contains(&(Some("CVE".to_string()), Some("CVE-1111-2222".to_string()),)));
}

#[test]
fn parses_plugin_metadata_fields() {
    let path = fs::canonicalize("tests/fixtures/plugin_metadata.nessus").unwrap();
    let report = parse_file(&path).unwrap();

    let item = report.items.first().unwrap();
    assert_eq!(item.description.as_deref(), Some("desc"));
    assert_eq!(item.solution.as_deref(), Some("sol"));
    assert_eq!(item.risk_factor.as_deref(), Some("Medium"));

    let plugin = report
        .plugins
        .iter()
        .find(|p| p.plugin_id == Some(1))
        .unwrap();
    assert_eq!(plugin.description.as_deref(), Some("desc"));
    assert_eq!(plugin.solution.as_deref(), Some("sol"));
    assert_eq!(plugin.risk_factor.as_deref(), Some("Medium"));
}

#[test]
fn maps_pluginid_zero_to_one() {
    let path = fs::canonicalize("tests/fixtures/plugin_id0.nessus").unwrap();
    let report = parse_file(&path).unwrap();

    let item = report.items.first().unwrap();
    assert_eq!(item.plugin_id, Some(1));

    assert!(report.plugins.iter().any(|p| p.plugin_id == Some(1)));
}

#[test]
fn parses_policy_block() {
    let path = fs::canonicalize("tests/fixtures/policy.nessus").unwrap();
    let report = parse_file(&path).unwrap();

    assert_eq!(report.policies.len(), 1);
    let policy = &report.policies[0];
    assert_eq!(policy.name.as_deref(), Some("basic"));
    assert_eq!(policy.comments.as_deref(), Some("hello"));

    assert_eq!(report.policy_plugins.len(), 1);
    let plg = &report.policy_plugins[0];
    assert_eq!(plg.plugin_id, Some(1));
    assert_eq!(plg.plugin_name.as_deref(), Some("plug"));
    assert_eq!(plg.family_name.as_deref(), Some("General"));
    assert_eq!(plg.status.as_deref(), Some("enabled"));

    assert_eq!(report.family_selections.len(), 1);
    assert_eq!(
        report.family_selections[0].family_name.as_deref(),
        Some("General")
    );

    assert_eq!(report.plugin_preferences.len(), 1);
    let pref = &report.plugin_preferences[0];
    assert_eq!(pref.plugin_id, Some(1));
    assert_eq!(pref.fullname.as_deref(), Some("Name"));
    assert_eq!(pref.preference_name.as_deref(), Some("pref"));
    assert_eq!(pref.preference_type.as_deref(), Some("type"));
    assert_eq!(pref.selected_value.as_deref(), Some("value"));

    assert_eq!(report.server_preferences.len(), 1);
    let sp = &report.server_preferences[0];
    assert_eq!(sp.name.as_deref(), Some("somepref"));
    assert_eq!(sp.value.as_deref(), Some("val"));
}

#[test]
fn recognizes_host_property_patterns() {
    let xml = r#"<NessusClientData_v2><ReportHost name='h'><HostProperties>
<tag name='cpe-0'>cpe:/a:vendor:prod:1.0</tag>
<tag name='KB12345'>Patch KB</tag>
<tag name='patch-summary-cves'>1</tag>
<tag name='mcafee-epo-guid'>abc</tag>
</HostProperties><ReportItem pluginID='1' severity='0' pluginName='plug'><msft>MS13-001</msft></ReportItem></ReportHost></NessusClientData_v2>"#;
    let dir = tempdir().unwrap();
    let path = dir.path().join("hostprops.nessus");
    fs::write(&path, xml).unwrap();

    let buf = Arc::new(Mutex::new(Vec::new()));
    let make_writer = { let buf = buf.clone(); move || VecWriter(buf.clone()) };
    let subscriber = fmt()
        .with_max_level(Level::DEBUG)
        .with_writer(make_writer)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let report = parse_file(&path).unwrap();

    let names: Vec<String> = report
        .host_properties
        .iter()
        .filter_map(|p| p.name.clone())
        .collect();
    assert!(names.contains(&"cpe-0".to_string()));
    assert!(names.contains(&"KB12345".to_string()));
    assert!(names.contains(&"patch-summary-cves".to_string()));
    assert!(names.contains(&"mcafee-epo-guid".to_string()));

    assert!(report.references.iter().any(|r| r.source.as_deref() == Some("MSFT")
        && r.value.as_deref() == Some("MS13-001")));

    let logs = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert!(
        !logs.contains("Unknown host properties encountered"),
        "logs: {}",
        logs
    );
    assert!(!logs.contains("Unknown XML elements encountered"));
}
