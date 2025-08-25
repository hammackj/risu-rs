use std::fs;
use std::io::{Result as IoResult, Write};
use std::sync::{Arc, Mutex};

use risu_rs::parser::parse_file;
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
    assert!(logs.contains("Unknown XML tags encountered"));
    assert!(logs.contains("unknown-prop"));
}
