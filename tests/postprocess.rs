use risu_rs::models::{Host, Item, Plugin};
use risu_rs::parser::{Filters, NessusReport};
use risu_rs::postprocess;
use std::collections::HashSet;

fn host(name: &str, ip: Option<&str>) -> Host {
    Host {
        id: 0,
        nessus_report_id: None,
        name: Some(name.to_string()),
        os: None,
        mac: None,
        start: None,
        end: None,
        ip: ip.map(|s| s.to_string()),
        fqdn: None,
        netbios: None,
        notes: None,
        risk_score: None,
        user_id: None,
        engagement_id: None,
        scanner_id: None,
    }
}

#[test]
fn fix_ips_sets_missing_ip() {
    let mut report = NessusReport {
        hosts: vec![host("10.0.0.1", None)],
        ..NessusReport::default()
    };
    postprocess::process(&mut report, &HashSet::new(), &HashSet::new(), &Filters::default());
    assert_eq!(report.hosts[0].ip.as_deref(), Some("10.0.0.1"));
}

#[test]
fn sort_hosts_orders_by_ip() {
    let mut report = NessusReport {
        hosts: vec![
            host("host2", Some("10.0.0.2")),
            host("host1", Some("10.0.0.1")),
        ],
        ..NessusReport::default()
    };
    postprocess::process(&mut report, &HashSet::new(), &HashSet::new(), &Filters::default());
    assert_eq!(report.hosts[0].ip.as_deref(), Some("10.0.0.1"));
    assert_eq!(report.hosts[1].ip.as_deref(), Some("10.0.0.2"));
}

#[test]
fn normalize_plugin_names_sanitizes_strings() {
    let mut plugin = Plugin::default();
    plugin.plugin_name = Some("Example (POODLE)".to_string());
    let mut report = NessusReport {
        plugins: vec![plugin],
        ..NessusReport::default()
    };
    postprocess::process(&mut report, &HashSet::new(), &HashSet::new(), &Filters::default());
    assert_eq!(report.plugins[0].plugin_name.as_deref(), Some("Example"));
}

#[test]
fn root_cause_sets_known_plugins() {
    let mut plugin = Plugin::default();
    plugin.plugin_id = Some(22194);
    let mut report = NessusReport {
        plugins: vec![plugin],
        ..NessusReport::default()
    };
    postprocess::process(&mut report, &HashSet::new(), &HashSet::new(), &Filters::default());
    assert_eq!(
        report.plugins[0].root_cause.as_deref(),
        Some("Vendor Patch")
    );
}

#[test]
fn risk_score_computes_scores() {
    let host = host("host", Some("10.0.0.1"));
    let mut plugin = Plugin::default();
    plugin.plugin_id = Some(1);
    plugin.cvss_base_score = Some(5.0);
    let mut item = Item::default();
    item.plugin_id = Some(1);
    let mut report = NessusReport {
        hosts: vec![host],
        plugins: vec![plugin],
        items: vec![item],
        ..NessusReport::default()
    };
    postprocess::process(&mut report, &HashSet::new(), &HashSet::new(), &Filters::default());
    assert_eq!(report.items[0].risk_score, Some(4));
    assert_eq!(report.plugins[0].risk_score, Some(4));
    assert_eq!(report.hosts[0].risk_score, Some(4));
}

#[test]
fn downgrade_plugins_adjusts_severity() {
    let mut item1 = Item::default();
    item1.plugin_id = Some(41028);
    item1.severity = Some(3);
    let mut item2 = Item::default();
    item2.plugin_id = Some(20007);
    item2.severity = Some(4);
    let mut report = NessusReport {
        items: vec![item1, item2],
        ..NessusReport::default()
    };
    postprocess::process(&mut report, &HashSet::new(), &HashSet::new(), &Filters::default());
    assert_eq!(report.items[0].severity, Some(0));
    assert_eq!(report.items[1].severity, Some(2));
}
#[test]
fn adobe_air_rollup_creates_summary_item() {
    let mut item = Item::default();
    item.plugin_id = Some(56959);
    item.severity = Some(2);
    let mut report = NessusReport {
        items: vec![item],
        ..NessusReport::default()
    };
    postprocess::process(&mut report, &HashSet::new(), &HashSet::new(), &Filters::default());
    // original item downgraded
    let orig = report.items.iter().find(|i| i.plugin_id == Some(56959)).unwrap();
    assert_eq!(orig.severity, Some(-1));
    assert_eq!(orig.real_severity, Some(2));
    // rollup plugin and item inserted
    assert!(report.plugins.iter().any(|p| p.plugin_id == Some(-99994)));
    assert!(report.items.iter().any(|i| i.plugin_id == Some(-99994) && i.severity == Some(2)));
}
#[test]
fn php_rollup_creates_summary_item() {
    let mut item = Item::default();
    item.plugin_id = Some(76281);
    item.severity = Some(3);
    let mut report = NessusReport {
        items: vec![item],
        ..NessusReport::default()
    };
    postprocess::process(&mut report, &HashSet::new(), &HashSet::new(), &Filters::default());
    // original item downgraded
    let orig = report.items.iter().find(|i| i.plugin_id == Some(76281)).unwrap();
    assert_eq!(orig.severity, Some(-1));
    assert_eq!(orig.real_severity, Some(3));
    // rollup plugin and item inserted
    assert!(report.plugins.iter().any(|p| p.plugin_id == Some(-99988)));
    assert!(
        report
            .items
            .iter()
            .any(|i| i.plugin_id == Some(-99988) && i.severity == Some(3))
    );
}

#[test]
fn cisco_ios_rollup_creates_summary_item() {
    let mut item = Item::default();
    item.plugin_id = Some(58568);
    item.severity = Some(3);
    let mut report = NessusReport {
        items: vec![item],
        ..NessusReport::default()
    };
    postprocess::process(&mut report, &HashSet::new(), &HashSet::new(), &Filters::default());
    // original item downgraded
    let orig = report.items.iter().find(|i| i.plugin_id == Some(58568)).unwrap();
    assert_eq!(orig.severity, Some(-1));
    assert_eq!(orig.real_severity, Some(3));
    // rollup plugin and item inserted
    assert!(report.plugins.iter().any(|p| p.plugin_id == Some(-99965)));
    assert!(
        report
            .items
            .iter()
            .any(|i| i.plugin_id == Some(-99965) && i.severity == Some(3))
    );
}

#[test]
fn vmware_vcenter_rollup_creates_summary_item() {
    let mut item = Item::default();
    item.plugin_id = Some(79865);
    item.severity = Some(4);
    let mut report = NessusReport {
        items: vec![item],
        ..NessusReport::default()
    };
    postprocess::process(&mut report, &HashSet::new(), &HashSet::new(), &Filters::default());
    // original item downgraded
    let orig = report.items.iter().find(|i| i.plugin_id == Some(79865)).unwrap();
    assert_eq!(orig.severity, Some(-1));
    assert_eq!(orig.real_severity, Some(4));
    // rollup plugin and item inserted
    assert!(report.plugins.iter().any(|p| p.plugin_id == Some(-99979)));
    assert!(
        report
            .items
            .iter()
            .any(|i| i.plugin_id == Some(-99979) && i.severity == Some(4))
    );
}

