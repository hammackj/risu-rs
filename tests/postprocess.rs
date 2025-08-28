use risu_rs::models::{Host, Item, Plugin};
use risu_rs::parser::{Filters, NessusReport};
use risu_rs::postprocess;
use std::collections::HashSet;
use tempfile::tempdir;

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
fn toml_rollups_create_per_host_items() {
    // Build a report with two hosts and items that match the rollup list
    let mut report = NessusReport::default();
    report.hosts = vec![
        Host {
            id: 0,
            nessus_report_id: None,
            name: Some("h1".into()),
            os: None,
            mac: None,
            start: None,
            end: None,
            ip: Some("10.0.0.1".into()),
            fqdn: None,
            netbios: None,
            notes: None,
            risk_score: None,
            user_id: None,
            engagement_id: None,
            scanner_id: None,
        },
        Host {
            id: 1,
            nessus_report_id: None,
            name: Some("h2".into()),
            os: None,
            mac: None,
            start: None,
            end: None,
            ip: Some("10.0.0.2".into()),
            fqdn: None,
            netbios: None,
            notes: None,
            risk_score: None,
            user_id: None,
            engagement_id: None,
            scanner_id: None,
        },
    ];
    // Underlying items using known IDs from repo rollups (7-Zip rollup)
    let mut i1 = Item::default();
    i1.host_id = Some(0);
    i1.plugin_id = Some(91230);
    i1.severity = Some(2);
    let mut i2 = Item::default();
    i2.host_id = Some(1);
    i2.plugin_id = Some(109730);
    i2.severity = Some(3);
    report.items = vec![i1, i2];

    // Run postprocess with TOML rollups
    postprocess::process(
        &mut report,
        &HashSet::new(),
        &HashSet::new(),
        &Filters::default(),
    );

    // Rollup plugin and per-host items inserted (7-Zip rollup id)
    assert!(report.plugins.iter().any(|p| p.plugin_id == Some(-99954)));
    assert!(report
        .items
        .iter()
        .any(|i| i.plugin_id == Some(-99954) && i.host_id == Some(0) && i.severity == Some(2)));
    assert!(report
        .items
        .iter()
        .any(|i| i.plugin_id == Some(-99954) && i.host_id == Some(1) && i.severity == Some(3)));
}

#[test]
fn toml_rollups_enrich_metadata() {
    use chrono::NaiveDate;

    let mut report = NessusReport::default();
    // Plugins providing metadata
    // Use known rollup plugin ids (7-Zip underlying)
    let mut p1 = Plugin::default();
    p1.plugin_id = Some(91230);
    p1.cvss_base_score = Some(5.0);
    p1.vuln_publication_date = Some(
        NaiveDate::from_ymd_opt(2020, 1, 2).unwrap().and_hms_opt(0, 0, 0).unwrap(),
    );
    p1.risk_factor = Some("Medium".into());
    let mut p2 = Plugin::default();
    p2.plugin_id = Some(109730);
    p2.cvss_base_score = Some(7.1);
    p2.vuln_publication_date = Some(
        NaiveDate::from_ymd_opt(2020, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap(),
    );
    p2.risk_factor = Some("High".into());
    p2.exploit_available = Some("true".into());
    report.plugins = vec![p1, p2];

    // One item to trigger rollup
    let mut it = Item::default();
    it.plugin_id = Some(109730);
    it.severity = Some(3);
    report.items.push(it);

    postprocess::process(
        &mut report,
        &HashSet::new(),
        &HashSet::new(),
        &Filters::default(),
    );

    let roll = report
        .plugins
        .iter()
        .find(|p| p.plugin_id == Some(-99954))
        .expect("rollup plugin");
    // Highest CVSS and earliest vuln date picked
    assert_eq!(roll.cvss_base_score, Some(7.1));
    assert_eq!(
        roll.vuln_publication_date,
        Some(NaiveDate::from_ymd_opt(2020, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap())
    );
    // Risk factor chosen by order
    assert_eq!(roll.risk_factor.as_deref(), Some("High"));
    // Exploit flag propagated
    assert_eq!(roll.exploit_available.as_deref(), Some("true"));

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
