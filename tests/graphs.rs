
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel_migrations::MigrationHarness;
use tempfile::tempdir;

use risu_rs::graphs::os_distribution::{os_distribution, OsDistributionGraph};
use risu_rs::graphs::windows_os::WindowsOsGraph;
use risu_rs::graphs::top_vuln::TopVulnGraph;
use risu_rs::graphs::host_severity_counts::HostSeverityCountsGraph;
use risu_rs::graphs::vulns_by_service::VulnsByServiceGraph;
use risu_rs::graphs::vuln_category::VulnCategoryGraph;
use risu_rs::migrate::MIGRATIONS;
use risu_rs::parser::NessusReport;
use risu_rs::schema::{nessus_hosts, nessus_items};
use risu_rs::schema::{nessus_plugins, scanners};

fn setup_db() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    conn.run_pending_migrations(MIGRATIONS).unwrap();
    conn
}

#[test]
fn graph_os_distribution_from_report() {
    let mut report = NessusReport::default();
    report.hosts = vec![
        risu_rs::models::Host {
            id: 0,
            nessus_report_id: None,
            name: None,
            os: Some("Windows 2000".into()),
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
        },
        risu_rs::models::Host {
            id: 1,
            nessus_report_id: None,
            name: None,
            os: Some("Microsoft Windows 2000 Professional".into()),
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
        },
        risu_rs::models::Host {
            id: 2,
            nessus_report_id: None,
            name: None,
            os: Some("Linux".into()),
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
        },
    ];

    let dir = tempdir().unwrap();
    let out = os_distribution(&report, dir.path()).unwrap();
    assert!(out.exists());
}

#[test]
fn graph_os_distribution_db() {
    let mut conn = setup_db();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_hosts)]
    struct NewHost<'a> {
        os: Option<&'a str>,
        scanner_id: Option<i32>,
    }
    diesel::insert_into(nessus_hosts::table)
        .values(&[
            NewHost { os: Some("Windows XP"), scanner_id: None },
            NewHost { os: Some("Microsoft Windows XP"), scanner_id: None },
            NewHost { os: Some("Linux"), scanner_id: None },
        ])
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    let out = OsDistributionGraph::generate(&mut conn, dir.path(), None).unwrap();
    assert!(out.exists());
}

#[test]
fn graph_os_distribution_db_scanner_filter() {
    let mut conn = setup_db();
    // Create scanners with ids 1 and 2 for FK consistency
    #[derive(Insertable)]
    #[diesel(table_name = scanners)]
    struct NewScanner<'a> { id: i32, scanner_type: &'a str, scanner_version: Option<&'a str> }
    diesel::insert_into(scanners::table)
        .values(&[
            NewScanner { id: 1, scanner_type: "Nessus", scanner_version: Some("1") },
            NewScanner { id: 2, scanner_type: "Nessus", scanner_version: Some("1") },
        ])
        .execute(&mut conn)
        .unwrap();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_hosts)]
    struct NewHost<'a> { os: Option<&'a str>, scanner_id: Option<i32> }
    diesel::insert_into(nessus_hosts::table)
        .values(&[
            NewHost { os: Some("Linux"), scanner_id: Some(1) },
            NewHost { os: Some("Linux"), scanner_id: Some(2) },
        ])
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    let out = OsDistributionGraph::generate(&mut conn, dir.path(), Some(1)).unwrap();
    assert!(out.exists());
    let out2 = OsDistributionGraph::generate(&mut conn, dir.path(), Some(2)).unwrap();
    assert!(out2.exists());
}

#[test]
fn graph_windows_os_generate() {
    let mut conn = setup_db();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_hosts)]
    struct NewHost<'a> { os: Option<&'a str> }
    diesel::insert_into(nessus_hosts::table)
        .values(&[
            NewHost { os: Some("Windows 2000") },
            NewHost { os: Some("Microsoft Windows 2000 Professional") },
            NewHost { os: Some("Windows XP") },
        ])
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    let out = WindowsOsGraph::generate(&mut conn, dir.path()).unwrap();
    assert!(out.exists());
}

#[test]
fn graph_top_vuln_generate() {
    let mut conn = setup_db();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_items)]
    struct NewItem<'a> {
        plugin_name: Option<&'a str>,
        rollup_finding: Option<bool>,
        scanner_id: Option<i32>,
    }
    diesel::insert_into(nessus_items::table)
        .values(&[
            NewItem { plugin_name: Some("OpenSSH"), rollup_finding: None, scanner_id: None },
            NewItem { plugin_name: Some("OpenSSH"), rollup_finding: Some(false), scanner_id: None },
            NewItem { plugin_name: Some("Apache"), rollup_finding: None, scanner_id: None },
        ])
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    let out = TopVulnGraph::generate(&mut conn, dir.path(), 10, None).unwrap();
    assert!(out.exists());
}

#[test]
fn graph_top_vuln_limit_and_scanner_filter() {
    let mut conn = setup_db();
    // Create scanners for ids used below
    #[derive(Insertable)]
    #[diesel(table_name = scanners)]
    struct NewScanner<'a> { id: i32, scanner_type: &'a str, scanner_version: Option<&'a str> }
    diesel::insert_into(scanners::table)
        .values(&[
            NewScanner { id: 1, scanner_type: "Nessus", scanner_version: Some("1") },
            NewScanner { id: 2, scanner_type: "Nessus", scanner_version: Some("1") },
        ])
        .execute(&mut conn)
        .unwrap();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_items)]
    struct NewItem<'a> { plugin_name: Option<&'a str>, rollup_finding: Option<bool>, scanner_id: Option<i32> }
    let rows = vec![
        NewItem { plugin_name: Some("A"), rollup_finding: None, scanner_id: Some(1) },
        NewItem { plugin_name: Some("A"), rollup_finding: None, scanner_id: Some(1) },
        NewItem { plugin_name: Some("B"), rollup_finding: None, scanner_id: Some(1) },
        NewItem { plugin_name: Some("C"), rollup_finding: None, scanner_id: Some(2) },
    ];
    diesel::insert_into(nessus_items::table)
        .values(&rows)
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    // Should succeed with scanner 1 and respect limit
    let out = TopVulnGraph::generate(&mut conn, dir.path(), 1, Some(1)).unwrap();
    assert!(out.exists());
}

#[test]
fn graph_host_severity_counts_generate() {
    let mut conn = setup_db();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_items)]
    struct NewItem {
        host_id: Option<i32>,
        severity: Option<i32>,
        rollup_finding: Option<bool>,
        scanner_id: Option<i32>,
    }
    // Insert corresponding hosts to satisfy FK constraints
    // Insert placeholder hosts to satisfy FK constraints
    diesel::insert_into(nessus_hosts::table)
        .values(&vec![
            (nessus_hosts::name.eq(Some("h1".to_string()))),
            (nessus_hosts::name.eq(Some("h2".to_string()))),
            (nessus_hosts::name.eq(Some("h3".to_string()))),
        ])
        .execute(&mut conn)
        .unwrap();

    diesel::insert_into(nessus_items::table)
        .values(&[
            NewItem { host_id: Some(1), severity: Some(3), rollup_finding: None, scanner_id: None },
            NewItem { host_id: Some(1), severity: Some(4), rollup_finding: None, scanner_id: None },
            NewItem { host_id: Some(2), severity: Some(2), rollup_finding: None, scanner_id: None },
            NewItem { host_id: Some(3), severity: Some(0), rollup_finding: None, scanner_id: None },
        ])
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    let out = HostSeverityCountsGraph::generate(&mut conn, dir.path(), None).unwrap();
    assert!(out.exists());
}

#[test]
fn graph_vulns_by_service_generate() {
    let mut conn = setup_db();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_items)]
    struct NewItem<'a> {
        svc_name: Option<&'a str>,
        rollup_finding: Option<bool>,
        scanner_id: Option<i32>,
    }
    diesel::insert_into(nessus_items::table)
        .values(&[
            NewItem { svc_name: Some("http"), rollup_finding: None, scanner_id: None },
            NewItem { svc_name: Some("ssh"), rollup_finding: None, scanner_id: None },
            NewItem { svc_name: Some("http"), rollup_finding: None, scanner_id: None },
        ])
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    let out = VulnsByServiceGraph::generate(&mut conn, dir.path(), 10, None).unwrap();
    let meta = std::fs::metadata(&out).unwrap();
    assert!(meta.len() > 0);
}

#[test]
fn graph_vulns_by_service_limit_and_empty() {
    let mut conn = setup_db();
    // Create scanner id 1 for FK
    #[derive(Insertable)]
    #[diesel(table_name = scanners)]
    struct NewScanner<'a> { id: i32, scanner_type: &'a str, scanner_version: Option<&'a str> }
    diesel::insert_into(scanners::table)
        .values(&[NewScanner { id: 1, scanner_type: "Nessus", scanner_version: Some("1") }])
        .execute(&mut conn)
        .unwrap();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_items)]
    struct NewItem<'a> { svc_name: Option<&'a str>, rollup_finding: Option<bool>, scanner_id: Option<i32> }
    diesel::insert_into(nessus_items::table)
        .values(&[
            NewItem { svc_name: Some("http"), rollup_finding: None, scanner_id: Some(1) },
            NewItem { svc_name: Some("ssh"), rollup_finding: None, scanner_id: Some(1) },
        ])
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    let out = VulnsByServiceGraph::generate(&mut conn, dir.path(), 1, Some(1)).unwrap();
    assert!(out.exists());
}

#[test]
fn graph_vuln_category_generate() {
    let mut conn = setup_db();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_plugins)]
    struct NewPlugin<'a> {
        plugin_id: Option<i32>,
        family_name: Option<&'a str>,
    }
    #[derive(Insertable)]
    #[diesel(table_name = nessus_items)]
    struct NewItem {
        plugin_id: Option<i32>,
        rollup_finding: Option<bool>,
        scanner_id: Option<i32>,
    }
    diesel::insert_into(risu_rs::schema::nessus_plugins::table)
        .values(&[
            NewPlugin { plugin_id: Some(1), family_name: Some("General") },
            NewPlugin { plugin_id: Some(2), family_name: Some("Web Servers") },
        ])
        .execute(&mut conn)
        .unwrap();
    diesel::insert_into(nessus_items::table)
        .values(&[
            NewItem { plugin_id: Some(1), rollup_finding: None, scanner_id: None },
            NewItem { plugin_id: Some(1), rollup_finding: None, scanner_id: None },
            NewItem { plugin_id: Some(2), rollup_finding: None, scanner_id: None },
        ])
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    let out = VulnCategoryGraph::generate(&mut conn, dir.path(), 10, None).unwrap();
    let meta = std::fs::metadata(&out).unwrap();
    assert!(meta.len() > 0);
}

#[test]
fn graph_vuln_category_scanner_and_empty() {
    let mut conn = setup_db();
    // Create scanner id 1 for FK
    #[derive(Insertable)]
    #[diesel(table_name = scanners)]
    struct NewScanner<'a> { id: i32, scanner_type: &'a str, scanner_version: Option<&'a str> }
    diesel::insert_into(scanners::table)
        .values(&[NewScanner { id: 1, scanner_type: "Nessus", scanner_version: Some("1") }])
        .execute(&mut conn)
        .unwrap();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_plugins)]
    struct NewPluginRow<'a> { id: Option<i32>, plugin_id: Option<i32>, family_name: Option<&'a str> }
    #[derive(Insertable)]
    #[diesel(table_name = nessus_items)]
    struct NewItem { plugin_id: Option<i32>, rollup_finding: Option<bool>, scanner_id: Option<i32> }
    diesel::insert_into(risu_rs::schema::nessus_plugins::table)
        .values(&[
            NewPluginRow { id: Some(10), plugin_id: Some(10), family_name: Some("General") },
        ])
        .execute(&mut conn)
        .unwrap();
    diesel::insert_into(nessus_items::table)
        .values(&[
            NewItem { plugin_id: Some(10), rollup_finding: None, scanner_id: Some(1) },
        ])
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    let out = VulnCategoryGraph::generate(&mut conn, dir.path(), 10, Some(1)).unwrap();
    assert!(out.exists());
}

#[test]
fn graph_os_distribution_report_empty_err() {
    let report = NessusReport::default();
    let dir = tempdir().unwrap();
    assert!(os_distribution(&report, dir.path()).is_err());
}

#[test]
fn graph_top_vuln_truncates_labels() {
    let mut conn = setup_db();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_items)]
    struct NewItem<'a> { plugin_name: Option<&'a str>, rollup_finding: Option<bool>, scanner_id: Option<i32> }
    // One long label (>10 chars) to exercise truncation branch
    diesel::insert_into(nessus_items::table)
        .values(&[
            NewItem { plugin_name: Some("averyverylonglabel"), rollup_finding: None, scanner_id: None },
            NewItem { plugin_name: Some("short"), rollup_finding: None, scanner_id: None },
        ])
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    let out = TopVulnGraph::generate(&mut conn, dir.path(), 10, None).unwrap();
    assert!(out.exists());
}

#[test]
fn graph_vulns_by_service_truncates_labels() {
    let mut conn = setup_db();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_items)]
    struct NewItem<'a> { svc_name: Option<&'a str>, rollup_finding: Option<bool>, scanner_id: Option<i32> }
    diesel::insert_into(nessus_items::table)
        .values(&[
            NewItem { svc_name: Some("averyverylongsvc"), rollup_finding: None, scanner_id: None },
            NewItem { svc_name: Some("http"), rollup_finding: None, scanner_id: None },
        ])
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    let out = VulnsByServiceGraph::generate(&mut conn, dir.path(), 10, None).unwrap();
    assert!(out.exists());
}

#[test]
fn graph_vuln_category_truncates_labels() {
    let mut conn = setup_db();
    #[derive(Insertable)]
    #[diesel(table_name = nessus_plugins)]
    struct NewPluginRow<'a> { id: Option<i32>, plugin_id: Option<i32>, family_name: Option<&'a str> }
    #[derive(Insertable)]
    #[diesel(table_name = nessus_items)]
    struct NewItem { plugin_id: Option<i32>, rollup_finding: Option<bool>, scanner_id: Option<i32> }
    diesel::insert_into(risu_rs::schema::nessus_plugins::table)
        .values(&[
            NewPluginRow { id: Some(20), plugin_id: Some(20), family_name: Some("averyverylongfamily") },
        ])
        .execute(&mut conn)
        .unwrap();
    diesel::insert_into(nessus_items::table)
        .values(&[
            NewItem { plugin_id: Some(20), rollup_finding: None, scanner_id: None },
        ])
        .execute(&mut conn)
        .unwrap();
    let dir = tempdir().unwrap();
    let out = VulnCategoryGraph::generate(&mut conn, dir.path(), 10, None).unwrap();
    assert!(out.exists());
}

#[test]
fn graph_host_severity_counts_empty_err() {
    let mut conn = setup_db();
    let dir = tempdir().unwrap();
    assert!(HostSeverityCountsGraph::generate(&mut conn, dir.path(), None).is_err());
}
