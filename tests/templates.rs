use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn run_template(name: &str, expected: &str) {
    let tmp = tempdir().unwrap();
    let sample = fs::canonicalize("tests/fixtures/sample.nessus").unwrap();

    Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "--create-config-file"])
        .current_dir(&tmp)
        .assert()
        .success();

    let output = tmp.path().join("out.csv");
    Command::cargo_bin("risu-rs")
        .unwrap()
        .current_dir(&tmp)
        .args([
            "--no-banner",
            "--config-file",
            "config.yml",
            "parse",
            sample.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-t",
            name,
            "--renderer",
            "csv",
        ])
        .assert()
        .success();

    let contents = fs::read_to_string(output).unwrap();
    assert!(contents.contains(expected));
}

fn run_template_fixture(name: &str, fixture: &str, expected: &str) {
    let tmp = tempdir().unwrap();
    let sample = fs::canonicalize(fixture).unwrap();

    Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "--create-config-file"])
        .current_dir(&tmp)
        .assert()
        .success();

    let output = tmp.path().join("out.csv");
    Command::cargo_bin("risu-rs")
        .unwrap()
        .current_dir(&tmp)
        .args([
            "--no-banner",
            "--config-file",
            "config.yml",
            "parse",
            sample.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-t",
            name,
            "--renderer",
            "csv",
        ])
        .assert()
        .success();

    let contents = fs::read_to_string(output).unwrap();
    assert!(contents.contains(expected));
}

fn render_template_capture(name: &str) -> String {
    let tmp = tempdir().unwrap();
    let sample = fs::canonicalize("tests/fixtures/sample.nessus").unwrap();

    Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "--create-config-file"])
        .current_dir(&tmp)
        .assert()
        .success();

    let output = tmp.path().join("out.csv");
    Command::cargo_bin("risu-rs")
        .unwrap()
        .current_dir(&tmp)
        .args([
            "--no-banner",
            "--config-file",
            "config.yml",
            "parse",
            sample.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-t",
            name,
            "--renderer",
            "csv",
        ])
        .assert()
        .success();

    fs::read_to_string(output).unwrap()
}

fn render_template_capture_raw(name: &str) -> String {
    let csv_data = render_template_capture(name);
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(csv_data.as_bytes());
    let mut lines = Vec::new();
    for rec in rdr.records() {
        let rec = rec.unwrap();
        if let Some(cell) = rec.get(0) {
            lines.push(cell.to_string());
        }
    }
    lines.join("\n")
}

fn render_template_capture_raw_fixture(name: &str, fixture: &str) -> String {
    let tmp = tempdir().unwrap();
    let sample = fs::canonicalize(fixture).unwrap();

    Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "--create-config-file"])
        .current_dir(&tmp)
        .assert()
        .success();

    let output = tmp.path().join("out.csv");
    Command::cargo_bin("risu-rs")
        .unwrap()
        .current_dir(&tmp)
        .args([
            "--no-banner",
            "--config-file",
            "config.yml",
            "parse",
            sample.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-t",
            name,
            "--renderer",
            "csv",
        ])
        .assert()
        .success();

    let csv_data = fs::read_to_string(output).unwrap();
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(csv_data.as_bytes());
    let mut lines = Vec::new();
    for rec in rdr.records() {
        let rec = rec.unwrap();
        if let Some(cell) = rec.get(0) {
            lines.push(cell.to_string());
        }
    }
    lines.join("\n")
}

#[test]
fn sans_top_template_orders_and_limits() {
    let tmp = tempdir().unwrap();
    let sample = fs::canonicalize("tests/fixtures/sans_top.nessus").unwrap();

    Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "--create-config-file"])
        .current_dir(&tmp)
        .assert()
        .success();

    let output = tmp.path().join("out.csv");
    Command::cargo_bin("risu-rs")
        .unwrap()
        .current_dir(&tmp)
        .args([
            "--no-banner",
            "--config-file",
            "config.yml",
            "parse",
            sample.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-t",
            "sans_top",
            "--renderer",
            "csv",
            "--template-arg",
            "top=2",
        ])
        .assert()
        .success();

    let contents = fs::read_to_string(output).unwrap();
    assert!(contents.contains("PluginB (2): 3"));
    assert!(contents.contains("PluginA (1): 2"));
    assert!(!contents.contains("PluginC"));
    let idx_b = contents.find("PluginB").unwrap();
    let idx_a = contents.find("PluginA").unwrap();
    assert!(idx_b < idx_a);
}

#[test]
fn notable_template_renders() {
    run_template("notable", "Notable Findings");
}

#[test]
fn notable_template_includes_high_severity_findings() {
    run_template_fixture(
        "notable",
        "tests/fixtures/notable_high.nessus",
        "Critical Plugin",
    );
}

#[test]
fn ms_update_summary_template_renders() {
    run_template("ms_update_summary", "Missing Microsoft Updates");
}

#[test]
fn graphs_template_renders() {
    run_template("graphs", "OS distribution");
}

#[test]
fn graphs_template_creates_and_embeds_graphs() {
    let work_dir = tempdir().unwrap();
    let graph_dir = tempdir().unwrap();
    let sample = fs::canonicalize("tests/fixtures/sample.nessus").unwrap();

    Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "--create-config-file"])
        .current_dir(&work_dir)
        .assert()
        .success();

    let output = work_dir.path().join("out.csv");
    Command::cargo_bin("risu-rs")
        .unwrap()
        .current_dir(&work_dir)
        .env("TMPDIR", graph_dir.path())
        .args([
            "--no-banner",
            "--config-file",
            "config.yml",
            "parse",
            sample.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-t",
            "graphs",
            "--renderer",
            "csv",
        ])
        .assert()
        .success();

    assert!(graph_dir.path().join("os_distribution.png").exists());
    assert!(graph_dir.path().join("top_vulnerabilities.png").exists());

    let contents = fs::read_to_string(output).unwrap();
    assert_eq!(contents.matches("data:image/png;base64").count(), 2);
}

#[test]
fn authentication_summary_reports_counts() {
    let output = render_template_capture_raw("authentication_summary");
    assert!(output.contains("Authenticated hosts: 0"));
    assert!(output.contains("Unauthenticated hosts: 0"));
}

#[test]
fn remote_local_summary_reports_counts() {
    let output = render_template_capture_raw_fixture(
        "remote_local_summary",
        "tests/fixtures/remote_local.nessus",
    );
    assert!(output.contains("Remote findings: 2"));
    assert!(output.contains("Local findings: 1"));
}

#[test]
fn top_25_template_lists_plugins() {
    let output = render_template_capture_raw("top_25");
    assert!(output.contains("Top Plugins"));
    assert!(output.contains("Test Plugin (100): 1"));
}

#[test]
fn pci_compliance_template_renders() {
    run_template("pci_compliance", "PCI / DSS Compliance Overview");
}

#[test]
fn ssl_summary_template_renders() {
    run_template_fixture(
        "ssl_summary",
        "tests/fixtures/ssl.nessus",
        "Total SSL findings: 2",
    );
}

#[test]
fn host_summary_template_renders() {
    let contents = render_template_capture("host_summary");
    assert!(contents.contains("Total Hosts: 1"));
    assert!(contents.contains("No network shares found."));
    assert!(contents.contains("Info: 1"));
}

#[test]
fn exec_summary_template_includes_risk_score() {
    let rust_out = render_template_capture_raw("exec_summary");
    assert!(rust_out.contains("Risk Score:"));
    assert!(rust_out.contains("Risk scores derived from weighted averages of finding severities",));
}

#[test]
fn finding_statistics_template_renders() {
    run_template_fixture(
        "finding_statistics",
        "tests/fixtures/notable_high.nessus",
        "High Risks: 1",
    );
}

#[test]
fn notable_detailed_template_renders() {
    run_template_fixture(
        "notable_detailed",
        "tests/fixtures/notable_high.nessus",
        "Critical Plugin",
    );
}

#[test]
fn host_findings_csv_template_renders() {
    run_template_fixture(
        "host_findings_csv",
        "tests/fixtures/notable_high.nessus",
        "Critical Plugin",
    );
}

#[test]
fn host_findings_csv_older_than_template_renders() {
    let tmp = tempdir().unwrap();
    let sample = fs::canonicalize("tests/fixtures/notable_high.nessus").unwrap();

    Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "--create-config-file"])
        .current_dir(&tmp)
        .assert()
        .success();

    let output = tmp.path().join("out.csv");
    Command::cargo_bin("risu-rs")
        .unwrap()
        .current_dir(&tmp)
        .args([
            "--no-banner",
            "--config-file",
            "config.yml",
            "parse",
            sample.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-t",
            "host_findings_csv_older_than",
            "--renderer",
            "csv",
            "--older-than",
            "0",
        ])
        .assert()
        .success();

    let contents = fs::read_to_string(output).unwrap();
    assert!(contents.contains("Critical Plugin"));
}

#[test]
fn assets_template_renders_host_details() {
    let contents = render_template_capture("assets");
    assert!(contents.contains("Name: 192.168.0.1"));
    assert!(contents.contains("FQDN: example.local"));
    assert!(contents.contains("IP: 192.168.0.1"));
    assert!(contents.contains("NetBIOS: EXAMPLE"));
    assert!(contents.contains("MAC: 00:11:22:33:44:55"));
    assert!(contents.contains("OS: Linux"));
}

#[test]
fn findings_host_template_renders() {
    run_template("findings_host", "Findings Summary by Host Report");
}

#[test]
fn findings_summary_template_renders() {
    run_template("findings_summary", "Findings Summary Report");
}

#[test]
fn findings_summary_with_pluginid_template_renders() {
    run_template("findings_summary_with_pluginid", "Findings Summary Report");
}

#[test]
fn malicious_process_detection_template_renders() {
    run_template(
        "malicious_process_detection",
        "Malicious Process Detection Findings",
    );
}

#[test]
fn missing_root_causes_template_renders() {
    run_template("missing_root_causes", "Missing Root Causes Report");
}

#[test]
fn ms_wsus_findings_template_renders() {
    run_template("ms_wsus_findings", "Patch Management: WSUS Report");
}

#[test]
fn service_inventory_template_lists_services() {
    run_template_fixture(
        "service_inventory",
        "tests/fixtures/service_inventory.nessus",
        "ssh,22,SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8",
    );
}

#[test]
fn unsupported_os_template_lists_hosts() {
    let out = render_template_capture_raw_fixture(
        "unsupported_os",
        "tests/fixtures/unsupported_os.nessus",
    );
    assert!(out.contains("winhost"));
    assert!(out.contains("linuxhost"));
}

#[test]
fn microsoft_windows_unquoted_service_path_enumeration_template_lists_hosts() {
    run_template_fixture(
        "microsoft_windows_unquoted_service_path_enumeration",
        "tests/fixtures/unquoted_service_path.nessus",
        "winhost",
    );
}

#[test]
fn virtual_machine_summary_template_lists_hosts() {
    let out = render_template_capture_raw_fixture(
        "virtual_machine_summary",
        "tests/fixtures/virtual_machines.nessus",
    );
    assert!(out.contains("vmwarehost"));
    assert!(out.contains("hypervhost"));
    assert!(out.contains("VMware"));
    assert!(out.contains("Hyper-V"));
}
