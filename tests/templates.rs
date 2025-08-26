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
fn exec_summary_template_matches_ruby() {
    let rust_out = render_template_capture_raw("exec_summary");
    let ruby_out = Command::new("ruby")
        .arg("tests/fixtures/exec_summary_ruby.rb")
        .arg("tests/fixtures/sample.nessus")
        .output()
        .expect("failed to run ruby script");
    let ruby_str = String::from_utf8_lossy(&ruby_out.stdout).trim().to_string();
    assert_eq!(rust_out.trim(), ruby_str);
}
