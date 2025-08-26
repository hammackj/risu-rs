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

#[test]
fn notable_template_renders() {
    run_template("notable", "Notable Findings");
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
fn pci_compliance_template_renders() {
    run_template("pci_compliance", "PCI / DSS Compliance Overview");
}
