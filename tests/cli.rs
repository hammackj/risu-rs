use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn create_config_and_parse() {
    let tmp = tempdir().unwrap();
    let sample = fs::canonicalize("tests/fixtures/sample.nessus").unwrap();

    // create config
    Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "create-config"])
        .current_dir(&tmp)
        .assert()
        .success();
    assert!(tmp.path().join("config.yml").exists());

    // parse file
    let output = tmp.path().join("out.csv");
    Command::cargo_bin("risu-rs")
        .unwrap()
        .current_dir(&tmp)
        .args([
            "--no-banner",
            "parse",
            sample.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-t",
            "simple",
        ])
        .assert()
        .success();
    assert!(output.exists());
}

#[test]
fn parse_with_nil_renderer_creates_no_file() {
    let tmp = tempdir().unwrap();
    let sample = fs::canonicalize("tests/fixtures/sample.nessus").unwrap();

    // create config
    Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "create-config"])
        .current_dir(&tmp)
        .assert()
        .success();
    assert!(tmp.path().join("config.yml").exists());

    // parse file with nil renderer
    let output = tmp.path().join("out.pdf");
    Command::cargo_bin("risu-rs")
        .unwrap()
        .current_dir(&tmp)
        .args([
            "--no-banner",
            "parse",
            sample.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-t",
            "simple",
            "--renderer",
            "nil",
        ])
        .assert()
        .success();
    assert!(!output.exists());
}
