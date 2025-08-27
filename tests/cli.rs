use assert_cmd::Command;
use predicates::str::contains;
use std::fs;
use tempfile::tempdir;

#[test]
fn create_config_and_parse() {
    let tmp = tempdir().unwrap();
    let sample = fs::canonicalize("tests/fixtures/sample.nessus").unwrap();

    // create config
    Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "--create-config-file"])
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
            "--config-file",
            "config.yml",
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
        .args(["--no-banner", "--create-config-file"])
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
            "--config-file",
            "config.yml",
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

#[test]
fn create_template_writes_skeleton() {
    let tmp = tempdir().unwrap();
    Command::cargo_bin("risu-rs")
        .unwrap()
        .current_dir(&tmp)
        .env("HOME", tmp.path())
        .args([
            "--no-banner",
            "create-template",
            "example",
            "--author",
            "Alice",
            "--renderer",
            "pdf",
        ])
        .assert()
        .success();
    let path = tmp
        .path()
        .join(".risu")
        .join("templates")
        .join("example.rs");
    assert!(path.exists());
}

#[test]
fn template_arg_overrides_title() {
    let tmp = tempdir().unwrap();
    let sample = fs::canonicalize("tests/fixtures/sample.nessus").unwrap();

    // create config
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
            "simple",
            "--renderer",
            "csv",
            "--template-arg",
            "title=Custom Title",
        ])
        .assert()
        .success();
    let contents = fs::read_to_string(output).unwrap();
    assert!(contents.contains("Custom Title"));
}

#[test]
fn list_post_process_shows_plugins() {
    let assert = Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "--list-post-process"])
        .assert()
        .success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(output.contains("fix_ips"));
    assert!(output.contains("normalize_plugin_names"));
}

#[test]
fn bug_report_shows_environment() {
    let assert = Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "--bug-report"])
        .assert()
        .success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(output.contains("Include the above output"));
}

#[test]
fn parse_invalid_input_displays_error() {
    let tmp = tempdir().unwrap();
    Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "--create-config-file"])
        .current_dir(&tmp)
        .assert()
        .success();

    let bad = tmp.path().join("bad.xml");
    fs::write(&bad, "<foo></foo>").unwrap();

    Command::cargo_bin("risu-rs")
        .unwrap()
        .current_dir(&tmp)
        .args([
            "--no-banner",
            "--config-file",
            "config.yml",
            "parse",
            bad.to_str().unwrap(),
            "-o",
            "out.csv",
            "-t",
            "simple",
        ])
        .assert()
        .failure()
        .stderr(contains("unsupported root element"));
}
