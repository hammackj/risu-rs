use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn parse_to_rtf_creates_file() {
    let tmp = tempdir().unwrap();
    let sample = fs::canonicalize("tests/fixtures/sample.nessus").unwrap();

    Command::cargo_bin("risu-rs")
        .unwrap()
        .args(["--no-banner", "--create-config-file"])
        .current_dir(&tmp)
        .assert()
        .success();

    let output = tmp.path().join("out.rtf");
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
            "rtf",
        ])
        .assert()
        .success();

    let contents = fs::read_to_string(output).unwrap();
    assert!(contents.starts_with("{\\rtf"));
    assert!(contents.contains("Simple Report"));
}
