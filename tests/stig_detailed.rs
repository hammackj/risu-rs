use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

use risu_rs::templates::stig_detailed::category_for_plugin;

#[test]
fn category_lookup_matches_dataset() {
    assert_eq!(category_for_plugin(1), Some("Category I"));
    assert_eq!(category_for_plugin(2), Some("Category II"));
    assert_eq!(category_for_plugin(3), Some("Category III"));
    assert_eq!(category_for_plugin(9999), None);
}

#[test]
fn template_outputs_by_category() {
    let tmp = tempdir().unwrap();
    let sample = fs::canonicalize("tests/fixtures/stig_sample.nessus").unwrap();

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
            "stig_detailed",
            "--renderer",
            "csv",
        ])
        .assert()
        .success();

    let contents = fs::read_to_string(output).unwrap();
    assert!(contents.contains("Category I"));
    assert!(contents.contains("Plug1"));
    assert!(contents.contains("Sol1"));
    assert!(contents.contains("Category II"));
    assert!(contents.contains("Plug2"));
    assert!(contents.contains("Category III"));
    assert!(contents.contains("Plug3"));
}
