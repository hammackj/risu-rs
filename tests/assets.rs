use risu_rs::templates::assets;
use tempfile::tempdir;

#[test]
fn nessus_logo_is_embedded_and_writable() {
    assert!(!assets::nessus_logo_jpg().is_empty());
    let dir = tempdir().unwrap();
    let path = assets::write_nessus_logo_jpg_to(dir.path()).unwrap();
    assert!(path.exists());
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(bytes, assets::nessus_logo_jpg());
}
