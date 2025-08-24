use std::error::Error;
use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose, Engine};
use diesel::sqlite::SqliteConnection;

use crate::graphs::{TopVulnGraph, WindowsOsGraph};
use crate::models::Attachment;

/// Produce a message indicating the operating system is unsupported.
pub fn unsupported_os(os: &str) -> String {
    format!("Unsupported operating system: {os}")
}

/// Format text as a second-level heading.
pub fn heading2(text: &str) -> String {
    format!("## {text}")
}

/// Embed a graph image as a base64 data URI.
///
/// The image bytes are expected to be in PNG format.
pub fn embed_graph(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let encoded = general_purpose::STANDARD.encode(bytes);
    Ok(format!("data:image/png;base64,{encoded}"))
}

/// Generate the top vulnerabilities graph and return it as a data URI.
pub fn top_vuln_graph(conn: &mut SqliteConnection) -> Result<String, Box<dyn Error>> {
    let dir: PathBuf = std::env::temp_dir();
    let path = TopVulnGraph::generate(conn, &dir, 10)?;
    let bytes = fs::read(path)?;
    embed_graph(&bytes)
}

/// Generate the Windows OS distribution graph and return it as a data URI.
pub fn windows_os_graph(conn: &mut SqliteConnection) -> Result<String, Box<dyn Error>> {
    let dir: PathBuf = std::env::temp_dir();
    let path = WindowsOsGraph::generate(conn, &dir)?;
    let bytes = fs::read(path)?;
    embed_graph(&bytes)
}

/// Embed a previously saved attachment as a data URI.
pub fn embed_attachment(att: &Attachment) -> Result<String, Box<dyn Error>> {
    let path = att
        .path
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "missing path"))?;
    let bytes = fs::read(path)?;
    let encoded = general_purpose::STANDARD.encode(bytes);
    let ctype = att
        .content_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());
    Ok(format!("data:{ctype};base64,{encoded}"))
}

/// Return the file system path of an attachment for referencing.
pub fn attachment_path(att: &Attachment) -> Option<&str> {
    att.path.as_deref()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_os_message() {
        let msg = unsupported_os("Solaris");
        assert_eq!(msg, "Unsupported operating system: Solaris");
    }

    #[test]
    fn heading2_formats() {
        assert_eq!(heading2("Title"), "## Title");
    }

    #[test]
    fn embed_graph_encodes_bytes() {
        let data = embed_graph(&[1u8, 2, 3]).unwrap();
        assert!(data.starts_with("data:image/png;base64,"));
        let b64 = &data["data:image/png;base64,".len()..];
        let expected = general_purpose::STANDARD.encode(&[1u8, 2, 3]);
        assert_eq!(b64, expected);
    }

    #[test]
    fn embed_attachment_reads_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("att.bin");
        std::fs::write(&file_path, b"hi").unwrap();
        let att = Attachment {
            id: 0,
            name: Some("att.bin".into()),
            content_type: Some("text/plain".into()),
            path: Some(file_path.to_string_lossy().to_string()),
            size: Some(2),
        };
        let data = embed_attachment(&att).unwrap();
        assert!(data.starts_with("data:text/plain;base64,"));
        let expected = general_purpose::STANDARD.encode(b"hi");
        assert_eq!(data["data:text/plain;base64,".len()..].to_string(), expected);
        assert_eq!(attachment_path(&att), att.path.as_deref());
    }
}
