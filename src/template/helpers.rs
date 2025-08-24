use std::error::Error;
use base64::{engine::general_purpose, Engine};

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
}
