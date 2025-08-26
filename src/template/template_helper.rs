//! Common helper functions for report templates.
//!
//! This module mirrors helper utilities from the original Ruby implementation
//! and aggregates the various sub-helpers so templates can import a single
//! prelude.

// Re-export sub-helper modules for convenience so templates can simply import
// `template_helper` and access everything under a common namespace.
pub use super::graph_template_helper as graph;
pub use super::host_template_helper as host;
pub use super::malware_template_helper as malware;
pub use super::scan_helper as scan;
pub use super::shares_template_helper as shares;

/// Format text as a Markdown heading at the given level.
///
/// ```
/// use risu::template::template_helper::heading;
/// assert_eq!(heading(2, "Section"), "## Section");
/// ```
pub fn heading(level: usize, text: &str) -> String {
    format!("{} {text}", "#".repeat(level))
}

/// Render an iterator of items as a Markdown bullet list.
///
/// ```
/// use risu::template::template_helper::bullet_list;
/// let out = bullet_list(["a", "b"]);
/// assert_eq!(out, "- a\n- b");
/// ```
pub fn bullet_list<I, T>(items: I) -> String
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    items
        .into_iter()
        .map(|s| format!("- {}", s.as_ref()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Format a simple name/value pair.
///
/// ```
/// use risu::template::template_helper::field;
/// assert_eq!(field("Host", "server"), "Host: server");
/// ```
pub fn field(name: &str, value: &str) -> String {
    format!("{name}: {value}")
}

/// Generate a simple classification banner appearing above and below text.
///
/// ```
/// use risu::template::template_helper::classification_banner;
/// let out = classification_banner("UNCLASSIFIED");
/// assert!(out.contains("UNCLASSIFIED"));
/// ```
pub fn classification_banner(text: &str) -> String {
    let line = format!("*** {text} ***");
    format!("{line}\n{line}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heading_levels() {
        assert_eq!(heading(1, "Title"), "# Title");
        assert_eq!(heading(2, "Sub"), "## Sub");
    }

    #[test]
    fn bullets_work() {
        let out = bullet_list(["one", "two"]);
        assert_eq!(out, "- one\n- two");
    }

    #[test]
    fn field_format() {
        assert_eq!(field("A", "B"), "A: B");
    }

    #[test]
    fn banner_contains_text() {
        let b = classification_banner("CLASS");
        assert!(b.contains("CLASS"));
    }
}
