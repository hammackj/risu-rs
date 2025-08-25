use super::helpers;

/// Format a section enumerating network shares.
pub fn share_enumeration(shares: &[(&str, &str)]) -> String {
    if shares.is_empty() {
        "No network shares found.".to_string()
    } else {
        let mut lines = Vec::new();
        lines.push(helpers::heading2("Network Shares"));
        for (name, path) in shares {
            lines.push(format!("{name}: {path}"));
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_shares() {
        assert_eq!(share_enumeration(&[]), "No network shares found.");
    }

    #[test]
    fn list_shares() {
        let out = share_enumeration(&[("C$", "C:\\"), ("D$", "D:\\")]);
        assert!(out.contains("Network Shares"));
        assert!(out.contains("C$"));
        assert!(out.contains("D$"));
    }
}
