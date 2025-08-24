pub mod nessus;
pub mod simple_nexpose;

pub use nessus::NessusReport;

use std::path::Path;
use crate::error::Error;

/// Detect file type and parse accordingly.
pub fn parse_file(path: &Path) -> Result<NessusReport, Error> {
    match path.extension().and_then(|e| e.to_str()).map(|s| s.to_lowercase()) {
        Some(ext) if ext == "csv" => {
            let report = simple_nexpose::parse_file(path)?;
            Ok(report.into())
        }
        _ => nessus::parse_file(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_csv_to_simple_parser() {
        let path = std::path::Path::new("tests/fixtures/sample_nexpose.csv");
        let report = parse_file(path).expect("parse csv");
        assert_eq!(report.hosts.len(), 2);
        assert_eq!(report.items.len(), 3);
        assert_eq!(report.plugins.len(), 2);
    }
}
