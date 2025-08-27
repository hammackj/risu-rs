use std::path::Path;

use crate::error::Error;

use super::NessusReport;

/// Parse a Tenable SecurityCenter export. SecurityCenter uses the Nessus XML
/// format so the standard Nessus parser can handle these reports.
pub fn parse_file(path: &Path) -> Result<NessusReport, Error> {
    super::parse_nessus(path, "SecurityCenter")
}
