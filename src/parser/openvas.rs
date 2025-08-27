use std::path::Path;

use crate::error::Error;

use super::NessusReport;

/// Parse an OpenVAS report. OpenVAS exports are generally compatible with the
/// Nessus XML schema, so we simply reuse the existing Nessus parser.
pub fn parse_file(path: &Path) -> Result<NessusReport, Error> {
    super::parse_nessus(path, "OpenVAS")
}
