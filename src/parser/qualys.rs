use std::path::Path;

use crate::error::Error;

use super::NessusReport;

/// Parse a Qualys export. Qualys can produce Nessus compatible XML, so we
/// delegate to the shared Nessus parser.
pub fn parse_file(path: &Path) -> Result<NessusReport, Error> {
    super::parse_nessus(path)
}
