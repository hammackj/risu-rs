use std::path::Path;

use crate::error::Error;

use super::NessusReport;

/// Parse a SAINT export. These reports use the Nessus XML schema so the
/// generic Nessus parser is sufficient.
pub fn parse_file(path: &Path) -> Result<NessusReport, Error> {
    super::parse_nessus(path)
}
