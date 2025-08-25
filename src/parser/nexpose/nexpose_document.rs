use std::path::Path;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::Error;
use crate::parser::NessusReport;

/// Determine if the provided XML file has a `NeXposeSimpleXML` root tag.
pub fn is_nexpose<P: AsRef<Path>>(path: P) -> Result<bool, Error> {
    let mut reader = Reader::from_file(path)?;
    reader.trim_text(true);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                return Ok(e.name().as_ref() == b"NeXposeSimpleXML");
            }
            Event::Eof => return Ok(false),
            _ => {}
        }
        buf.clear();
    }
}

/// Parse a Nexpose simple XML file into a [`NessusReport`].
pub fn parse_file(path: &Path) -> Result<NessusReport, Error> {
    let mut reader = Reader::from_file(path)?;
    reader.trim_text(true);
    let mut buf = Vec::new();

    // Validate root element
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                if e.name().as_ref() != b"NeXposeSimpleXML" {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unexpected root element",
                    )
                    .into());
                }
                break;
            }
            Event::Eof => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected end of file",
                )
                .into());
            }
            _ => {}
        }
        buf.clear();
    }

    super::simple_nexpose::parse(&mut reader)
}
