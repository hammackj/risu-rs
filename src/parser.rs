use std::fs;
use std::path::Path;

/// Parse an input file and return its contents
pub fn parse_file(path: &Path) -> String {
    println!("Parsing file: {}", path.display());
    fs::read_to_string(path).unwrap_or_default()
}

