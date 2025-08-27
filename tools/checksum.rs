use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256, Sha512};

fn main() -> io::Result<()> {
    let paths: Vec<String> = env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: checksum <file> [file ...]");
        std::process::exit(1);
    }

    fs::create_dir_all("checksum")?;

    for path in paths {
        let mut file = File::open(&path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let sha256 = Sha256::digest(&buf);
        let sha512 = Sha512::digest(&buf);

        let name = Path::new(&path)
            .file_name()
            .expect("file name")
            .to_string_lossy();

        let mut out256 = File::create(format!("checksum/{}.sha256", name))?;
        writeln!(out256, "{:x}  {}", sha256, name)?;

        let mut out512 = File::create(format!("checksum/{}.sha512", name))?;
        writeln!(out512, "{:x}  {}", sha512, name)?;
    }

    Ok(())
}

