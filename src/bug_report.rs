use std::path::Path;

/// Print environment details useful for filing bug reports.
pub fn print(config_path: &Path) {
    println!("Please include the following information when filing an issue:\n");

    // Application and Rust versions via existing helper
    crate::version::print();

    // OS details
    if let Ok(os_type) = sys_info::os_type() {
        if let Ok(os_release) = sys_info::os_release() {
            println!("os {os_type} {os_release}");
        } else {
            println!("os {os_type}");
        }
    }

    // Database backend information
    let cfg = crate::config::load_config(config_path).unwrap_or_default();
    println!("database {}", cfg.database_url);
    println!("sqlite {}", rusqlite::version());

    // Recent log files in the current directory
    if let Ok(entries) = std::fs::read_dir(".") {
        let mut logs: Vec<_> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("log"))
            .collect();
        logs.sort();
        if !logs.is_empty() {
            println!("recent log files:");
            for path in logs.iter().take(5) {
                println!("  {}", path.display());
            }
        }
    }

    println!("\nInclude the above output when filing an issue.");
}
