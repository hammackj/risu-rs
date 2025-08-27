use std::path::Path;

/// Print environment details useful for filing bug reports.
pub fn print(config_path: &Path) {
    println!("Please include the following information when filing an issue:\n");
    // Application and Rust versions via existing helper
    crate::version::print();
    // Database engine version
    println!("sqlite {}", rusqlite::version());
    // OS details
    if let Ok(os_type) = sys_info::os_type() {
        if let Ok(os_release) = sys_info::os_release() {
            println!("os {os_type} {os_release}");
        } else {
            println!("os {os_type}");
        }
    }
    // Configuration file location
    println!("config file {}", config_path.display());
    // Recent log lines if a log file exists in the current directory
    let log_path = Path::new("risu.log");
    if log_path.exists() {
        println!("recent log lines from {}:", log_path.display());
        if let Ok(log) = std::fs::read_to_string(log_path) {
            let lines: Vec<_> = log.lines().rev().take(20).collect();
            for line in lines.into_iter().rev() {
                println!("  {line}");
            }
        }
    }
    println!("\nInclude the above output when filing an issue.");
}
