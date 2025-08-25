use cargo_lock::Lockfile;

/// Print application, Rust, and crate versions then exit.
pub fn print() {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    println!("rustc {}", rustc_version_runtime::version());
    if let Ok(lock) = Lockfile::load("Cargo.lock") {
        println!("crates:");
        for pkg in lock.packages {
            println!("  {} {}", pkg.name, pkg.version);
        }
    }
}
