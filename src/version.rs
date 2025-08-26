use cargo_lock::Lockfile;
use diesel::prelude::*;
use diesel::result::Error;
use diesel::sqlite::SqliteConnection;
use tracing::warn;

use crate::schema::versions::dsl::{version as version_col, versions};

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

/// Return the database schema version if available.
pub fn db_version(conn: &mut SqliteConnection) -> Result<Option<String>, Error> {
    versions.select(version_col).first::<String>(conn).optional()
}

/// Warn if the database schema version differs from the application version.
pub fn warn_on_mismatch(conn: &mut SqliteConnection) {
    if let Ok(Some(db_ver)) = db_version(conn) {
        let app_ver = env!("CARGO_PKG_VERSION");
        if db_ver != app_ver {
            warn!(
                "database schema version ({db_ver}) does not match application version ({app_ver})"
            );
        }
    }
}
