use diesel::migration::MigrationSource;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use tracing::info;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

/// Perform database migrations
pub fn run(create_tables: bool, drop_tables: bool) -> Result<(), crate::error::Error> {
    let database_url = "risu.db";
    let mut conn = SqliteConnection::establish(database_url)?;

    if create_tables {
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(crate::error::Error::Migration)?;

        use crate::models::version::NewVersion;
        use crate::schema::versions::dsl::versions as versions_table;
        use diesel::dsl::insert_into;
        let new_ver = NewVersion {
            version: env!("CARGO_PKG_VERSION"),
        };
        let _ = insert_into(versions_table)
            .values(&new_ver)
            .execute(&mut conn);
    }

    if drop_tables {
        let migs = MIGRATIONS
            .migrations()
            .map_err(crate::error::Error::Migration)?;
        for migration in migs.iter().rev() {
            conn.revert_migration(migration)
                .map_err(crate::error::Error::Migration)?;
        }
    }

    if !create_tables && !drop_tables {
        info!("No migration action specified");
    }
    Ok(())
}
