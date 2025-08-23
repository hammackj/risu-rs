use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::migration::MigrationSource;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

/// Perform database migrations
pub fn run(create_tables: bool, drop_tables: bool) {
    let database_url = "risu.db";
    let mut conn = SqliteConnection::establish(database_url)
        .expect("Failed to connect to database");

    if create_tables {
        conn.run_pending_migrations(MIGRATIONS)
            .expect("Failed to run migrations");
    }

    if drop_tables {
        if let Ok(migs) = MIGRATIONS.migrations() {
            for migration in migs.iter().rev() {
                conn.revert_migration(migration)
                    .expect("Failed to revert migration");
            }
        }
    }

    if !create_tables && !drop_tables {
        println!("No migration action specified");
    }
}

