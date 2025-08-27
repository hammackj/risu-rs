use diesel::migration::MigrationSource;
use diesel::prelude::*;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use tracing::info;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub fn run(
    database_url: &str,
    backend: &str,
    create_tables: bool,
    drop_tables: bool,
) -> Result<(), crate::error::Error> {
    match backend {
        "postgres" => {
            #[cfg(feature = "postgres")]
            {
                let mut conn = diesel::pg::PgConnection::establish(database_url)?;
                execute_migrations(&mut conn, create_tables, drop_tables)
            }
            #[cfg(not(feature = "postgres"))]
            {
                Err(crate::error::Error::Migration("postgres feature not enabled".into()))
            }
        }
        "mysql" => {
            #[cfg(feature = "mysql")]
            {
                let mut conn = diesel::mysql::MysqlConnection::establish(database_url)?;
                execute_migrations(&mut conn, create_tables, drop_tables)
            }
            #[cfg(not(feature = "mysql"))]
            {
                Err(crate::error::Error::Migration("mysql feature not enabled".into()))
            }
        }
        _ => {
            #[cfg(feature = "sqlite")]
            {
                let mut conn = diesel::sqlite::SqliteConnection::establish(database_url)?;
                execute_migrations(&mut conn, create_tables, drop_tables)
            }
            #[cfg(not(feature = "sqlite"))]
            {
                Err(crate::error::Error::Migration("sqlite feature not enabled".into()))
            }
        }
    }
}

fn execute_migrations<DB, C>(
    conn: &mut C,
    create_tables: bool,
    drop_tables: bool,
) -> Result<(), crate::error::Error>
where
    DB: diesel::backend::Backend,
    C: MigrationHarness<DB> + diesel::Connection<Backend = DB>,
{
    if create_tables {
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(crate::error::Error::Migration)?;
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
