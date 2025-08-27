use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use rustyline::{DefaultEditor, error::ReadlineError};
use std::path::Path;

use crate::{config, error, models};

pub fn run(config_path: &Path) -> Result<(), error::Error> {
    let cfg = config::load_config(config_path).unwrap_or_default();
    let mut dconn = SqliteConnection::establish(&cfg.database_url)?;
    let db_path = cfg
        .database_url
        .strip_prefix("sqlite://")
        .unwrap_or(&cfg.database_url)
        .to_string();
    let rconn =
        rusqlite::Connection::open(db_path).map_err(|e| error::Error::Config(e.to_string()))?;
    let mut rl = DefaultEditor::new().map_err(|e| error::Error::Config(e.to_string()))?;
    loop {
        match rl.readline("risu> ") {
            Ok(line) => {
                let input = line.trim();
                if input.eq_ignore_ascii_case("exit") {
                    break;
                }
                if input.eq_ignore_ascii_case("hosts") {
                    match models::Host::ip_list(&mut dconn, None) {
                        Ok(list) => println!("{list}"),
                        Err(e) => println!("{e}"),
                    }
                    continue;
                }
                if input.is_empty() {
                    continue;
                }
                if let Err(e) = execute_sql(&rconn, input) {
                    println!("{e}");
                }
            }
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(err) => {
                println!("{err}");
                break;
            }
        }
    }
    Ok(())
}

fn execute_sql(conn: &rusqlite::Connection, sql: &str) -> Result<(), rusqlite::Error> {
    if sql.trim_start().to_uppercase().starts_with("SELECT") {
        let mut stmt = conn.prepare(sql)?;
        let column_count = stmt.column_count();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let mut parts = Vec::new();
            for i in 0..column_count {
                let val: rusqlite::types::Value = row.get(i)?;
                parts.push(value_to_string(val));
            }
            println!("{}", parts.join(" | "));
        }
    } else {
        conn.execute(sql, [])?;
    }
    Ok(())
}

fn value_to_string(val: rusqlite::types::Value) -> String {
    use rusqlite::types::Value::*;
    match val {
        Null => "NULL".to_string(),
        Integer(i) => i.to_string(),
        Real(f) => f.to_string(),
        Text(t) => t,
        Blob(_) => "<BLOB>".to_string(),
    }
}
