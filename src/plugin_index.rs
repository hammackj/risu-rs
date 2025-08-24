use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel_migrations::MigrationHarness;
use regex::Regex;
use walkdir::WalkDir;

use crate::migrate::MIGRATIONS;
use crate::schema::nessus_plugin_metadata;
use tracing::info;

#[derive(Insertable)]
#[diesel(table_name = nessus_plugin_metadata)]
struct NewPluginMetadata<'a> {
    script_id: i32,
    script_name: &'a str,
    cve: Option<&'a str>,
    bid: Option<&'a str>,
}

pub fn run(dir: &std::path::Path) -> Result<(), crate::error::Error> {
    let database_url = "risu.db";
    let mut conn = SqliteConnection::establish(database_url)?;
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(crate::error::Error::Migration)?;

    // clear existing entries
    diesel::delete(nessus_plugin_metadata::table).execute(&mut conn)?;

    let re_id = Regex::new(r"(?m)script_id\s*\(\s*([0-9]+)\s*\)")?;
    let re_name = Regex::new(r#"(?m)script_name\s*\(\s*\"([^\"]+)\""#)?;
    let re_xref = Regex::new(
        r#"(?m)script_xref\s*\(\s*name\s*:\s*\"([^\"]+)\"\s*,\s*value\s*:\s*\"([^\"]+)\""#,
    )?;

    let mut processed = 0;
    let mut inserted = 0;

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file()
            && entry.path().extension().and_then(|s| s.to_str()) == Some("nasl")
        {
            processed += 1;
            let content = match std::fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let id_cap = match re_id.captures(&content) {
                Some(c) => c,
                None => continue,
            };
            let name_cap = match re_name.captures(&content) {
                Some(c) => c,
                None => continue,
            };
            let script_id: i32 = id_cap[1].parse().unwrap_or(0);
            let script_name = name_cap[1].trim();

            let mut cves = Vec::new();
            let mut bids = Vec::new();
            for cap in re_xref.captures_iter(&content) {
                match &cap[1] {
                    "CVE" => cves.push(cap[2].to_string()),
                    "BID" => bids.push(cap[2].to_string()),
                    _ => {}
                }
            }
            let cve_str = if cves.is_empty() {
                None
            } else {
                Some(cves.join(","))
            };
            let bid_str = if bids.is_empty() {
                None
            } else {
                Some(bids.join(","))
            };

            let new_md = NewPluginMetadata {
                script_id,
                script_name,
                cve: cve_str.as_deref(),
                bid: bid_str.as_deref(),
            };
            diesel::insert_into(nessus_plugin_metadata::table)
                .values(&new_md)
                .execute(&mut conn)?;
            inserted += 1;
            info!("Indexed plugin {} ({})", script_id, script_name);
        }
    }

    info!(
        "Processed {} plugin files, inserted {} records",
        processed, inserted
    );
    Ok(())
}
