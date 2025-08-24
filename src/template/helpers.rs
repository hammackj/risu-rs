use std::error::Error;
use std::fs;
use std::path::PathBuf;

use base64::{Engine, engine::general_purpose};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::graphs::{TopVulnGraph, WindowsOsGraph};

/// Produce a message indicating the operating system is unsupported.
pub fn unsupported_os(os: &str) -> String {
    format!("Unsupported operating system: {os}")
}

/// Format text as a second-level heading.
pub fn heading2(text: &str) -> String {
    format!("## {text}")
}

/// Embed a graph image as a base64 data URI.
///
/// The image bytes are expected to be in PNG format.
pub fn embed_graph(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let encoded = general_purpose::STANDARD.encode(bytes);
    Ok(format!("data:image/png;base64,{encoded}"))
}

/// Generate the top vulnerabilities graph and return it as a data URI.
pub fn top_vuln_graph(conn: &mut SqliteConnection) -> Result<String, Box<dyn Error>> {
    let dir: PathBuf = std::env::temp_dir();
    let path = TopVulnGraph::generate(conn, &dir, 10)?;
    let bytes = fs::read(path)?;
    embed_graph(&bytes)
}

/// Generate the Windows OS distribution graph and return it as a data URI.
pub fn windows_os_graph(conn: &mut SqliteConnection) -> Result<String, Box<dyn Error>> {
    let dir: PathBuf = std::env::temp_dir();
    let path = WindowsOsGraph::generate(conn, &dir)?;
    let bytes = fs::read(path)?;
    embed_graph(&bytes)
}

/// List plugin names that were individually enabled in the policy.
pub fn enabled_plugins(conn: &mut SqliteConnection) -> QueryResult<String> {
    use crate::schema::nessus_individual_plugin_selections::dsl::*;
    let rows = nessus_individual_plugin_selections
        .filter(status.eq("enabled"))
        .select(plugin_name)
        .load::<Option<String>>(conn)?;
    Ok(rows.into_iter().flatten().collect::<Vec<_>>().join(", "))
}

/// List server preferences as `name=value` pairs.
pub fn server_preferences_list(conn: &mut SqliteConnection) -> QueryResult<String> {
    use crate::schema::nessus_server_preferences::dsl::*;
    let rows = nessus_server_preferences
        .select((name, value))
        .load::<(Option<String>, Option<String>)>(conn)?;
    Ok(rows
        .into_iter()
        .map(|(n, v)| format!("{}={}", n.unwrap_or_default(), v.unwrap_or_default()))
        .collect::<Vec<_>>()
        .join(", "))
}

/// List plugin preferences as `name=selected` pairs.
pub fn plugin_preferences_list(conn: &mut SqliteConnection) -> QueryResult<String> {
    use crate::schema::nessus_plugins_preferences::dsl::*;
    let rows = nessus_plugins_preferences
        .select((preference_name, selected_values))
        .load::<(Option<String>, Option<String>)>(conn)?;
    Ok(rows
        .into_iter()
        .map(|(n, v)| format!("{}={}", n.unwrap_or_default(), v.unwrap_or_default()))
        .collect::<Vec<_>>()
        .join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::MIGRATIONS;
    use crate::schema::{
        nessus_individual_plugin_selections, nessus_plugins_preferences, nessus_server_preferences,
    };
    use diesel::sqlite::SqliteConnection;
    use diesel_migrations::MigrationHarness;

    #[test]
    fn unsupported_os_message() {
        let msg = unsupported_os("Solaris");
        assert_eq!(msg, "Unsupported operating system: Solaris");
    }

    #[test]
    fn heading2_formats() {
        assert_eq!(heading2("Title"), "## Title");
    }

    #[test]
    fn embed_graph_encodes_bytes() {
        let data = embed_graph(&[1u8, 2, 3]).unwrap();
        assert!(data.starts_with("data:image/png;base64,"));
        let b64 = &data["data:image/png;base64,".len()..];
        let expected = general_purpose::STANDARD.encode(&[1u8, 2, 3]);
        assert_eq!(b64, expected);
    }

    #[test]
    fn lists_enabled_plugins() {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        conn.run_pending_migrations(MIGRATIONS).unwrap();
        diesel::insert_into(nessus_individual_plugin_selections::table)
            .values((
                nessus_individual_plugin_selections::plugin_name.eq("Sample"),
                nessus_individual_plugin_selections::status.eq("enabled"),
            ))
            .execute(&mut conn)
            .unwrap();
        let list = enabled_plugins(&mut conn).unwrap();
        assert_eq!(list, "Sample");
    }

    #[test]
    fn lists_server_preferences() {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        conn.run_pending_migrations(MIGRATIONS).unwrap();
        diesel::insert_into(nessus_server_preferences::table)
            .values((
                nessus_server_preferences::name.eq("pref"),
                nessus_server_preferences::value.eq("val"),
            ))
            .execute(&mut conn)
            .unwrap();
        let list = server_preferences_list(&mut conn).unwrap();
        assert_eq!(list, "pref=val");
    }

    #[test]
    fn lists_plugin_preferences() {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        conn.run_pending_migrations(MIGRATIONS).unwrap();
        diesel::insert_into(nessus_plugins_preferences::table)
            .values((
                nessus_plugins_preferences::preference_name.eq("p"),
                nessus_plugins_preferences::selected_values.eq("s"),
            ))
            .execute(&mut conn)
            .unwrap();
        let list = plugin_preferences_list(&mut conn).unwrap();
        assert_eq!(list, "p=s");
    }
}
