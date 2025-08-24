use std::error::Error;
use std::fs;
use std::path::PathBuf;

use base64::{Engine, engine::general_purpose};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::graphs::{TopVulnGraph, WindowsOsGraph};
use crate::models::{Attachment, FamilySelection, HostProperty, PolicyPlugin};

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

/// Embed a previously saved attachment as a data URI.
pub fn embed_attachment(att: &Attachment) -> Result<String, Box<dyn Error>> {
    let path = att
        .path
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "missing path"))?;
    let bytes = fs::read(path)?;
    let encoded = general_purpose::STANDARD.encode(bytes);
    let ctype = att
        .content_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());
    Ok(format!("data:{ctype};base64,{encoded}"))
}

/// Return the file system path of an attachment for referencing.
pub fn attachment_path(att: &Attachment) -> Option<&str> {
    att.path.as_deref()
}

/// Fetch a host property by name for a given host.
pub fn host_property(
    conn: &mut SqliteConnection,
    host_id_val: i32,
    prop_name: &str,
) -> QueryResult<Option<String>> {
    use crate::schema::nessus_host_properties::dsl::*;
    nessus_host_properties
        .filter(host_id.eq(host_id_val).and(name.eq(prop_name)))
        .select(value)
        .first::<Option<String>>(conn)
        .optional()
        .map(|res| res.flatten())
}

/// Retrieve all properties for a host.
pub fn host_properties(
    conn: &mut SqliteConnection,
    host_id_val: i32,
) -> QueryResult<Vec<HostProperty>> {
    use crate::schema::nessus_host_properties::dsl::*;
    nessus_host_properties
        .filter(host_id.eq(host_id_val))
        .load::<HostProperty>(conn)
}

/// Fetch enabled plugin families for a policy.
pub fn enabled_families(
    conn: &mut SqliteConnection,
    policy_id_val: i32,
) -> QueryResult<Vec<FamilySelection>> {
    use crate::schema::nessus_family_selections::dsl::*;
    nessus_family_selections
        .filter(policy_id.eq(policy_id_val).and(status.eq("enabled")))
        .load::<FamilySelection>(conn)
}

/// Fetch enabled plugins for a policy.
pub fn enabled_plugins(
    conn: &mut SqliteConnection,
    policy_id_val: i32,
) -> QueryResult<Vec<PolicyPlugin>> {
    use crate::schema::nessus_policy_plugins::dsl::*;
    nessus_policy_plugins
        .filter(policy_id.eq(policy_id_val).and(status.eq("enabled")))
        .load::<PolicyPlugin>(conn)
}

/// Fetch a server preference by name for a policy.
pub fn server_preference(
    conn: &mut SqliteConnection,
    policy_id_val: i32,
    pref_name: &str,
) -> QueryResult<Option<String>> {
    use crate::schema::nessus_server_preferences::dsl::*;
    nessus_server_preferences
        .filter(policy_id.eq(policy_id_val).and(name.eq(pref_name)))
        .select(value)
        .first::<Option<String>>(conn)
        .optional()
        .map(|r| r.flatten())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn embed_attachment_reads_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("att.bin");
        std::fs::write(&file_path, b"hi").unwrap();
        let att = Attachment {
            id: 0,
            name: Some("att.bin".into()),
            content_type: Some("text/plain".into()),
            path: Some(file_path.to_string_lossy().to_string()),
            size: Some(2),
        };
        let data = embed_attachment(&att).unwrap();
        assert!(data.starts_with("data:text/plain;base64,"));
        let expected = general_purpose::STANDARD.encode(b"hi");
        assert_eq!(
            data["data:text/plain;base64,".len()..].to_string(),
            expected
        );
        assert_eq!(attachment_path(&att), att.path.as_deref());
    }

    use crate::migrate::MIGRATIONS;
    use crate::schema::{nessus_host_properties, nessus_hosts};
    use crate::schema::{
        nessus_family_selections, nessus_policy_plugins, nessus_policies,
        nessus_server_preferences,
    };
    use diesel::sqlite::SqliteConnection;
    use diesel_migrations::MigrationHarness;

    #[derive(Insertable)]
    #[diesel(table_name = nessus_hosts)]
    struct NewHost<'a> {
        ip: Option<&'a str>,
    }

    #[derive(Insertable)]
    #[diesel(table_name = nessus_host_properties)]
    struct NewHostProperty<'a> {
        host_id: Option<i32>,
        name: Option<&'a str>,
        value: Option<&'a str>,
    }

    #[derive(Insertable)]
    #[diesel(table_name = nessus_policies)]
    struct NewPolicy<'a> {
        name: Option<&'a str>,
        comments: Option<&'a str>,
    }

    #[derive(Insertable)]
    #[diesel(table_name = nessus_policy_plugins)]
    struct NewPolicyPlugin<'a> {
        policy_id: Option<i32>,
        plugin_id: Option<i32>,
        status: Option<&'a str>,
    }

    #[derive(Insertable)]
    #[diesel(table_name = nessus_family_selections)]
    struct NewFamilySelection<'a> {
        policy_id: Option<i32>,
        family_name: Option<&'a str>,
        status: Option<&'a str>,
    }

    #[derive(Insertable)]
    #[diesel(table_name = nessus_server_preferences)]
    struct NewServerPreference<'a> {
        policy_id: Option<i32>,
        name: Option<&'a str>,
        value: Option<&'a str>,
    }

    fn setup() -> SqliteConnection {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        conn.run_pending_migrations(MIGRATIONS).unwrap();
        conn
    }

    #[test]
    fn host_property_queries() {
        let mut conn = setup();
        diesel::insert_into(nessus_hosts::table)
            .values(&NewHost {
                ip: Some("10.0.0.1"),
            })
            .execute(&mut conn)
            .unwrap();
        diesel::insert_into(nessus_host_properties::table)
            .values(&NewHostProperty {
                host_id: Some(1),
                name: Some("foo"),
                value: Some("bar"),
            })
            .execute(&mut conn)
            .unwrap();
        let val = host_property(&mut conn, 1, "foo").unwrap();
        assert_eq!(val.as_deref(), Some("bar"));
        let props = host_properties(&mut conn, 1).unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].name.as_deref(), Some("foo"));
    }

    #[test]
    fn policy_helpers_query() {
        let mut conn = setup();
        diesel::insert_into(nessus_policies::table)
            .values(&NewPolicy {
                name: Some("default"),
                comments: None,
            })
            .execute(&mut conn)
            .unwrap();
        diesel::insert_into(nessus_policy_plugins::table)
            .values(&NewPolicyPlugin {
                policy_id: Some(1),
                plugin_id: Some(1),
                status: Some("enabled"),
            })
            .execute(&mut conn)
            .unwrap();
        diesel::insert_into(nessus_family_selections::table)
            .values(&NewFamilySelection {
                policy_id: Some(1),
                family_name: Some("General"),
                status: Some("enabled"),
            })
            .execute(&mut conn)
            .unwrap();
        diesel::insert_into(nessus_server_preferences::table)
            .values(&NewServerPreference {
                policy_id: Some(1),
                name: Some("opt"),
                value: Some("1"),
            })
            .execute(&mut conn)
            .unwrap();

        let fams = enabled_families(&mut conn, 1).unwrap();
        assert_eq!(fams.len(), 1);
        assert_eq!(fams[0].family_name.as_deref(), Some("General"));

        let plugs = enabled_plugins(&mut conn, 1).unwrap();
        assert_eq!(plugs.len(), 1);
        assert_eq!(plugs[0].plugin_id, Some(1));

        let pref = server_preference(&mut conn, 1, "opt").unwrap();
        assert_eq!(pref.as_deref(), Some("1"));
    }
}
