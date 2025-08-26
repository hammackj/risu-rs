use std::error::Error;
use std::fs;
use std::path::PathBuf;

use base64::{Engine, engine::general_purpose};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::graphs::{TopVulnGraph, WindowsOsGraph};
use crate::models::{Attachment, FamilySelection, HostProperty, PolicyPlugin};
use crate::renderer::Renderer;

/// Produce a message indicating the operating system is unsupported.
pub fn unsupported_os(os: &str) -> String {
    format!("Unsupported operating system: {os}")
}

/// Format text as a second-level heading.
pub fn heading2(text: &str) -> String {
    format!("## {text}")
}

/// Record a section heading for navigation structures via the renderer.
pub fn section(
    renderer: &mut dyn Renderer,
    level: usize,
    title: &str,
) -> Result<(), Box<dyn Error>> {
    renderer.heading(level, title)
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

/// Plugins that indicate default credentials were accepted.
pub static DEFAULT_CREDENTIAL_PLUGINS: &[i32] = &[
    1000, 2000, 3000,
];

/// Determine if the given plugin ID indicates default credentials.
pub fn has_default_credentials(plugin_id: i32) -> bool {
    DEFAULT_CREDENTIAL_PLUGINS.contains(&plugin_id)
}

/// Generate a warning section when default credential plugins are present.
///
/// `plugin_ids` should contain all plugin identifiers observed in a report or
/// host. If any match [`DEFAULT_CREDENTIAL_PLUGINS`], a markdown formatted
/// section is returned, otherwise an empty string is produced.
pub fn default_credentials_section(plugin_ids: &[i32]) -> String {
    let found: Vec<i32> = plugin_ids
        .iter()
        .copied()
        .filter(|id| has_default_credentials(*id))
        .collect();

    if found.is_empty() {
        String::new()
    } else {
        let mut section = String::from("### Default Credentials Detected\n\n");
        section.push_str(
            "The following plugins indicate that default credentials were\
             accepted by the target:\n",
        );
        for id in found {
            section.push_str(&format!("- Plugin {id}\n"));
        }
        section
    }
}

/// Generate an appendix entry for default credential findings.
///
/// This simply wraps [`default_credentials_section`] in a second-level heading
/// suitable for inclusion in an appendix.
pub fn default_credentials_appendix_section(plugin_ids: &[i32]) -> String {
    let section = default_credentials_section(plugin_ids);
    if section.is_empty() {
        String::new()
    } else {
        format!("## Default Credentials\n\n{}", section)
    }
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

/// Fetch CVE identifiers for a given finding (item).
pub fn cve_identifiers(conn: &mut SqliteConnection, item_id_val: i32) -> QueryResult<Vec<String>> {
    use crate::schema::nessus_references::dsl::*;
    nessus_references
        .filter(item_id.eq(item_id_val).and(source.eq("CVE")))
        .select(value)
        .load::<Option<String>>(conn)
        .map(|vals| vals.into_iter().flatten().collect())
}

/// Fetch BID identifiers for a given finding (item).
pub fn bid_identifiers(conn: &mut SqliteConnection, item_id_val: i32) -> QueryResult<Vec<String>> {
    use crate::schema::nessus_references::dsl::*;
    nessus_references
        .filter(item_id.eq(item_id_val).and(source.eq("BID")))
        .select(value)
        .load::<Option<String>>(conn)
        .map(|vals| vals.into_iter().flatten().collect())
}

/// Fetch CVE identifiers for a plugin via indexed metadata.
pub fn plugin_cve_identifiers(
    conn: &mut SqliteConnection,
    plugin_id_val: i32,
) -> QueryResult<Vec<String>> {
    use crate::models::NessusPluginMetadata;
    Ok(NessusPluginMetadata::by_plugin_id(conn, plugin_id_val)?
        .and_then(|md| md.cve)
        .map(|s| s.split(',').map(|c| c.trim().to_string()).collect())
        .unwrap_or_default())
}

/// Fetch BID identifiers for a plugin via indexed metadata.
pub fn plugin_bid_identifiers(
    conn: &mut SqliteConnection,
    plugin_id_val: i32,
) -> QueryResult<Vec<String>> {
    use crate::models::NessusPluginMetadata;
    Ok(NessusPluginMetadata::by_plugin_id(conn, plugin_id_val)?
        .and_then(|md| md.bid)
        .map(|s| s.split(',').map(|b| b.trim().to_string()).collect())
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_default_credential_plugins() {
        assert!(has_default_credentials(1000));
        assert!(!has_default_credentials(42));
    }

    #[test]
    fn default_credential_sections_generate_output() {
        let plugins = vec![1, 1000, 2000];
        let section = default_credentials_section(&plugins);
        assert!(!section.is_empty());
        assert!(section.contains("Plugin 1000"));
        let appendix = default_credentials_appendix_section(&plugins);
        assert!(appendix.contains("Default Credentials"));
        assert!(appendix.contains("Plugin 2000"));
    }

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
            ahash: None,
            value: None,
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
    use crate::schema::{
        nessus_family_selections, nessus_policies, nessus_policy_plugins, nessus_server_preferences,
    };
    use crate::schema::{
        nessus_host_properties, nessus_hosts, nessus_items, nessus_plugin_metadata, nessus_plugins,
        nessus_references,
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

    #[derive(Insertable)]
    #[diesel(table_name = nessus_plugins)]
    struct NewPlugin<'a> {
        plugin_id: Option<i32>,
        plugin_name: Option<&'a str>,
    }

    #[derive(Insertable)]
    #[diesel(table_name = nessus_items)]
    struct NewItem<'a> {
        host_id: Option<i32>,
        plugin_id: Option<i32>,
        plugin_name: Option<&'a str>,
    }

    #[derive(Insertable)]
    #[diesel(table_name = nessus_references)]
    struct NewReference<'a> {
        plugin_id: Option<i32>,
        item_id: Option<i32>,
        source: Option<&'a str>,
        value: Option<&'a str>,
    }

    #[derive(Insertable)]
    #[diesel(table_name = nessus_plugin_metadata)]
    struct NewPluginMetadata<'a> {
        script_id: Option<i32>,
        script_name: Option<&'a str>,
        cve: Option<&'a str>,
        bid: Option<&'a str>,
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

    #[test]
    fn reference_queries() {
        let mut conn = setup();
        diesel::insert_into(nessus_hosts::table)
            .values(&NewHost {
                ip: Some("10.0.0.1"),
            })
            .execute(&mut conn)
            .unwrap();
        diesel::insert_into(nessus_plugins::table)
            .values(&NewPlugin {
                plugin_id: Some(1),
                plugin_name: Some("plug"),
            })
            .execute(&mut conn)
            .unwrap();
        diesel::insert_into(nessus_items::table)
            .values(&NewItem {
                host_id: Some(1),
                plugin_id: Some(1),
                plugin_name: Some("plug"),
            })
            .execute(&mut conn)
            .unwrap();
        diesel::insert_into(nessus_references::table)
            .values(&[
                NewReference {
                    plugin_id: Some(1),
                    item_id: Some(1),
                    source: Some("CVE"),
                    value: Some("CVE-2023-0001"),
                },
                NewReference {
                    plugin_id: Some(1),
                    item_id: Some(1),
                    source: Some("BID"),
                    value: Some("BID-1000"),
                },
            ])
            .execute(&mut conn)
            .unwrap();

        let cves = cve_identifiers(&mut conn, 1).unwrap();
        assert_eq!(cves, vec!["CVE-2023-0001".to_string()]);
        let bids = bid_identifiers(&mut conn, 1).unwrap();
        assert_eq!(bids, vec!["BID-1000".to_string()]);
    }

    #[test]
    fn plugin_metadata_queries() {
        let mut conn = setup();
        diesel::insert_into(nessus_plugin_metadata::table)
            .values(&NewPluginMetadata {
                script_id: Some(99),
                script_name: Some("plug"),
                cve: Some("CVE-2023-0001,CVE-2023-0002"),
                bid: Some("BID-1000,BID-1001"),
            })
            .execute(&mut conn)
            .unwrap();

        let cves = plugin_cve_identifiers(&mut conn, 99).unwrap();
        assert_eq!(cves, vec!["CVE-2023-0001", "CVE-2023-0002"]);
        let bids = plugin_bid_identifiers(&mut conn, 99).unwrap();
        assert_eq!(bids, vec!["BID-1000", "BID-1001"]);
    }
}
