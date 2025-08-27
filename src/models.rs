//! Database models representing parsed Nessus data.
//!
//! The models map directly to tables created by Diesel migrations and are used
//! by the parser and CLI. Only a subset of the original Ruby models are
//! implemented at the moment.

pub mod attachment;
pub mod family_selection;
pub mod host;
pub mod host_property;
pub mod item;
pub mod patch;
pub mod plugin_metadata;
pub mod plugin_preference;
pub mod policy;
pub mod policy_plugin;
pub mod reference;
pub mod report;
pub mod server_preference;
pub mod service_description;
pub mod scanner;
pub mod version;

pub use attachment::Attachment;
pub use family_selection::FamilySelection;
pub use host_property::HostProperty;
pub use item::Item;
pub use patch::Patch;
pub use plugin_metadata::NessusPluginMetadata;
pub use plugin_preference::PluginPreference;
pub use policy::Policy;
pub use policy_plugin::PolicyPlugin;
pub use reference::Reference;
pub use report::Report;
pub use server_preference::ServerPreference;
pub use service_description::ServiceDescription;
pub use scanner::Scanner;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use std::net::IpAddr;

use crate::schema::{nessus_hosts, nessus_plugins};

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Report, foreign_key = nessus_report_id))]
#[diesel(table_name = nessus_hosts)]
pub struct Host {
    pub id: i32,
    pub nessus_report_id: Option<i32>,
    pub name: Option<String>,
    pub os: Option<String>,
    pub mac: Option<String>,
    pub start: Option<chrono::NaiveDateTime>,
    pub end: Option<chrono::NaiveDateTime>,
    pub ip: Option<String>,
    pub fqdn: Option<String>,
    pub netbios: Option<String>,
    pub notes: Option<String>,
    pub risk_score: Option<i32>,
    pub user_id: Option<i32>,
    pub engagement_id: Option<i32>,
    pub scanner_id: Option<i32>,
}

#[derive(Debug, Queryable, Identifiable)]
#[diesel(table_name = nessus_plugins)]
pub struct Plugin {
    pub id: i32,
    pub plugin_id: Option<i32>,
    pub plugin_name: Option<String>,
    pub family_name: Option<String>,
    pub description: Option<String>,
    pub plugin_version: Option<String>,
    pub plugin_publication_date: Option<chrono::NaiveDateTime>,
    pub plugin_modification_date: Option<chrono::NaiveDateTime>,
    pub vuln_publication_date: Option<chrono::NaiveDateTime>,
    pub cvss_vector: Option<String>,
    pub cvss_base_score: Option<f32>,
    pub cvss_temporal_score: Option<String>,
    pub cvss_temporal_vector: Option<String>,
    pub exploitability_ease: Option<String>,
    pub exploit_framework_core: Option<String>,
    pub exploit_framework_metasploit: Option<String>,
    pub metasploit_name: Option<String>,
    pub exploit_framework_canvas: Option<String>,
    pub canvas_package: Option<String>,
    pub exploit_available: Option<String>,
    pub risk_factor: Option<String>,
    pub solution: Option<String>,
    pub synopsis: Option<String>,
    pub plugin_type: Option<String>,
    pub exploit_framework_exploithub: Option<String>,
    pub exploithub_sku: Option<String>,
    pub stig_severity: Option<String>,
    pub fname: Option<String>,
    pub always_run: Option<String>,
    pub script_version: Option<String>,
    pub d2_elliot_name: Option<String>,
    pub exploit_framework_d2_elliot: Option<String>,
    pub exploited_by_malware: Option<String>,
    pub rollup: Option<bool>,
    pub risk_score: Option<i32>,
    pub compliance: Option<String>,
    pub root_cause: Option<String>,
    pub agent: Option<String>,
    pub potential_vulnerability: Option<bool>,
    pub in_the_news: Option<bool>,
    pub exploited_by_nessus: Option<bool>,
    pub unsupported_by_vendor: Option<bool>,
    pub default_account: Option<bool>,
    pub user_id: Option<i32>,
    pub engagement_id: Option<i32>,
    pub policy_id: Option<i32>,
    pub scanner_id: Option<i32>,
}

impl Default for Plugin {
    fn default() -> Self {
        Self {
            id: 0,
            plugin_id: None,
            plugin_name: None,
            family_name: None,
            description: None,
            plugin_version: None,
            plugin_publication_date: None,
            plugin_modification_date: None,
            vuln_publication_date: None,
            cvss_vector: None,
            cvss_base_score: None,
            cvss_temporal_score: None,
            cvss_temporal_vector: None,
            exploitability_ease: None,
            exploit_framework_core: None,
            exploit_framework_metasploit: None,
            metasploit_name: None,
            exploit_framework_canvas: None,
            canvas_package: None,
            exploit_available: None,
            risk_factor: None,
            solution: None,
            synopsis: None,
            plugin_type: None,
            exploit_framework_exploithub: None,
            exploithub_sku: None,
            stig_severity: None,
            fname: None,
            always_run: None,
            script_version: None,
            d2_elliot_name: None,
            exploit_framework_d2_elliot: None,
            exploited_by_malware: None,
            rollup: None,
            risk_score: None,
            compliance: None,
            root_cause: None,
            agent: None,
            potential_vulnerability: None,
            in_the_news: None,
            exploited_by_nessus: None,
            unsupported_by_vendor: None,
            default_account: None,
            user_id: None,
            engagement_id: None,
            policy_id: None,
            scanner_id: None,
        }
    }
}

impl Host {
    pub fn sorted(conn: &mut SqliteConnection, scanner: Option<i32>) -> QueryResult<Vec<Host>> {
        use crate::schema::nessus_hosts::dsl::*;
        let mut query = nessus_hosts.filter(ip.is_not_null()).into_boxed();
        if let Some(sid) = scanner {
            query = query.filter(scanner_id.eq(sid));
        }
        let mut results = query.order(ip.asc()).load::<Host>(conn)?;
        results.sort_by(|a, b| {
            let ia = a.ip.as_ref().and_then(|s| s.parse::<IpAddr>().ok());
            let ib = b.ip.as_ref().and_then(|s| s.parse::<IpAddr>().ok());
            ia.cmp(&ib)
        });
        Ok(results)
    }

    pub fn ip_list(conn: &mut SqliteConnection, scanner: Option<i32>) -> QueryResult<String> {
        let hosts = Host::sorted(conn, scanner)?;
        Ok(hosts
            .into_iter()
            .filter_map(|h| h.ip)
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::MIGRATIONS;
    use crate::schema::nessus_hosts;
    use diesel::sqlite::SqliteConnection;
    use diesel_migrations::MigrationHarness;

    #[derive(Insertable)]
    #[diesel(table_name = nessus_hosts)]
    struct NewHost<'a> {
        ip: Option<&'a str>,
        scanner_id: Option<i32>,
    }

    fn setup() -> SqliteConnection {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        conn.run_pending_migrations(MIGRATIONS).unwrap();
        conn
    }

    #[test]
    fn ip_list_returns_sorted_addresses() {
        let mut conn = setup();
        diesel::insert_into(nessus_hosts::table)
            .values(&[
                NewHost {
                    ip: Some("10.0.0.2"),
                    scanner_id: None,
                },
                NewHost {
                    ip: Some("10.0.0.1"),
                    scanner_id: None,
                },
            ])
            .execute(&mut conn)
            .unwrap();

        let list = Host::ip_list(&mut conn, None).unwrap();
        assert_eq!(list, "10.0.0.1\n10.0.0.2");
    }
}
