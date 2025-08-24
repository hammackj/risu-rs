//! Database models representing parsed Nessus data.
//!
//! The models map directly to tables created by Diesel migrations and are used
//! by the parser and CLI. Only a subset of the original Ruby models are
//! implemented at the moment.

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use std::net::IpAddr;

use crate::schema::{
    nessus_host_properties, nessus_hosts, nessus_items, nessus_patches, nessus_plugins,
    nessus_service_descriptions,
};

#[derive(Debug, Queryable, Identifiable)]
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
}

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Host, foreign_key = host_id))]
#[diesel(table_name = nessus_host_properties)]
pub struct HostProperty {
    pub id: i32,
    pub host_id: Option<i32>,
    pub name: Option<String>,
    pub value: Option<String>,
    pub user_id: Option<i32>,
    pub engagement_id: Option<i32>,
}

impl Default for HostProperty {
    fn default() -> Self {
        Self {
            id: 0,
            host_id: None,
            name: None,
            value: None,
            user_id: None,
            engagement_id: None,
        }
    }
}

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Host, foreign_key = host_id))]
#[diesel(belongs_to(Plugin, foreign_key = plugin_id))]
#[diesel(table_name = nessus_items)]
pub struct Item {
    pub id: i32,
    pub host_id: Option<i32>,
    pub plugin_id: Option<i32>,
    pub attachment_id: Option<i32>,
    pub plugin_output: Option<String>,
    pub port: Option<i32>,
    pub svc_name: Option<String>,
    pub protocol: Option<String>,
    pub severity: Option<i32>,
    pub plugin_name: Option<String>,
    pub verified: Option<bool>,
    pub cm_compliance_info: Option<String>,
    pub cm_compliance_actual_value: Option<String>,
    pub cm_compliance_check_id: Option<String>,
    pub cm_compliance_policy_value: Option<String>,
    pub cm_compliance_audit_file: Option<String>,
    pub cm_compliance_check_name: Option<String>,
    pub cm_compliance_result: Option<String>,
    pub cm_compliance_output: Option<String>,
    pub cm_compliance_reference: Option<String>,
    pub cm_compliance_see_also: Option<String>,
    pub cm_compliance_solution: Option<String>,
    pub real_severity: Option<i32>,
    pub risk_score: Option<i32>,
    pub user_id: Option<i32>,
    pub engagement_id: Option<i32>,
}

impl Default for Item {
    fn default() -> Self {
        Self {
            id: 0,
            host_id: None,
            plugin_id: None,
            attachment_id: None,
            plugin_output: None,
            port: None,
            svc_name: None,
            protocol: None,
            severity: None,
            plugin_name: None,
            verified: None,
            cm_compliance_info: None,
            cm_compliance_actual_value: None,
            cm_compliance_check_id: None,
            cm_compliance_policy_value: None,
            cm_compliance_audit_file: None,
            cm_compliance_check_name: None,
            cm_compliance_result: None,
            cm_compliance_output: None,
            cm_compliance_reference: None,
            cm_compliance_see_also: None,
            cm_compliance_solution: None,
            real_severity: None,
            risk_score: None,
            user_id: None,
            engagement_id: None,
        }
    }
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
}

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Host, foreign_key = host_id))]
#[diesel(table_name = nessus_patches)]
pub struct Patch {
    pub id: i32,
    pub host_id: Option<i32>,
    pub name: Option<String>,
    pub value: Option<String>,
    pub user_id: Option<i32>,
    pub engagement_id: Option<i32>,
}

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Host, foreign_key = host_id))]
#[diesel(belongs_to(Item, foreign_key = item_id))]
#[diesel(table_name = nessus_service_descriptions)]
pub struct ServiceDescription {
    pub id: i32,
    pub host_id: Option<i32>,
    pub item_id: Option<i32>,
    pub name: Option<String>,
    pub port: Option<i32>,
    pub protocol: Option<String>,
    pub description: Option<String>,
    pub user_id: Option<i32>,
    pub engagement_id: Option<i32>,
}

impl Default for ServiceDescription {
    fn default() -> Self {
        Self {
            id: 0,
            host_id: None,
            item_id: None,
            name: None,
            port: None,
            protocol: None,
            description: None,
            user_id: None,
            engagement_id: None,
        }
    }
}

impl Default for Patch {
    fn default() -> Self {
        Self {
            id: 0,
            host_id: None,
            name: None,
            value: None,
            user_id: None,
            engagement_id: None,
        }
    }
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
        }
    }
}

impl Host {
    pub fn sorted(conn: &mut SqliteConnection) -> QueryResult<Vec<Host>> {
        use crate::schema::nessus_hosts::dsl::*;
        let mut results = nessus_hosts
            .filter(ip.is_not_null())
            .order(ip.asc())
            .load::<Host>(conn)?;
        results.sort_by(|a, b| {
            let ia = a.ip.as_ref().and_then(|s| s.parse::<IpAddr>().ok());
            let ib = b.ip.as_ref().and_then(|s| s.parse::<IpAddr>().ok());
            ia.cmp(&ib)
        });
        Ok(results)
    }

    pub fn ip_list(conn: &mut SqliteConnection) -> QueryResult<String> {
        let hosts = Host::sorted(conn)?;
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
                },
                NewHost {
                    ip: Some("10.0.0.1"),
                },
            ])
            .execute(&mut conn)
            .unwrap();

        let list = Host::ip_list(&mut conn).unwrap();
        assert_eq!(list, "10.0.0.1\n10.0.0.2");
    }
}
