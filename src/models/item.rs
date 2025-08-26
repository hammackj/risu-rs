use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::schema::nessus_items;

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(super::Host, foreign_key = host_id))]
#[diesel(belongs_to(super::Plugin, foreign_key = plugin_id))]
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
    pub description: Option<String>,
    pub solution: Option<String>,
    pub risk_factor: Option<String>,
    pub cvss_base_score: Option<f32>,
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
    pub rollup_finding: Option<bool>,
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
            description: None,
            solution: None,
            risk_factor: None,
            cvss_base_score: None,
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
            rollup_finding: Some(false),
        }
    }
}

impl Item {
    pub fn search_plugin_output(
        conn: &mut SqliteConnection,
        keyword: &str,
    ) -> QueryResult<Vec<Self>> {
        use crate::schema::nessus_items::dsl::*;

        let pattern = format!("%{}%", keyword);
        nessus_items
            .filter(plugin_output.is_not_null())
            .filter(plugin_output.like(pattern))
            .load::<Item>(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::MIGRATIONS;
    use crate::schema::nessus_items;
    use diesel::sqlite::SqliteConnection;
    use diesel_migrations::MigrationHarness;

    #[derive(Insertable)]
    #[diesel(table_name = nessus_items)]
    struct NewItem<'a> {
        host_id: Option<i32>,
        plugin_id: Option<i32>,
        plugin_output: Option<&'a str>,
        plugin_name: Option<&'a str>,
    }

    fn setup() -> SqliteConnection {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        conn.run_pending_migrations(MIGRATIONS).unwrap();
        conn
    }

    #[test]
    fn search_case_insensitive() {
        let mut conn = setup();

        let entries = vec![
            NewItem {
                host_id: None,
                plugin_id: None,
                plugin_output: Some("foo"),
                plugin_name: Some("A"),
            },
            NewItem {
                host_id: None,
                plugin_id: None,
                plugin_output: Some("FoO"),
                plugin_name: Some("B"),
            },
        ];

        diesel::insert_into(nessus_items::table)
            .values(&entries)
            .execute(&mut conn)
            .unwrap();

        let lower = Item::search_plugin_output(&mut conn, "foo").unwrap();
        assert_eq!(lower.len(), 2);
        let upper = Item::search_plugin_output(&mut conn, "FOO").unwrap();
        assert_eq!(upper.len(), 2);
    }
}
