use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::schema::nessus_plugin_metadata;

#[derive(Debug, Queryable, Identifiable)]
#[diesel(table_name = nessus_plugin_metadata)]
pub struct NessusPluginMetadata {
    pub id: i32,
    pub script_id: Option<i32>,
    pub script_name: Option<String>,
    pub cve: Option<String>,
    pub bid: Option<String>,
}

impl Default for NessusPluginMetadata {
    fn default() -> Self {
        Self {
            id: 0,
            script_id: None,
            script_name: None,
            cve: None,
            bid: None,
        }
    }
}

impl NessusPluginMetadata {
    pub fn by_plugin_id(conn: &mut SqliteConnection, pid: i32) -> QueryResult<Option<Self>> {
        use crate::schema::nessus_plugin_metadata::dsl::*;
        nessus_plugin_metadata
            .filter(script_id.eq(pid))
            .first::<NessusPluginMetadata>(conn)
            .optional()
    }
}
