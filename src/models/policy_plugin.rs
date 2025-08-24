use diesel::prelude::*;

use crate::schema::nessus_policy_plugins;
use super::Policy;

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Policy, foreign_key = policy_id))]
#[diesel(table_name = nessus_policy_plugins)]
pub struct PolicyPlugin {
    pub id: i32,
    pub policy_id: Option<i32>,
    pub plugin_id: Option<i32>,
    pub plugin_name: Option<String>,
    pub family_name: Option<String>,
    pub status: Option<String>,
}

impl Default for PolicyPlugin {
    fn default() -> Self {
        Self {
            id: 0,
            policy_id: None,
            plugin_id: None,
            plugin_name: None,
            family_name: None,
            status: None,
        }
    }
}
