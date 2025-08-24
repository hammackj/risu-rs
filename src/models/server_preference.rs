use diesel::prelude::*;

use crate::schema::nessus_server_preferences;
use super::Policy;

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Policy, foreign_key = policy_id))]
#[diesel(table_name = nessus_server_preferences)]
pub struct ServerPreference {
    pub id: i32,
    pub policy_id: Option<i32>,
    pub name: Option<String>,
    pub value: Option<String>,
}

impl Default for ServerPreference {
    fn default() -> Self {
        Self { id: 0, policy_id: None, name: None, value: None }
    }
}
