use diesel::prelude::*;

use crate::schema::nessus_plugin_preferences;
use super::Policy;

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Policy, foreign_key = policy_id))]
#[diesel(table_name = nessus_plugin_preferences)]
pub struct PluginPreference {
    pub id: i32,
    pub policy_id: Option<i32>,
    pub plugin_id: Option<i32>,
    pub fullname: Option<String>,
    pub preference_name: Option<String>,
    pub preference_type: Option<String>,
    pub selected_value: Option<String>,
}

impl Default for PluginPreference {
    fn default() -> Self {
        Self {
            id: 0,
            policy_id: None,
            plugin_id: None,
            fullname: None,
            preference_name: None,
            preference_type: None,
            selected_value: None,
        }
    }
}
