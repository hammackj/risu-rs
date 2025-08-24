use super::policy::Policy;
use crate::schema::nessus_plugins_preferences;
use diesel::prelude::*;

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Policy))]
#[diesel(table_name = nessus_plugins_preferences)]
pub struct PluginsPreference {
    pub id: i32,
    pub policy_id: Option<i32>,
    pub plugin_name: Option<String>,
    pub plugin_id: Option<i32>,
    pub full_name: Option<String>,
    pub preference_name: Option<String>,
    pub preference_type: Option<String>,
    pub preference_values: Option<String>,
    pub selected_values: Option<String>,
}

impl Default for PluginsPreference {
    fn default() -> Self {
        Self {
            id: 0,
            policy_id: None,
            plugin_name: None,
            plugin_id: None,
            full_name: None,
            preference_name: None,
            preference_type: None,
            preference_values: None,
            selected_values: None,
        }
    }
}
