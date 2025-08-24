use diesel::prelude::*;
use crate::schema::nessus_individual_plugin_selections;
use super::policy::Policy;

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Policy))]
#[diesel(table_name = nessus_individual_plugin_selections)]
pub struct IndividualPluginSelection {
    pub id: i32,
    pub policy_id: Option<i32>,
    pub plugin_id: Option<i32>,
    pub plugin_name: Option<String>,
    pub family: Option<String>,
    pub status: Option<String>,
}

impl Default for IndividualPluginSelection {
    fn default() -> Self {
        Self {
            id: 0,
            policy_id: None,
            plugin_id: None,
            plugin_name: None,
            family: None,
            status: None,
        }
    }
}
