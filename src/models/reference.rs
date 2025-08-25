use diesel::prelude::*;

use crate::schema::nessus_references;

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(crate::models::Plugin, foreign_key = plugin_id))]
#[diesel(belongs_to(crate::models::Item, foreign_key = item_id))]
#[diesel(table_name = nessus_references)]
pub struct Reference {
    pub id: i32,
    pub plugin_id: Option<i32>,
    pub item_id: Option<i32>,
    pub source: Option<String>,
    pub value: Option<String>,
    pub user_id: Option<i32>,
    pub engagement_id: Option<i32>,
}

impl Default for Reference {
    fn default() -> Self {
        Self {
            id: 0,
            plugin_id: None,
            item_id: None,
            source: None,
            value: None,
            user_id: None,
            engagement_id: None,
        }
    }
}
