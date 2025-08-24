use diesel::prelude::*;

use crate::models::Host;
use crate::schema::nessus_host_properties;

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
