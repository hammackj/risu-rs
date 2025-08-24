use diesel::prelude::*;

use crate::models::{Host, Item};
use crate::schema::nessus_service_descriptions;

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Host, foreign_key = host_id))]
#[diesel(belongs_to(Item, foreign_key = item_id))]
#[diesel(table_name = nessus_service_descriptions)]
pub struct ServiceDescription {
    pub id: i32,
    pub host_id: Option<i32>,
    pub item_id: Option<i32>,
    pub port: Option<i32>,
    pub svc_name: Option<String>,
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
            port: None,
            svc_name: None,
            protocol: None,
            description: None,
            user_id: None,
            engagement_id: None,
        }
    }
}
