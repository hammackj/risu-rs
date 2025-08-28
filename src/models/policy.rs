use diesel::prelude::*;

use crate::models::Report;
use crate::schema::nessus_policies;

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Report, foreign_key = nessus_report_id))]
#[diesel(table_name = nessus_policies)]
pub struct Policy {
    pub id: i32,
    pub nessus_report_id: Option<i32>,
    pub name: Option<String>,
    pub comments: Option<String>,
    pub owner: Option<String>,
    pub visibility: Option<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            id: 0,
            nessus_report_id: None,
            name: None,
            comments: None,
            owner: None,
            visibility: None,
        }
    }
}
