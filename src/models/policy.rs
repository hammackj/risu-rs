use diesel::prelude::*;
use crate::schema::nessus_policies;

#[derive(Debug, Queryable, Identifiable)]
#[diesel(table_name = nessus_policies)]
pub struct Policy {
    pub id: i32,
    pub name: Option<String>,
    pub comments: Option<String>,
    pub owner: Option<String>,
    pub visibility: Option<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            id: 0,
            name: None,
            comments: None,
            owner: None,
            visibility: None,
        }
    }
}
