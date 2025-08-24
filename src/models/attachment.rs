use diesel::prelude::*;

use crate::schema::nessus_attachments;

#[derive(Debug, Queryable, Identifiable)]
#[diesel(table_name = nessus_attachments)]
pub struct Attachment {
    pub id: i32,
    pub name: Option<String>,
    pub content_type: Option<String>,
    pub path: Option<String>,
    pub size: Option<i32>,
}

impl Default for Attachment {
    fn default() -> Self {
        Self {
            id: 0,
            name: None,
            content_type: None,
            path: None,
            size: None,
        }
    }
}
