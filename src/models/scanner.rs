use diesel::prelude::*;

use crate::schema::scanners;

#[derive(Debug, Queryable, Identifiable)]
#[diesel(table_name = scanners)]
pub struct Scanner {
    pub id: i32,
    pub scanner_type: String,
    pub scanner_version: Option<String>,
}

#[derive(Insertable)]
#[diesel(table_name = scanners)]
pub struct NewScanner<'a> {
    pub scanner_type: &'a str,
    pub scanner_version: Option<&'a str>,
}

impl Default for Scanner {
    fn default() -> Self {
        Self {
            id: 0,
            scanner_type: String::new(),
            scanner_version: None,
        }
    }
}
