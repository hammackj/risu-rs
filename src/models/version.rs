use diesel::prelude::*;

use crate::schema::versions;

#[derive(Debug, Queryable, Identifiable)]
#[diesel(table_name = versions)]
pub struct Version {
    pub id: i32,
    pub version: String,
}

#[derive(Insertable)]
#[diesel(table_name = versions)]
pub struct NewVersion<'a> {
    pub version: &'a str,
}
