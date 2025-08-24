use diesel::prelude::*;
use crate::schema::nessus_family_selections;
use super::policy::Policy;

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Policy))]
#[diesel(table_name = nessus_family_selections)]
pub struct FamilySelection {
    pub id: i32,
    pub policy_id: Option<i32>,
    pub family_name: Option<String>,
    pub status: Option<String>,
}

impl Default for FamilySelection {
    fn default() -> Self {
        Self {
            id: 0,
            policy_id: None,
            family_name: None,
            status: None,
        }
    }
}
