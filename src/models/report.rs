use diesel::prelude::*;

use crate::models::Host;
use crate::schema::nessus_reports;

#[derive(Debug, Queryable, Identifiable)]
#[diesel(table_name = nessus_reports)]
pub struct Report {
    pub id: i32,
    pub title: Option<String>,
    pub author: Option<String>,
    pub company: Option<String>,
    pub classification: Option<String>,
    pub user_id: Option<i32>,
    pub engagement_id: Option<i32>,
}

impl Report {
    /// Returns the earliest start time across all hosts in the report.
    pub fn scan_date(&self, hosts: &[Host]) -> Option<chrono::NaiveDateTime> {
        hosts.iter().filter_map(|h| h.start).min()
    }

    /// Static text describing Nessus severity ratings.
    pub fn scanner_nessus_ratings_text(&self) -> &'static str {
        "Nessus severity ratings: 0 (Info), 1 (Low), 2 (Medium), 3 (High), 4 (Critical)."
    }
}

impl Default for Report {
    fn default() -> Self {
        Self {
            id: 0,
            title: None,
            author: None,
            company: None,
            classification: None,
            user_id: None,
            engagement_id: None,
        }
    }
}
