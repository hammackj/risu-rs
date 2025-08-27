use std::path::Path;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::error::Error;
use crate::models::{Attachment, Host, Item, Plugin};

use super::NessusReport;

/// Parse a Nessus SQLite export into a [`NessusReport`].
pub fn parse_file(path: &Path) -> Result<NessusReport, Error> {
    let db_path = path
        .to_str()
        .ok_or_else(|| Error::InvalidDocument("invalid path".to_string()))?;
    let mut conn = SqliteConnection::establish(db_path)?;

    use crate::schema::nessus_attachments::dsl as attachments_dsl;
    use crate::schema::nessus_hosts::dsl as hosts_dsl;
    use crate::schema::nessus_items::dsl as items_dsl;
    use crate::schema::nessus_plugins::dsl as plugins_dsl;

    let hosts = hosts_dsl::nessus_hosts.load::<Host>(&mut conn)?;
    let items = items_dsl::nessus_items.load::<Item>(&mut conn)?;
    let plugins = plugins_dsl::nessus_plugins.load::<Plugin>(&mut conn)?;
    let attachments = attachments_dsl::nessus_attachments.load::<Attachment>(&mut conn)?;

    let mut report = NessusReport::default();
    report.version = "sqlite".to_string();
    report.hosts = hosts;
    report.items = items;
    report.plugins = plugins;
    report.attachments = attachments;

    Ok(report)
}
