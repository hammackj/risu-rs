use diesel::prelude::*;

use crate::error::Error;
use crate::models::{
    Attachment, FamilySelection, Host, HostProperty, Item, Patch, Plugin, PluginPreference,
    Policy, PolicyPlugin, Reference, Report, Scanner, ServerPreference, ServiceDescription,
};
use crate::schema;

/// Load a NessusReport from the SQLite database and normalize IDs so in-memory
/// relationships match parser-produced reports (host/item indices rather than DB IDs).
pub fn load_report(
    conn: &mut SqliteConnection,
    report_id_opt: Option<i32>,
) -> Result<crate::parser::NessusReport, Error> {
    use schema::nessus_reports::dsl as rep;
    use schema::nessus_hosts::dsl as hosts;
    use schema::nessus_items::dsl as items;
    use schema::nessus_plugins::dsl as plugs;
    use schema::nessus_attachments::dsl as atts;
    use schema::nessus_host_properties::dsl as hprops;
    use schema::nessus_service_descriptions::dsl as sdesc;
    use schema::nessus_references::dsl as refs;
    use schema::nessus_patches::dsl as patches;
    use schema::scanners::dsl as scn;

    // Pick report id: use provided or latest
    let report_id = match report_id_opt {
        Some(id) => id,
        None => rep::nessus_reports
            .select(rep::id)
            .order(rep::id.desc())
            .first::<i32>(conn)?,
    };

    // Load base Report row
    let db_report: Report = rep::nessus_reports
        .filter(rep::id.eq(report_id))
        .first::<Report>(conn)?;

    // Load hosts for this report
    let mut hosts_db: Vec<Host> = hosts::nessus_hosts
        .filter(hosts::nessus_report_id.eq(report_id))
        .order(hosts::id.asc())
        .load::<Host>(conn)?;

    // Map DB host_id -> index
    let mut host_index_map = std::collections::HashMap::new();
    for (idx, h) in hosts_db.iter_mut().enumerate() {
        host_index_map.insert(h.id, idx as i32);
        h.id = idx as i32; // normalize id to vector index
    }

    // Load plugins for scanner(s) referenced by these hosts/items
    // We may not yet know scanner id; try to get from first host or later items
    let scanner_id_opt = hosts_db
        .iter()
        .filter_map(|h| h.scanner_id)
        .next();

    // Load all plugins for that scanner; if none, load all plugins (fallback)
    let plugins_db: Vec<Plugin> = if let Some(sid) = scanner_id_opt {
        plugs::nessus_plugins
            .filter(plugs::scanner_id.eq(sid))
            .order(plugs::id.asc())
            .load::<Plugin>(conn)?
    } else {
        plugs::nessus_plugins.order(plugs::id.asc()).load::<Plugin>(conn)?
    };

    // Build map: plugin table id (DB) -> external plugin_id
    let mut plugin_db_to_external: std::collections::HashMap<i32, i32> =
        std::collections::HashMap::new();
    for p in &plugins_db {
        if let (Some(db_id), Some(ext)) = (Some(p.id), p.plugin_id) {
            plugin_db_to_external.insert(db_id, ext);
        }
    }

    // Load attachments
    let mut attachments: Vec<Attachment> = atts::nessus_attachments
        .order(atts::id.asc())
        .load::<Attachment>(conn)?;
    let mut attachment_id_map = std::collections::HashMap::new();
    for (idx, a) in attachments.iter_mut().enumerate() {
        attachment_id_map.insert(a.id, idx as i32);
        a.id = idx as i32; // normalize to index
    }

    // Load items related to hosts of this report
    let host_db_ids: Vec<i32> = host_index_map.keys().copied().collect();
    let mut items_db: Vec<Item> = if host_db_ids.is_empty() {
        Vec::new()
    } else {
        items::nessus_items
            .filter(items::host_id.eq_any(&host_db_ids))
            .order(items::id.asc())
            .load::<Item>(conn)?
    };
    // Build map from DB item id -> index in vector
    let mut item_index_map = std::collections::HashMap::new();
    for (idx, it) in items_db.iter_mut().enumerate() {
        // Remap host_id (DB) -> index
        if let Some(db_hid) = it.host_id {
            if let Some(new_idx) = host_index_map.get(&db_hid) {
                it.host_id = Some(*new_idx);
            }
        }
        // Remap plugin_id (DB fk) -> external plugin id
        if let Some(db_pid) = it.plugin_id {
            if let Some(ext) = plugin_db_to_external.get(&db_pid) {
                it.plugin_id = Some(*ext);
            }
        }
        // Remap attachment id (DB) -> index
        if let Some(db_aid) = it.attachment_id {
            if let Some(new_aid) = attachment_id_map.get(&db_aid) {
                it.attachment_id = Some(*new_aid);
            }
        }
        item_index_map.insert(it.id, idx as i32);
        it.id = idx as i32; // normalize id to index
    }

    // Load host properties and remap host_id
    let mut host_properties: Vec<HostProperty> = if host_db_ids.is_empty() {
        Vec::new()
    } else {
        hprops::nessus_host_properties
            .filter(hprops::host_id.eq_any(&host_db_ids))
            .order(hprops::id.asc())
            .load::<HostProperty>(conn)?
    };
    for hp in &mut host_properties {
        if let Some(db_hid) = hp.host_id {
            if let Some(new_idx) = host_index_map.get(&db_hid) {
                hp.host_id = Some(*new_idx);
            }
        }
    }

    // Load service descriptions and remap host_id/item_id
    let mut service_descriptions: Vec<ServiceDescription> = if host_db_ids.is_empty() {
        Vec::new()
    } else {
        sdesc::nessus_service_descriptions
            .filter(sdesc::host_id.eq_any(&host_db_ids))
            .order(sdesc::id.asc())
            .load::<ServiceDescription>(conn)?
    };
    for sd in &mut service_descriptions {
        if let Some(db_hid) = sd.host_id {
            if let Some(new_idx) = host_index_map.get(&db_hid) {
                sd.host_id = Some(*new_idx);
            }
        }
        if let Some(db_iid) = sd.item_id {
            if let Some(new_idx) = item_index_map.get(&db_iid) {
                sd.item_id = Some(*new_idx);
            }
        }
    }

    // Load references and remap plugin_id (db->external) and item_id (db->index)
    let mut references: Vec<Reference> = if host_db_ids.is_empty() {
        refs::nessus_references.order(refs::id.asc()).load::<Reference>(conn)?
    } else {
        refs::nessus_references.order(refs::id.asc()).load::<Reference>(conn)?
    };
    for r in &mut references {
        if let Some(db_iid) = r.item_id {
            if let Some(new_idx) = item_index_map.get(&db_iid) {
                r.item_id = Some(*new_idx);
            }
        }
        if let Some(db_pid) = r.plugin_id {
            if let Some(ext) = plugin_db_to_external.get(&db_pid) {
                r.plugin_id = Some(*ext);
            }
        }
    }

    // Load patches and remap host_id
    let mut patches_vec: Vec<Patch> = if host_db_ids.is_empty() {
        Vec::new()
    } else {
        patches::nessus_patches
            .filter(patches::host_id.eq_any(&host_db_ids))
            .order(patches::id.asc())
            .load::<Patch>(conn)?
    };
    for p in &mut patches_vec {
        if let Some(db_hid) = p.host_id {
            if let Some(new_idx) = host_index_map.get(&db_hid) {
                p.host_id = Some(*new_idx);
            }
        }
    }

    // Choose scanner
    let scanner = if let Some(sid) = scanner_id_opt
        .or_else(|| items_db.iter().filter_map(|i| i.scanner_id).next())
        .or_else(|| plugins_db.iter().filter_map(|p| p.scanner_id).next())
    {
        scn::scanners
            .filter(scn::id.eq(sid))
            .first::<Scanner>(conn)
            .unwrap_or_default()
    } else {
        Scanner::default()
    };

    // Build final report
    let mut report = crate::parser::NessusReport {
        report: db_report,
        version: "".into(),
        hosts: hosts_db,
        items: items_db,
        plugins: plugins_db,
        patches: patches_vec,
        attachments,
        host_properties,
        service_descriptions,
        references,
        policies: Vec::new(),
        policy_plugins: Vec::new(),
        family_selections: Vec::new(),
        plugin_preferences: Vec::new(),
        server_preferences: Vec::new(),
        scanner,
        filters: crate::parser::Filters::default(),
    };
    // Propagate scanner id to entries
    let sc_type = report.scanner.scanner_type.clone();
    let sc_ver = report.scanner.scanner_version.clone();
    report.set_scanner(&sc_type, sc_ver);
    Ok(report)
}
