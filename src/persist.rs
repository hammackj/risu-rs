use diesel::prelude::*;
use diesel::sql_types::BigInt;

use crate::error::Error;
use crate::models::{
    Attachment, FamilySelection, Host, HostProperty, Item, Patch, Plugin, PluginPreference,
    Policy, PolicyPlugin, Reference, Report, Scanner, ServerPreference, ServiceDescription,
};
use crate::schema;

#[derive(QueryableByName)]
struct LastId {
    #[diesel(sql_type = BigInt)]
    id: i64,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_reports)]
struct NewReport<'a> {
    title: Option<&'a str>,
    author: Option<&'a str>,
    company: Option<&'a str>,
    classification: Option<&'a str>,
    user_id: Option<i32>,
    engagement_id: Option<i32>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::scanners)]
struct NewScanner<'a> {
    scanner_type: &'a str,
    scanner_version: Option<&'a str>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_hosts)]
struct NewHost<'a> {
    nessus_report_id: Option<i32>,
    name: Option<&'a str>,
    os: Option<&'a str>,
    mac: Option<&'a str>,
    start: Option<chrono::NaiveDateTime>,
    end: Option<chrono::NaiveDateTime>,
    ip: Option<&'a str>,
    fqdn: Option<&'a str>,
    netbios: Option<&'a str>,
    notes: Option<&'a str>,
    risk_score: Option<i32>,
    user_id: Option<i32>,
    engagement_id: Option<i32>,
    scanner_id: Option<i32>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_plugins)]
struct NewPlugin<'a> {
    plugin_id: Option<i32>,
    plugin_name: Option<&'a str>,
    family_name: Option<&'a str>,
    description: Option<&'a str>,
    plugin_version: Option<&'a str>,
    plugin_publication_date: Option<chrono::NaiveDateTime>,
    plugin_modification_date: Option<chrono::NaiveDateTime>,
    vuln_publication_date: Option<chrono::NaiveDateTime>,
    cvss_vector: Option<&'a str>,
    cvss_base_score: Option<f32>,
    cvss_temporal_score: Option<&'a str>,
    cvss_temporal_vector: Option<&'a str>,
    exploitability_ease: Option<&'a str>,
    exploit_framework_core: Option<&'a str>,
    exploit_framework_metasploit: Option<&'a str>,
    metasploit_name: Option<&'a str>,
    exploit_framework_canvas: Option<&'a str>,
    canvas_package: Option<&'a str>,
    exploit_available: Option<&'a str>,
    risk_factor: Option<&'a str>,
    solution: Option<&'a str>,
    synopsis: Option<&'a str>,
    plugin_type: Option<&'a str>,
    exploit_framework_exploithub: Option<&'a str>,
    exploithub_sku: Option<&'a str>,
    stig_severity: Option<&'a str>,
    fname: Option<&'a str>,
    always_run: Option<&'a str>,
    script_version: Option<&'a str>,
    d2_elliot_name: Option<&'a str>,
    exploit_framework_d2_elliot: Option<&'a str>,
    exploited_by_malware: Option<&'a str>,
    rollup: Option<bool>,
    risk_score: Option<i32>,
    compliance: Option<&'a str>,
    root_cause: Option<&'a str>,
    agent: Option<&'a str>,
    potential_vulnerability: Option<bool>,
    in_the_news: Option<bool>,
    exploited_by_nessus: Option<bool>,
    unsupported_by_vendor: Option<bool>,
    default_account: Option<bool>,
    user_id: Option<i32>,
    engagement_id: Option<i32>,
    policy_id: Option<i32>,
    scanner_id: Option<i32>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_attachments)]
struct NewAttachment<'a> {
    name: Option<&'a str>,
    content_type: Option<&'a str>,
    path: Option<&'a str>,
    size: Option<i32>,
    ahash: Option<&'a str>,
    value: Option<&'a str>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_items)]
struct NewItem<'a> {
    host_id: Option<i32>,
    plugin_id: Option<i32>,
    attachment_id: Option<i32>,
    plugin_output: Option<&'a str>,
    port: Option<i32>,
    svc_name: Option<&'a str>,
    protocol: Option<&'a str>,
    severity: Option<i32>,
    plugin_name: Option<&'a str>,
    description: Option<&'a str>,
    solution: Option<&'a str>,
    risk_factor: Option<&'a str>,
    cvss_base_score: Option<f32>,
    plugin_version: Option<&'a str>,
    plugin_publication_date: Option<chrono::NaiveDateTime>,
    plugin_modification_date: Option<chrono::NaiveDateTime>,
    vuln_publication_date: Option<chrono::NaiveDateTime>,
    cvss_vector: Option<&'a str>,
    cvss_temporal_score: Option<&'a str>,
    cvss_temporal_vector: Option<&'a str>,
    exploitability_ease: Option<&'a str>,
    synopsis: Option<&'a str>,
    exploit_framework_core: Option<&'a str>,
    exploit_framework_metasploit: Option<&'a str>,
    exploit_framework_canvas: Option<&'a str>,
    exploit_framework_exploithub: Option<&'a str>,
    exploit_framework_d2_elliot: Option<&'a str>,
    verified: Option<bool>,
    cm_compliance_info: Option<&'a str>,
    cm_compliance_actual_value: Option<&'a str>,
    cm_compliance_check_id: Option<&'a str>,
    cm_compliance_policy_value: Option<&'a str>,
    cm_compliance_audit_file: Option<&'a str>,
    cm_compliance_check_name: Option<&'a str>,
    cm_compliance_result: Option<&'a str>,
    cm_compliance_output: Option<&'a str>,
    cm_compliance_reference: Option<&'a str>,
    cm_compliance_see_also: Option<&'a str>,
    cm_compliance_solution: Option<&'a str>,
    real_severity: Option<i32>,
    risk_score: Option<i32>,
    user_id: Option<i32>,
    engagement_id: Option<i32>,
    rollup_finding: Option<bool>,
    scanner_id: Option<i32>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_host_properties)]
struct NewHostProperty<'a> {
    host_id: Option<i32>,
    name: Option<&'a str>,
    value: Option<&'a str>,
    user_id: Option<i32>,
    engagement_id: Option<i32>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_service_descriptions)]
struct NewServiceDescription<'a> {
    host_id: Option<i32>,
    item_id: Option<i32>,
    port: Option<i32>,
    svc_name: Option<&'a str>,
    protocol: Option<&'a str>,
    description: Option<&'a str>,
    user_id: Option<i32>,
    engagement_id: Option<i32>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_references)]
struct NewReference<'a> {
    plugin_id: Option<i32>,
    item_id: Option<i32>,
    source: Option<&'a str>,
    value: Option<&'a str>,
    user_id: Option<i32>,
    engagement_id: Option<i32>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_patches)]
struct NewPatch<'a> {
    host_id: Option<i32>,
    name: Option<&'a str>,
    value: Option<&'a str>,
    user_id: Option<i32>,
    engagement_id: Option<i32>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_policies)]
struct NewPolicy<'a> {
    nessus_report_id: Option<i32>,
    name: Option<&'a str>,
    comments: Option<&'a str>,
    owner: Option<&'a str>,
    visibility: Option<&'a str>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_policy_plugins)]
struct NewPolicyPlugin<'a> {
    policy_id: Option<i32>,
    plugin_id: Option<i32>,
    plugin_name: Option<&'a str>,
    family_name: Option<&'a str>,
    status: Option<&'a str>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_family_selections)]
struct NewFamilySelection<'a> {
    policy_id: Option<i32>,
    family_name: Option<&'a str>,
    status: Option<&'a str>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_plugin_preferences)]
struct NewPluginPreference<'a> {
    policy_id: Option<i32>,
    plugin_id: Option<i32>,
    fullname: Option<&'a str>,
    preference_name: Option<&'a str>,
    preference_type: Option<&'a str>,
    selected_value: Option<&'a str>,
    preference_values: Option<&'a str>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::nessus_server_preferences)]
struct NewServerPreference<'a> {
    policy_id: Option<i32>,
    name: Option<&'a str>,
    value: Option<&'a str>,
}

pub fn to_sqlite(conn: &mut SqliteConnection, report: &crate::parser::NessusReport) -> Result<(), Error> {
    conn.transaction(|conn| {
        use schema::*;
        use schema::scanners::dsl as scn;
        use schema::nessus_reports::dsl as rep;
        use schema::nessus_hosts::dsl as hosts;
        use schema::nessus_plugins::dsl as plugins;
        use schema::nessus_attachments::dsl as attach;
        use schema::nessus_items::dsl as items;
        use schema::nessus_host_properties::dsl as hprops;
        use schema::nessus_service_descriptions::dsl as sdesc;
        use schema::nessus_references::dsl as refs;
        use schema::nessus_patches::dsl as patches;
        use schema::nessus_policies::dsl as pols;
        use schema::nessus_policy_plugins::dsl as polplugs;
        use schema::nessus_family_selections::dsl as famsel;
        use schema::nessus_plugin_preferences::dsl as plgprefs;
        use schema::nessus_server_preferences::dsl as srvprefs;

        // 1) Scanner upsert (by type + version)
        let scanner_type = report.scanner.scanner_type.as_str();
        let scanner_version = report.scanner.scanner_version.as_deref();
        let scanner_id: i32 = if let Some(ver) = scanner_version {
            scn::scanners
                .filter(scn::scanner_type.eq(scanner_type))
                .filter(scn::scanner_version.eq(ver))
                .select(scn::id)
                .first::<i32>(conn)
                .optional()?
                .unwrap_or_else(|| {
                    diesel::insert_into(scn::scanners)
                        .values(NewScanner { scanner_type, scanner_version })
                        .execute(conn)
                        .expect("insert scanner");
                    diesel::sql_query("SELECT last_insert_rowid() AS id")
                        .get_result::<LastId>(conn)
                        .expect("last id").id as i32
                })
        } else {
            scn::scanners
                .filter(scn::scanner_type.eq(scanner_type))
                .filter(scn::scanner_version.is_null())
                .select(scn::id)
                .first::<i32>(conn)
                .optional()?
                .unwrap_or_else(|| {
                    diesel::insert_into(scn::scanners)
                        .values(NewScanner { scanner_type, scanner_version })
                        .execute(conn)
                        .expect("insert scanner");
                    diesel::sql_query("SELECT last_insert_rowid() AS id")
                        .get_result::<LastId>(conn)
                        .expect("last id").id as i32
                })
        };

        // 2) Report row
        diesel::insert_into(rep::nessus_reports)
            .values(NewReport {
                title: report.report.title.as_deref(),
                author: report.report.author.as_deref(),
                company: report.report.company.as_deref(),
                classification: report.report.classification.as_deref(),
                user_id: None,
                engagement_id: None,
            })
            .execute(conn)?;
        let report_id = diesel::sql_query("SELECT last_insert_rowid() AS id")
            .get_result::<LastId>(conn)?
            .id as i32;

        // 3) Hosts (batch insert, then fetch ids in order)
        let new_hosts: Vec<NewHost> = report
            .hosts
            .iter()
            .map(|h| NewHost {
                nessus_report_id: Some(report_id),
                name: h.name.as_deref(),
                os: h.os.as_deref(),
                mac: h.mac.as_deref(),
                start: h.start,
                end: h.end,
                ip: h.ip.as_deref(),
                fqdn: h.fqdn.as_deref(),
                netbios: h.netbios.as_deref(),
                notes: h.notes.as_deref(),
                risk_score: h.risk_score,
                user_id: None,
                engagement_id: None,
                scanner_id: Some(scanner_id),
            })
            .collect();
        if !new_hosts.is_empty() {
            diesel::insert_into(hosts::nessus_hosts)
                .values(&new_hosts)
                .execute(conn)?;
        }
        let host_ids: Vec<i32> = hosts::nessus_hosts
            .filter(hosts::nessus_report_id.eq(report_id))
            .order(hosts::id.asc())
            .select(hosts::id)
            .load::<i32>(conn)?;

        // 4) Plugins: build map external plugin_id -> db id
        use std::collections::HashMap;
        let mut plugin_id_map: HashMap<i32, i32> = HashMap::new();
        let ext_ids: Vec<i32> = report
            .plugins
            .iter()
            .filter_map(|p| p.plugin_id)
            .collect();
        if !ext_ids.is_empty() {
            // existing
            for (pid, id) in plugins::nessus_plugins
                .filter(plugins::scanner_id.eq(scanner_id))
                .filter(plugins::plugin_id.eq_any(&ext_ids))
                .select((plugins::plugin_id, plugins::id))
                .load::<(Option<i32>, i32)>(conn)?
                .into_iter()
                .filter_map(|(pid, id)| pid.map(|p| (p, id)))
            {
                plugin_id_map.insert(pid, id);
            }
            // insert missing
            let missing: Vec<&Plugin> = report
                .plugins
                .iter()
                .filter(|p| p.plugin_id.and_then(|pid| plugin_id_map.get(&pid).cloned()).is_none())
                .collect();
            let to_insert: Vec<NewPlugin> = missing
                .iter()
                .map(|p| NewPlugin {
                    plugin_id: p.plugin_id,
                    plugin_name: p.plugin_name.as_deref(),
                    family_name: p.family_name.as_deref(),
                    description: p.description.as_deref(),
                    plugin_version: p.plugin_version.as_deref(),
                    plugin_publication_date: p.plugin_publication_date,
                    plugin_modification_date: p.plugin_modification_date,
                    vuln_publication_date: p.vuln_publication_date,
                    cvss_vector: p.cvss_vector.as_deref(),
                    cvss_base_score: p.cvss_base_score,
                    cvss_temporal_score: p.cvss_temporal_score.as_deref(),
                    cvss_temporal_vector: p.cvss_temporal_vector.as_deref(),
                    exploitability_ease: p.exploitability_ease.as_deref(),
                    exploit_framework_core: p.exploit_framework_core.as_deref(),
                    exploit_framework_metasploit: p.exploit_framework_metasploit.as_deref(),
                    metasploit_name: p.metasploit_name.as_deref(),
                    exploit_framework_canvas: p.exploit_framework_canvas.as_deref(),
                    canvas_package: p.canvas_package.as_deref(),
                    exploit_available: p.exploit_available.as_deref(),
                    risk_factor: p.risk_factor.as_deref(),
                    solution: p.solution.as_deref(),
                    synopsis: p.synopsis.as_deref(),
                    plugin_type: p.plugin_type.as_deref(),
                    exploit_framework_exploithub: p.exploit_framework_exploithub.as_deref(),
                    exploithub_sku: p.exploithub_sku.as_deref(),
                    stig_severity: p.stig_severity.as_deref(),
                    fname: p.fname.as_deref(),
                    always_run: p.always_run.as_deref(),
                    script_version: p.script_version.as_deref(),
                    d2_elliot_name: p.d2_elliot_name.as_deref(),
                    exploit_framework_d2_elliot: p.exploit_framework_d2_elliot.as_deref(),
                    exploited_by_malware: p.exploited_by_malware.as_deref(),
                    rollup: p.rollup,
                    risk_score: p.risk_score,
                    compliance: p.compliance.as_deref(),
                    root_cause: p.root_cause.as_deref(),
                    agent: p.agent.as_deref(),
                    potential_vulnerability: p.potential_vulnerability,
                    in_the_news: p.in_the_news,
                    exploited_by_nessus: p.exploited_by_nessus,
                    unsupported_by_vendor: p.unsupported_by_vendor,
                    default_account: p.default_account,
                    user_id: None,
                    engagement_id: None,
                    policy_id: None,
                    scanner_id: Some(scanner_id),
                })
                .collect();
            if !to_insert.is_empty() {
                diesel::insert_into(plugins::nessus_plugins)
                    .values(&to_insert)
                    .execute(conn)?;
                // refresh map
                for (pid, id) in plugins::nessus_plugins
                    .filter(plugins::scanner_id.eq(scanner_id))
                    .filter(plugins::plugin_id.eq_any(&ext_ids))
                    .select((plugins::plugin_id, plugins::id))
                    .load::<(Option<i32>, i32)>(conn)?
                    .into_iter()
                    .filter_map(|(pid, id)| pid.map(|p| (p, id)))
                {
                    plugin_id_map.insert(pid, id);
                }
            }
        }

        // 5) Attachments: upsert by ahash
        let mut attachment_id_map: Vec<Option<i32>> = vec![None; report.attachments.len()];
        for (idx, a) in report.attachments.iter().enumerate() {
            if let Some(hash) = a.ahash.as_deref() {
                if let Some(id) = attach::nessus_attachments
                    .filter(attach::ahash.eq(hash))
                    .select(attach::id)
                    .first::<i32>(conn)
                    .optional()? {
                    attachment_id_map[idx] = Some(id);
                } else {
                    diesel::insert_into(attach::nessus_attachments)
                        .values(NewAttachment {
                            name: a.name.as_deref(),
                            content_type: a.content_type.as_deref(),
                            path: a.path.as_deref(),
                            size: a.size,
                            ahash: a.ahash.as_deref(),
                            value: a.value.as_deref(),
                        })
                        .execute(conn)?;
                    let id = diesel::sql_query("SELECT last_insert_rowid() AS id")
                        .get_result::<LastId>(conn)?
                        .id as i32;
                    attachment_id_map[idx] = Some(id);
                }
            }
        }

        // 6) Items one-by-one to get id map
        let mut item_id_map: Vec<Option<i32>> = vec![None; report.items.len()];
        for (idx, it) in report.items.iter().enumerate() {
            let host_db_id = it.host_id.and_then(|hid| host_ids.get(hid as usize).copied());
            let plugin_db_id = it
                .plugin_id
                .and_then(|pid| plugin_id_map.get(&pid).copied());
            let attachment_db_id = it
                .attachment_id
                .and_then(|aid| attachment_id_map.get(aid as usize).copied().flatten());
            diesel::insert_into(items::nessus_items)
                .values(NewItem {
                    host_id: host_db_id,
                    plugin_id: plugin_db_id,
                    attachment_id: attachment_db_id,
                    plugin_output: it.plugin_output.as_deref(),
                    port: it.port,
                    svc_name: it.svc_name.as_deref(),
                    protocol: it.protocol.as_deref(),
                    severity: it.severity,
                    plugin_name: it.plugin_name.as_deref(),
                    description: it.description.as_deref(),
                    solution: it.solution.as_deref(),
                    risk_factor: it.risk_factor.as_deref(),
                    cvss_base_score: it.cvss_base_score,
                    plugin_version: it.plugin_version.as_deref(),
                    plugin_publication_date: it.plugin_publication_date,
                    plugin_modification_date: it.plugin_modification_date,
                    vuln_publication_date: it.vuln_publication_date,
                    cvss_vector: it.cvss_vector.as_deref(),
                    cvss_temporal_score: it.cvss_temporal_score.as_deref(),
                    cvss_temporal_vector: it.cvss_temporal_vector.as_deref(),
                    exploitability_ease: it.exploitability_ease.as_deref(),
                    synopsis: it.synopsis.as_deref(),
                    exploit_framework_core: it.exploit_framework_core.as_deref(),
                    exploit_framework_metasploit: it.exploit_framework_metasploit.as_deref(),
                    exploit_framework_canvas: it.exploit_framework_canvas.as_deref(),
                    exploit_framework_exploithub: it.exploit_framework_exploithub.as_deref(),
                    exploit_framework_d2_elliot: it.exploit_framework_d2_elliot.as_deref(),
                    verified: it.verified,
                    cm_compliance_info: it.cm_compliance_info.as_deref(),
                    cm_compliance_actual_value: it.cm_compliance_actual_value.as_deref(),
                    cm_compliance_check_id: it.cm_compliance_check_id.as_deref(),
                    cm_compliance_policy_value: it.cm_compliance_policy_value.as_deref(),
                    cm_compliance_audit_file: it.cm_compliance_audit_file.as_deref(),
                    cm_compliance_check_name: it.cm_compliance_check_name.as_deref(),
                    cm_compliance_result: it.cm_compliance_result.as_deref(),
                    cm_compliance_output: it.cm_compliance_output.as_deref(),
                    cm_compliance_reference: it.cm_compliance_reference.as_deref(),
                    cm_compliance_see_also: it.cm_compliance_see_also.as_deref(),
                    cm_compliance_solution: it.cm_compliance_solution.as_deref(),
                    real_severity: it.real_severity,
                    risk_score: it.risk_score,
                    user_id: None,
                    engagement_id: None,
                    rollup_finding: it.rollup_finding,
                    scanner_id: Some(scanner_id),
                })
                .execute(conn)?;
            let id = diesel::sql_query("SELECT last_insert_rowid() AS id")
                .get_result::<LastId>(conn)?
                .id as i32;
            item_id_map[idx] = Some(id);
        }

        // 7) Host properties
        if !report.host_properties.is_empty() {
            let new_props: Vec<NewHostProperty> = report
                .host_properties
                .iter()
                .map(|p| NewHostProperty {
                    host_id: p.host_id.and_then(|hid| host_ids.get(hid as usize).copied()),
                    name: p.name.as_deref(),
                    value: p.value.as_deref(),
                    user_id: None,
                    engagement_id: None,
                })
                .collect();
            if !new_props.is_empty() {
                diesel::insert_into(hprops::nessus_host_properties)
                    .values(&new_props)
                    .execute(conn)?;
            }
        }

        // 8) Service descriptions
        if !report.service_descriptions.is_empty() {
            let new_sd: Vec<NewServiceDescription> = report
                .service_descriptions
                .iter()
                .map(|sd| NewServiceDescription {
                    host_id: sd.host_id.and_then(|hid| host_ids.get(hid as usize).copied()),
                    item_id: sd.item_id.and_then(|iid| item_id_map.get(iid as usize).copied().flatten()),
                    port: sd.port,
                    svc_name: sd.svc_name.as_deref(),
                    protocol: sd.protocol.as_deref(),
                    description: sd.description.as_deref(),
                    user_id: None,
                    engagement_id: None,
                })
                .collect();
            if !new_sd.is_empty() {
                diesel::insert_into(sdesc::nessus_service_descriptions)
                    .values(&new_sd)
                    .execute(conn)?;
            }
        }

        // 9) References
        if !report.references.is_empty() {
            let new_refs: Vec<NewReference> = report
                .references
                .iter()
                .map(|r| NewReference {
                    plugin_id: r.plugin_id.and_then(|pid| plugin_id_map.get(&pid).copied()),
                    item_id: r.item_id.and_then(|iid| item_id_map.get(iid as usize).copied().flatten()),
                    source: r.source.as_deref(),
                    value: r.value.as_deref(),
                    user_id: None,
                    engagement_id: None,
                })
                .collect();
            if !new_refs.is_empty() {
                diesel::insert_into(refs::nessus_references)
                    .values(&new_refs)
                    .execute(conn)?;
            }
        }

        // 10) Patches
        if !report.patches.is_empty() {
            let new_patches: Vec<NewPatch> = report
                .patches
                .iter()
                .map(|p| NewPatch {
                    host_id: p.host_id.and_then(|hid| host_ids.get(hid as usize).copied()),
                    name: p.name.as_deref(),
                    value: p.value.as_deref(),
                    user_id: None,
                    engagement_id: None,
                })
                .collect();
            if !new_patches.is_empty() {
                diesel::insert_into(patches::nessus_patches)
                    .values(&new_patches)
                    .execute(conn)?;
            }
        }

        // 11) Policies and related
        if !report.policies.is_empty() {
            let new_pols: Vec<NewPolicy> = report
                .policies
                .iter()
                .map(|p| NewPolicy {
                    nessus_report_id: Some(report_id),
                    name: p.name.as_deref(),
                    comments: p.comments.as_deref(),
                    owner: p.owner.as_deref(),
                    visibility: p.visibility.as_deref(),
                })
                .collect();
            if !new_pols.is_empty() {
                diesel::insert_into(pols::nessus_policies)
                    .values(&new_pols)
                    .execute(conn)?;
            }
            // Fetch policy ids in order
            let policy_ids: Vec<i32> = pols::nessus_policies
                .filter(pols::nessus_report_id.eq(report_id))
                .order(pols::id.asc())
                .select(pols::id)
                .load::<i32>(conn)?;

            // Policy plugins
            let new_pp: Vec<NewPolicyPlugin> = report
                .policy_plugins
                .iter()
                .map(|pp| NewPolicyPlugin {
                    policy_id: None,
                    plugin_id: pp.plugin_id,
                    plugin_name: pp.plugin_name.as_deref(),
                    family_name: pp.family_name.as_deref(),
                    status: pp.status.as_deref(),
                })
                .collect();
            if !new_pp.is_empty() {
                diesel::insert_into(polplugs::nessus_policy_plugins)
                    .values(&new_pp)
                    .execute(conn)?;
            }
            // Family selections
            let new_fs: Vec<NewFamilySelection> = report
                .family_selections
                .iter()
                .map(|fs| NewFamilySelection {
                    policy_id: None,
                    family_name: fs.family_name.as_deref(),
                    status: fs.status.as_deref(),
                })
                .collect();
            if !new_fs.is_empty() {
                diesel::insert_into(famsel::nessus_family_selections)
                    .values(&new_fs)
                    .execute(conn)?;
            }
            // Plugin preferences
            let new_pf: Vec<NewPluginPreference> = report
                .plugin_preferences
                .iter()
                .map(|pf| NewPluginPreference {
                    policy_id: None,
                    plugin_id: pf.plugin_id,
                    fullname: pf.fullname.as_deref(),
                    preference_name: pf.preference_name.as_deref(),
                    preference_type: pf.preference_type.as_deref(),
                    selected_value: pf.selected_value.as_deref(),
                    preference_values: pf.preference_values.as_deref(),
                })
                .collect();
            if !new_pf.is_empty() {
                diesel::insert_into(plgprefs::nessus_plugin_preferences)
                    .values(&new_pf)
                    .execute(conn)?;
            }
            // Server preferences
            let new_sp: Vec<NewServerPreference> = report
                .server_preferences
                .iter()
                .map(|sp| NewServerPreference {
                    policy_id: None,
                    name: sp.name.as_deref(),
                    value: sp.value.as_deref(),
                })
                .collect();
            if !new_sp.is_empty() {
                diesel::insert_into(srvprefs::nessus_server_preferences)
                    .values(&new_sp)
                    .execute(conn)?;
            }
        }

        Ok(())
    })
}
