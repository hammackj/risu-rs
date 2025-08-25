use diesel::prelude::*;

use crate::schema::nessus_items;

#[derive(Debug, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(super::Host, foreign_key = host_id))]
#[diesel(belongs_to(super::Plugin, foreign_key = plugin_id))]
#[diesel(table_name = nessus_items)]
pub struct Item {
    pub id: i32,
    pub host_id: Option<i32>,
    pub plugin_id: Option<i32>,
    pub attachment_id: Option<i32>,
    pub plugin_output: Option<String>,
    pub port: Option<i32>,
    pub svc_name: Option<String>,
    pub protocol: Option<String>,
    pub severity: Option<i32>,
    pub plugin_name: Option<String>,
    pub description: Option<String>,
    pub solution: Option<String>,
    pub risk_factor: Option<String>,
    pub cvss_base_score: Option<f32>,
    pub verified: Option<bool>,
    pub cm_compliance_info: Option<String>,
    pub cm_compliance_actual_value: Option<String>,
    pub cm_compliance_check_id: Option<String>,
    pub cm_compliance_policy_value: Option<String>,
    pub cm_compliance_audit_file: Option<String>,
    pub cm_compliance_check_name: Option<String>,
    pub cm_compliance_result: Option<String>,
    pub cm_compliance_output: Option<String>,
    pub cm_compliance_reference: Option<String>,
    pub cm_compliance_see_also: Option<String>,
    pub cm_compliance_solution: Option<String>,
    pub real_severity: Option<i32>,
    pub risk_score: Option<i32>,
    pub user_id: Option<i32>,
    pub engagement_id: Option<i32>,
    pub rollup_finding: Option<bool>,
}

impl Default for Item {
    fn default() -> Self {
        Self {
            id: 0,
            host_id: None,
            plugin_id: None,
            attachment_id: None,
            plugin_output: None,
            port: None,
            svc_name: None,
            protocol: None,
            severity: None,
            plugin_name: None,
            description: None,
            solution: None,
            risk_factor: None,
            cvss_base_score: None,
            verified: None,
            cm_compliance_info: None,
            cm_compliance_actual_value: None,
            cm_compliance_check_id: None,
            cm_compliance_policy_value: None,
            cm_compliance_audit_file: None,
            cm_compliance_check_name: None,
            cm_compliance_result: None,
            cm_compliance_output: None,
            cm_compliance_reference: None,
            cm_compliance_see_also: None,
            cm_compliance_solution: None,
            real_severity: None,
            risk_score: None,
            user_id: None,
            engagement_id: None,
            rollup_finding: Some(false),
        }
    }
}
