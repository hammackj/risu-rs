diesel::table! {
    nessus_hosts (id) {
        id -> Integer,
        nessus_report_id -> Nullable<Integer>,
        name -> Nullable<Text>,
        os -> Nullable<Text>,
        mac -> Nullable<Text>,
        start -> Nullable<Timestamp>,
        end -> Nullable<Timestamp>,
        ip -> Nullable<Text>,
        fqdn -> Nullable<Text>,
        netbios -> Nullable<Text>,
        notes -> Nullable<Text>,
        risk_score -> Nullable<Integer>,
        user_id -> Nullable<Integer>,
        engagement_id -> Nullable<Integer>,
    }
}

diesel::table! {
    nessus_host_properties (id) {
        id -> Integer,
        host_id -> Nullable<Integer>,
        name -> Nullable<Text>,
        value -> Nullable<Text>,
        user_id -> Nullable<Integer>,
        engagement_id -> Nullable<Integer>,
    }
}

diesel::table! {
    nessus_plugins (id) {
        id -> Integer,
        plugin_id -> Nullable<Integer>,
        plugin_name -> Nullable<Text>,
        family_name -> Nullable<Text>,
        description -> Nullable<Text>,
        plugin_version -> Nullable<Text>,
        plugin_publication_date -> Nullable<Timestamp>,
        plugin_modification_date -> Nullable<Timestamp>,
        vuln_publication_date -> Nullable<Timestamp>,
        cvss_vector -> Nullable<Text>,
        cvss_base_score -> Nullable<Float>,
        cvss_temporal_score -> Nullable<Text>,
        cvss_temporal_vector -> Nullable<Text>,
        exploitability_ease -> Nullable<Text>,
        exploit_framework_core -> Nullable<Text>,
        exploit_framework_metasploit -> Nullable<Text>,
        metasploit_name -> Nullable<Text>,
        exploit_framework_canvas -> Nullable<Text>,
        canvas_package -> Nullable<Text>,
        exploit_available -> Nullable<Text>,
        risk_factor -> Nullable<Text>,
        solution -> Nullable<Text>,
        synopsis -> Nullable<Text>,
        plugin_type -> Nullable<Text>,
        exploit_framework_exploithub -> Nullable<Text>,
        exploithub_sku -> Nullable<Text>,
        stig_severity -> Nullable<Text>,
        fname -> Nullable<Text>,
        always_run -> Nullable<Text>,
        script_version -> Nullable<Text>,
        d2_elliot_name -> Nullable<Text>,
        exploit_framework_d2_elliot -> Nullable<Text>,
        exploited_by_malware -> Nullable<Text>,
        rollup -> Nullable<Bool>,
        risk_score -> Nullable<Integer>,
        compliance -> Nullable<Text>,
        root_cause -> Nullable<Text>,
        agent -> Nullable<Text>,
        potential_vulnerability -> Nullable<Bool>,
        in_the_news -> Nullable<Bool>,
        exploited_by_nessus -> Nullable<Bool>,
        unsupported_by_vendor -> Nullable<Bool>,
        default_account -> Nullable<Bool>,
        user_id -> Nullable<Integer>,
        engagement_id -> Nullable<Integer>,
        policy_id -> Nullable<Integer>,
    }
}

diesel::table! {
    nessus_items (id) {
        id -> Integer,
        host_id -> Nullable<Integer>,
        plugin_id -> Nullable<Integer>,
        attachment_id -> Nullable<Integer>,
        plugin_output -> Nullable<Text>,
        port -> Nullable<Integer>,
        svc_name -> Nullable<Text>,
        protocol -> Nullable<Text>,
        severity -> Nullable<Integer>,
        plugin_name -> Nullable<Text>,
        verified -> Nullable<Bool>,
        cm_compliance_info -> Nullable<Text>,
        cm_compliance_actual_value -> Nullable<Text>,
        cm_compliance_check_id -> Nullable<Text>,
        cm_compliance_policy_value -> Nullable<Text>,
        cm_compliance_audit_file -> Nullable<Text>,
        cm_compliance_check_name -> Nullable<Text>,
        cm_compliance_result -> Nullable<Text>,
        cm_compliance_output -> Nullable<Text>,
        cm_compliance_reference -> Nullable<Text>,
        cm_compliance_see_also -> Nullable<Text>,
        cm_compliance_solution -> Nullable<Text>,
        real_severity -> Nullable<Integer>,
        risk_score -> Nullable<Integer>,
        user_id -> Nullable<Integer>,
        engagement_id -> Nullable<Integer>,
    }
}

diesel::table! {
    nessus_plugin_metadata (id) {
        id -> Integer,
        script_id -> Nullable<Integer>,
        script_name -> Nullable<Text>,
        cve -> Nullable<Text>,
        bid -> Nullable<Text>,
    }
}

diesel::table! {
    nessus_patches (id) {
        id -> Integer,
        host_id -> Nullable<Integer>,
        name -> Nullable<Text>,
        value -> Nullable<Text>,
        user_id -> Nullable<Integer>,
        engagement_id -> Nullable<Integer>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    nessus_hosts,
    nessus_host_properties,
    nessus_items,
    nessus_plugins,
    nessus_plugin_metadata,
    nessus_patches,
);
