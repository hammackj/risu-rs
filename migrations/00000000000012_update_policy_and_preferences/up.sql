ALTER TABLE nessus_policies ADD COLUMN owner TEXT;
ALTER TABLE nessus_policies ADD COLUMN visibility TEXT;

ALTER TABLE nessus_plugin_preferences ADD COLUMN preference_values TEXT;

