CREATE TABLE nessus_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    comments TEXT,
    owner TEXT,
    visibility TEXT
);

CREATE TABLE nessus_family_selections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER REFERENCES nessus_policies(id),
    family_name TEXT,
    status TEXT
);

CREATE TABLE nessus_individual_plugin_selections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER REFERENCES nessus_policies(id),
    plugin_id INTEGER,
    plugin_name TEXT,
    family TEXT,
    status TEXT
);

CREATE TABLE nessus_plugins_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER REFERENCES nessus_policies(id),
    plugin_name TEXT,
    plugin_id INTEGER,
    full_name TEXT,
    preference_name TEXT,
    preference_type TEXT,
    preference_values TEXT,
    selected_values TEXT
);

CREATE TABLE nessus_server_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER REFERENCES nessus_policies(id),
    name TEXT,
    value TEXT
);
