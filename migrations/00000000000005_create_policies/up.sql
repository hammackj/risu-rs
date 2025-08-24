CREATE TABLE nessus_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    comments TEXT
);

CREATE TABLE nessus_policy_plugins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER REFERENCES nessus_policies(id),
    plugin_id INTEGER,
    plugin_name TEXT,
    family_name TEXT,
    status TEXT
);

CREATE TABLE nessus_family_selections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER REFERENCES nessus_policies(id),
    family_name TEXT,
    status TEXT
);

CREATE TABLE nessus_plugin_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER REFERENCES nessus_policies(id),
    plugin_id INTEGER,
    fullname TEXT,
    preference_name TEXT,
    preference_type TEXT,
    selected_value TEXT
);

CREATE TABLE nessus_server_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER REFERENCES nessus_policies(id),
    name TEXT,
    value TEXT
);
