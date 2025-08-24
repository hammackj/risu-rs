CREATE TABLE nessus_plugin_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    script_id INTEGER,
    script_name TEXT,
    cve TEXT,
    bid TEXT
);
