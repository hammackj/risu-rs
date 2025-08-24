CREATE TABLE nessus_patches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER REFERENCES nessus_hosts(id),
    name TEXT,
    value TEXT,
    user_id INTEGER,
    engagement_id INTEGER
);
