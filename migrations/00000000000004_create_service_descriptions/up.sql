CREATE TABLE nessus_service_descriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER REFERENCES nessus_hosts(id),
    item_id INTEGER REFERENCES nessus_items(id),
    name TEXT,
    port INTEGER,
    protocol TEXT,
    description TEXT,
    user_id INTEGER,
    engagement_id INTEGER
);
