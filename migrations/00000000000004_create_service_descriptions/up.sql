CREATE TABLE nessus_service_descriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER REFERENCES nessus_hosts(id),
    item_id INTEGER REFERENCES nessus_items(id),
    port INTEGER,
    svc_name TEXT,
    protocol TEXT,
    description TEXT,
    user_id INTEGER,
    engagement_id INTEGER
);
CREATE INDEX index_nessus_service_descriptions_on_host_id ON nessus_service_descriptions(host_id);
CREATE INDEX index_nessus_service_descriptions_on_item_id ON nessus_service_descriptions(item_id);
