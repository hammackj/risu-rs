CREATE TABLE nessus_references (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_id INTEGER REFERENCES nessus_plugins(id),
    item_id INTEGER REFERENCES nessus_items(id),
    source TEXT,
    value TEXT,
    user_id INTEGER,
    engagement_id INTEGER
);
CREATE INDEX index_nessus_references_on_plugin_id ON nessus_references(plugin_id);
CREATE INDEX index_nessus_references_on_item_id ON nessus_references(item_id);
