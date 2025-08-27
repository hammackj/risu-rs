CREATE TABLE scanners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanner_type TEXT NOT NULL,
    scanner_version TEXT
);

ALTER TABLE nessus_hosts ADD COLUMN scanner_id INTEGER REFERENCES scanners(id);
ALTER TABLE nessus_items ADD COLUMN scanner_id INTEGER REFERENCES scanners(id);
ALTER TABLE nessus_plugins ADD COLUMN scanner_id INTEGER REFERENCES scanners(id);
