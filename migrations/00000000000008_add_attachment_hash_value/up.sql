CREATE TABLE IF NOT EXISTS nessus_attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    content_type TEXT,
    path TEXT,
    size INTEGER
);
ALTER TABLE nessus_attachments ADD COLUMN ahash TEXT;
ALTER TABLE nessus_attachments ADD COLUMN value TEXT;
