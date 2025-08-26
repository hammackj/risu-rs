CREATE TABLE nessus_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    author TEXT,
    company TEXT,
    classification TEXT,
    user_id INTEGER,
    engagement_id INTEGER
);

ALTER TABLE nessus_policies ADD COLUMN nessus_report_id INTEGER;
