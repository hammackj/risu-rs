ALTER TABLE nessus_plugins DROP COLUMN scanner_id;
ALTER TABLE nessus_items DROP COLUMN scanner_id;
ALTER TABLE nessus_hosts DROP COLUMN scanner_id;
DROP TABLE scanners;
