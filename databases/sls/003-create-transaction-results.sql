CREATE TABLE sls.transaction_results
(
    tx_hash     CITEXT PRIMARY KEY,
    quarantined BOOLEAN     NOT NULL,
    created_on  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA sls TO slsadmin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA sls TO slsgeth;
GRANT SELECT ON ALL TABLES IN SCHEMA sls TO slsreadonly;

ALTER TABLE sls.integrity_address ALTER COLUMN address TYPE CITEXT;
ALTER TABLE sls.quarantine ALTER COLUMN tx_hash TYPE CITEXT;
ALTER TABLE sls.quarantine ALTER COLUMN from_addr TYPE CITEXT;
ALTER TABLE sls.quarantine_detector_calls ALTER COLUMN from_addr TYPE CITEXT;
ALTER TABLE sls.quarantine_detector_calls ALTER COLUMN tx_hash TYPE CITEXT;
