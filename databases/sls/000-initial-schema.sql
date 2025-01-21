-- ******************************
-- SLS Database Schema
-- ******************************

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

--
-- Create Users
--

-- Passwords should be random generated with 40 alphanumeric chars for each environment and stored in the correct vaults.
CREATE USER slsadmin WITH PASSWORD 'SANITIZED';
CREATE USER slsgeth WITH PASSWORD 'SANITIZED';
CREATE USER slsreadonly WITH PASSWORD 'SANITIZED';

--
-- Create Database and Schema
--

CREATE SCHEMA sls;
ALTER SCHEMA sls OWNER TO slsadmin;
--
-- Grant Privileges
--

-- slsadmin
GRANT ALL ON SCHEMA sls TO slsadmin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA sls TO slsadmin;

-- slsgeth
GRANT USAGE ON SCHEMA sls TO slsgeth;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA sls TO slsgeth;

-- slsreadonly
GRANT USAGE ON SCHEMA sls TO slsreadonly;
GRANT SELECT ON ALL TABLES IN SCHEMA sls TO slsreadonly;
 

--
-- Create Tables
--
CREATE TABLE sls.quarantine
(
    id                 SERIAL PRIMARY KEY,
    expires_on         TIMESTAMPTZ NOT NULL,
    tx_data            BYTEA       NOT NULL,
    tx_hash            TEXT        NOT NULL,
    quarantined_at     TIMESTAMPTZ NOT NULL,
    quarantined_reason TEXT        NOT NULL,
    quarantined_by     TEXT        NOT NULL,
    released_by        TEXT,
    is_released        BOOLEAN     NOT NULL DEFAULT FALSE,
    from_addr          TEXT        NOT NULL,
    nonce              BIGINT      NOT NULL,
    released_at        TIMESTAMPTZ,
    loss               BIGINT      NOT NULL,
    value              BIGINT      NOT NULL,
    released_reason    TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE sls.quarantine ADD CONSTRAINT quarantine_tx_hash_unique UNIQUE (tx_hash);

ALTER TABLE sls.quarantine ADD COLUMN quarantine_type INT;
ALTER TABLE sls.quarantine ALTER COLUMN expires_on DROP NOT NULL;

CREATE TABLE sls.integrity_address
(
    address TEXT PRIMARY KEY,
    created_on TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sls.quarantine_detector_calls (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    path TEXT NOT NULL DEFAULT '',
    request_body JSONB NOT NULL DEFAULT '{}',
    response_body JSONB NOT NULL DEFAULT '{}',
    provider TEXT NOT NULL DEFAULT '',
    response_code INT NOT NULL DEFAULT 0,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    response_duration INT NOT NULL DEFAULT 0,
    attempt INT NOT NULL DEFAULT 0,
    from_addr TEXT NOT NULL DEFAULT '',
    tx_hash TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
