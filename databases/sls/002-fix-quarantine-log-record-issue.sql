ALTER TABLE sls.quarantine_detector_calls
    ALTER COLUMN response_duration TYPE bigint USING response_duration::bigint;
