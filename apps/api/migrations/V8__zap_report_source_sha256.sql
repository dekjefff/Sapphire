ALTER TABLE zap_report_imports ADD COLUMN source_sha256 TEXT CHECK (source_sha256 IS NULL OR source_sha256 ~ '^[0-9a-f]{64}$');
