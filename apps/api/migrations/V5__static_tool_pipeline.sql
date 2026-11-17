ALTER TABLE assessments ADD COLUMN coverage_status TEXT NOT NULL DEFAULT 'pending'
  CHECK (coverage_status IN ('pending', 'complete', 'incomplete'));

ALTER TABLE tool_runs ADD COLUMN tool_version TEXT;
ALTER TABLE tool_runs ADD COLUMN adapter_version TEXT;
ALTER TABLE tool_runs ADD COLUMN config_id TEXT;
ALTER TABLE tool_runs ADD COLUMN config_sha256 TEXT CHECK (config_sha256 IS NULL OR config_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE tool_runs ADD COLUMN exit_code INTEGER;
ALTER TABLE tool_runs ADD COLUMN coverage_status TEXT NOT NULL DEFAULT 'pending'
  CHECK (coverage_status IN ('pending', 'complete', 'incomplete'));
ALTER TABLE tool_runs ADD COLUMN provenance JSONB NOT NULL DEFAULT '{}'::jsonb
  CHECK (octet_length(provenance::text) <= 16384);

CREATE TABLE scan_artifacts (
  id UUID PRIMARY KEY,
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  tool_run_id UUID NOT NULL REFERENCES tool_runs(id) ON DELETE CASCADE,
  artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('semgrep_json', 'semgrep_sarif', 'trivy_json')),
  relative_path TEXT NOT NULL,
  media_type TEXT NOT NULL,
  sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  byte_size BIGINT NOT NULL CHECK (byte_size >= 0),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tool_run_id, artifact_kind)
);

CREATE TABLE finding_groups (
  id UUID PRIMARY KEY,
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (assessment_id, fingerprint)
);

CREATE TABLE normalized_findings (
  id UUID PRIMARY KEY,
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  tool_run_id UUID NOT NULL REFERENCES tool_runs(id) ON DELETE CASCADE,
  artifact_id UUID NOT NULL REFERENCES scan_artifacts(id) ON DELETE CASCADE,
  group_id UUID NOT NULL REFERENCES finding_groups(id) ON DELETE CASCADE,
  raw_pointer TEXT NOT NULL,
  finding_type TEXT NOT NULL CHECK (finding_type IN ('sast', 'vulnerability', 'secret', 'misconfiguration', 'license', 'unknown')),
  rule_id TEXT,
  cve_id TEXT,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')),
  confidence NUMERIC(4,3) CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
  source_file TEXT,
  start_line INTEGER,
  start_column INTEGER,
  end_line INTEGER,
  end_column INTEGER,
  fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tool_run_id, raw_pointer)
);

CREATE INDEX normalized_findings_assessment_group_idx ON normalized_findings (assessment_id, group_id);

INSERT INTO tool_definitions (id, name, version, enabled, metadata) VALUES
  ('semgrep', 'Semgrep static analysis', '1.185.0', TRUE, '{"network":false,"source_read_only":true}'::jsonb),
  ('trivy', 'Trivy filesystem scan', '0.76.2', TRUE, '{"network":false,"source_read_only":true}'::jsonb)
ON CONFLICT (id) DO UPDATE SET version=EXCLUDED.version, enabled=EXCLUDED.enabled, metadata=EXCLUDED.metadata;
