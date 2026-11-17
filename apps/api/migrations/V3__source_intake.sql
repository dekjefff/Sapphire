ALTER TABLE assessments DROP CONSTRAINT IF EXISTS assessments_status_check;
ALTER TABLE assessments ADD CONSTRAINT assessments_status_check
  CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled'));

ALTER TABLE tool_runs DROP CONSTRAINT IF EXISTS tool_runs_status_check;
ALTER TABLE tool_runs ADD CONSTRAINT tool_runs_status_check
  CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled'));

ALTER TABLE projects ADD COLUMN source_type TEXT CHECK (source_type IN ('local_path', 'zip'));
ALTER TABLE projects ADD COLUMN source_location TEXT;
ALTER TABLE projects ADD COLUMN source_identity_type TEXT CHECK (source_identity_type IN ('git_commit', 'content_sha256'));
ALTER TABLE projects ADD COLUMN source_identity TEXT;
ALTER TABLE projects ADD COLUMN source_file_count INTEGER;
ALTER TABLE projects ADD COLUMN source_total_bytes BIGINT;
ALTER TABLE projects ADD COLUMN intake_status TEXT NOT NULL DEFAULT 'pending'
  CHECK (intake_status IN ('pending', 'queued', 'running', 'completed', 'failed'));

CREATE TABLE detected_technologies (
  id BIGSERIAL PRIMARY KEY,
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  confidence NUMERIC(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  reason TEXT NOT NULL,
  UNIQUE (assessment_id, category, name)
);

CREATE TABLE discovered_routes (
  id BIGSERIAL PRIMARY KEY,
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  source_file TEXT NOT NULL,
  source_line INTEGER,
  confidence NUMERIC(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  UNIQUE (assessment_id, method, path, source_file, source_line)
);

CREATE TABLE intake_findings (
  id BIGSERIAL PRIMARY KEY,
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  severity TEXT NOT NULL CHECK (severity IN ('warning', 'error')),
  code TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO tool_definitions (id, name, version, enabled, metadata) VALUES
  ('source-intake', 'Read-only source intake', '1.0.0', TRUE, '{"executes_commands":false,"reads_untrusted_source":true}'::jsonb)
ON CONFLICT (id) DO NOTHING;
