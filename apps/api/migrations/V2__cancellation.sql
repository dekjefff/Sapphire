ALTER TABLE assessments DROP CONSTRAINT IF EXISTS assessments_status_check;
ALTER TABLE assessments ADD CONSTRAINT assessments_status_check
  CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled'));

ALTER TABLE tool_runs DROP CONSTRAINT IF EXISTS tool_runs_status_check;
ALTER TABLE tool_runs ADD CONSTRAINT tool_runs_status_check
  CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled'));
ALTER TABLE tool_runs ADD COLUMN cancel_requested BOOLEAN NOT NULL DEFAULT false;
