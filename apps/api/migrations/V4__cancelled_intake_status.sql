ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_intake_status_check;
ALTER TABLE projects ADD CONSTRAINT projects_intake_status_check
  CHECK (intake_status IN ('pending', 'queued', 'running', 'completed', 'failed', 'cancelled'));
