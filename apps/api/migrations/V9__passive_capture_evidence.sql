CREATE TABLE passive_capture_evidence (
  assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  run_id uuid NOT NULL,
  evidence jsonb NOT NULL,
  imported_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (assessment_id, run_id)
);
