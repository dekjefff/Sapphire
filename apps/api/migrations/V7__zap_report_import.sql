-- Only the allowlisted normalized report is persisted; the source file is not stored.
CREATE TABLE zap_report_imports (
  assessment_id UUID PRIMARY KEY REFERENCES assessments(id) ON DELETE CASCADE,
  revision_id UUID NOT NULL,
  report JSONB NOT NULL CHECK (jsonb_typeof(report) = 'object' AND octet_length(report::text) <= 12582912),
  imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
