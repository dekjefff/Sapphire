CREATE TABLE project_code_reviews (
    assessment_id UUID PRIMARY KEY REFERENCES assessments(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'waiting_for_scans'
        CHECK (status IN ('waiting_for_scans', 'queued', 'running', 'completed', 'incomplete', 'cancelled')),
    consent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_sha256 TEXT CHECK (source_sha256 IS NULL OR source_sha256 ~ '^[0-9a-f]{64}$'),
    static_report JSONB,
    report JSONB,
    reason TEXT,
    cancel_requested BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX project_code_reviews_queue ON project_code_reviews (status, updated_at);
