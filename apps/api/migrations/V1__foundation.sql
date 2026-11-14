CREATE TABLE projects (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    repository_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE assessments (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tool_definitions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT false,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE tool_runs (
    id UUID PRIMARY KEY,
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    tool_definition_id TEXT REFERENCES tool_definitions(id),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error TEXT
);

CREATE TABLE audit_events (
    id BIGSERIAL PRIMARY KEY,
    assessment_id UUID REFERENCES assessments(id) ON DELETE CASCADE,
    tool_run_id UUID REFERENCES tool_runs(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO tool_definitions (id, name, version, enabled, metadata) VALUES
    ('foundation-dummy', 'Foundation dummy worker', '1.0.0', TRUE, '{"kind":"demo","executes_commands":false}'::jsonb);
