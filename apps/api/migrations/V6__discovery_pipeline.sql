-- Discovery reuses the existing tool_runs/scan_artifacts provenance model.
ALTER TABLE tool_definitions ADD CONSTRAINT tool_definitions_discovery_version_check
  CHECK ((id = 'httpx' AND version = '1.12.0') OR (id = 'katana' AND version = '1.8.0') OR id NOT IN ('httpx', 'katana'));

INSERT INTO tool_definitions (id, name, version, enabled, metadata) VALUES
  ('httpx', 'ProjectDiscovery httpx probe', '1.12.0', TRUE, '{"network":true,"discovery":true,"redirects":false,"methods":["GET"]}'::jsonb),
  ('katana', 'ProjectDiscovery Katana passive crawler', '1.8.0', TRUE, '{"network":true,"discovery":true,"headless":false,"forms":false,"methods":["GET"]}'::jsonb)
ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, version=EXCLUDED.version, enabled=EXCLUDED.enabled, metadata=EXCLUDED.metadata;

CREATE FUNCTION jsonb_is_safe_path_prefix_array(value JSONB) RETURNS BOOLEAN LANGUAGE SQL IMMUTABLE STRICT AS $$
  SELECT jsonb_typeof(value) = 'array' AND NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements(value) AS item
    WHERE jsonb_typeof(item) <> 'string' OR item #>> '{}' !~ '^/'
      OR position('?' in item #>> '{}') > 0 OR position('#' in item #>> '{}') > 0
      OR position(chr(92) in item #>> '{}') > 0
  );
$$;

ALTER TABLE scan_artifacts DROP CONSTRAINT IF EXISTS scan_artifacts_artifact_kind_check;
ALTER TABLE scan_artifacts ADD CONSTRAINT scan_artifacts_artifact_kind_check
  CHECK (artifact_kind IN ('semgrep_json', 'semgrep_sarif', 'trivy_json', 'httpx_json', 'katana_json'));
ALTER TABLE scan_artifacts ADD CONSTRAINT scan_artifacts_assessment_run_artifact_unique
  UNIQUE (assessment_id, tool_run_id, id);

CREATE TABLE discovery_scopes (
  id UUID PRIMARY KEY,
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  scheme TEXT NOT NULL CHECK (scheme IN ('http', 'https')),
  host TEXT NOT NULL CHECK (length(host) BETWEEN 1 AND 253 AND host = lower(host) AND host NOT LIKE '%*%'),
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  path_mode TEXT NOT NULL CHECK (path_mode IN ('whole_origin', 'prefix')),
  path_prefixes JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(path_prefixes) = 'array' AND octet_length(path_prefixes::text) <= 16384),
  allowed_methods JSONB NOT NULL DEFAULT '["GET"]'::jsonb CHECK (allowed_methods = '["GET"]'::jsonb),
  pinned_ips JSONB NOT NULL CHECK (jsonb_typeof(pinned_ips) = 'array' AND jsonb_array_length(pinned_ips) BETWEEN 1 AND 32 AND octet_length(pinned_ips::text) <= 4096),
  policy_revision TEXT NOT NULL CHECK (length(policy_revision) BETWEEN 1 AND 64),
  policy_sha256 TEXT NOT NULL CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
  authorization_actor TEXT NOT NULL CHECK (length(authorization_actor) BETWEEN 1 AND 120),
  authorized_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > authorized_at),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT discovery_scope_path_mode_check CHECK (
    (path_mode = 'whole_origin' AND jsonb_array_length(path_prefixes) = 0) OR
    (path_mode = 'prefix' AND scheme = 'http' AND jsonb_array_length(path_prefixes) BETWEEN 1 AND 100)
  ),
  CONSTRAINT discovery_scope_prefix_values_check CHECK (jsonb_is_safe_path_prefix_array(path_prefixes)),
  UNIQUE (assessment_id, id),
  UNIQUE (assessment_id, policy_sha256),
  UNIQUE (assessment_id, id, policy_sha256)
);

CREATE FUNCTION reject_discovery_scope_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'discovery scopes are immutable; create a new scope revision';
END;
$$;
CREATE TRIGGER discovery_scopes_immutable BEFORE UPDATE ON discovery_scopes
  FOR EACH ROW EXECUTE FUNCTION reject_discovery_scope_update();

ALTER TABLE tool_runs ADD COLUMN discovery_scope_id UUID;
ALTER TABLE tool_runs ADD COLUMN scope_policy_sha256 TEXT CHECK (scope_policy_sha256 IS NULL OR scope_policy_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE tool_runs ADD COLUMN failure_reason_code TEXT;
ALTER TABLE tool_runs ADD COLUMN counters JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(counters) = 'object' AND octet_length(counters::text) <= 4096);
ALTER TABLE tool_runs ADD CONSTRAINT tool_runs_failure_reason_code_check
  CHECK (failure_reason_code IS NULL OR failure_reason_code ~ '^[a-z][a-z0-9_]{1,63}$');
ALTER TABLE tool_runs ADD CONSTRAINT tool_runs_scope_assessment_fk
  FOREIGN KEY (assessment_id, discovery_scope_id, scope_policy_sha256) REFERENCES discovery_scopes(assessment_id, id, policy_sha256);
ALTER TABLE tool_runs ADD CONSTRAINT tool_runs_discovery_scope_pair_check CHECK (
  (tool_definition_id IN ('httpx', 'katana') AND discovery_scope_id IS NOT NULL AND scope_policy_sha256 IS NOT NULL)
  OR ((tool_definition_id IS NULL OR tool_definition_id NOT IN ('httpx', 'katana')) AND discovery_scope_id IS NULL AND scope_policy_sha256 IS NULL)
);

CREATE TABLE runtime_endpoints (
  id UUID PRIMARY KEY,
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  tool_run_id UUID NOT NULL,
  artifact_id UUID NOT NULL,
  scheme TEXT NOT NULL CHECK (scheme IN ('http', 'https')),
  host TEXT NOT NULL CHECK (length(host) BETWEEN 1 AND 253 AND host = lower(host)),
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  path TEXT NOT NULL CHECK (path ~ '^/' AND length(path) <= 2048 AND position('?' in path) = 0 AND position('#' in path) = 0 AND position(chr(92) in path) = 0),
  observed_method TEXT NOT NULL CHECK (observed_method = 'GET'),
  status_code INTEGER CHECK (status_code IS NULL OR status_code BETWEEN 100 AND 599),
  content_type TEXT CHECK (content_type IS NULL OR length(content_type) <= 256),
  content_length BIGINT CHECK (content_length IS NULL OR content_length >= 0),
  title TEXT CHECK (title IS NULL OR length(title) <= 512),
  referrer_path TEXT CHECK (referrer_path IS NULL OR (referrer_path ~ '^/' AND length(referrer_path) <= 2048 AND position('?' in referrer_path) = 0 AND position('#' in referrer_path) = 0 AND position(chr(92) in referrer_path) = 0)),
  first_seen_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL CHECK (last_seen_at >= first_seen_at),
  tool_version TEXT NOT NULL CHECK (length(tool_version) BETWEEN 1 AND 64),
  config_sha256 TEXT NOT NULL CHECK (config_sha256 ~ '^[0-9a-f]{64}$'),
  scope_policy_sha256 TEXT NOT NULL CHECK (scope_policy_sha256 ~ '^[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  FOREIGN KEY (assessment_id, tool_run_id, artifact_id) REFERENCES scan_artifacts(assessment_id, tool_run_id, id) ON DELETE CASCADE,
  UNIQUE (tool_run_id, scheme, host, port, path, observed_method),
  UNIQUE (assessment_id, id)
);

CREATE TABLE endpoint_route_matches (
  id UUID PRIMARY KEY,
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  runtime_endpoint_id UUID REFERENCES runtime_endpoints(id) ON DELETE CASCADE,
  coverage_class TEXT NOT NULL CHECK (coverage_class IN ('matched', 'source_only', 'runtime_only', 'unresolved')),
  source_method TEXT CHECK (source_method IS NULL OR source_method = 'GET'),
  source_route TEXT CHECK (source_route IS NULL OR (source_route ~ '^/' AND length(source_route) <= 2048)),
  source_file TEXT CHECK (source_file IS NULL OR length(source_file) <= 2048),
  source_line INTEGER CHECK (source_line IS NULL OR source_line > 0),
  candidate_source_route_ids JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(candidate_source_route_ids) = 'array' AND octet_length(candidate_source_route_ids::text) <= 8192),
  reason_code TEXT NOT NULL,
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= 8192),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT endpoint_route_match_shape_check CHECK (
    (coverage_class IN ('matched', 'runtime_only') AND runtime_endpoint_id IS NOT NULL) OR
    (coverage_class = 'source_only' AND runtime_endpoint_id IS NULL AND source_route IS NOT NULL AND source_method IS NOT NULL) OR
    (coverage_class = 'unresolved' AND (runtime_endpoint_id IS NOT NULL OR source_route IS NOT NULL))
  ),
  FOREIGN KEY (assessment_id, runtime_endpoint_id) REFERENCES runtime_endpoints(assessment_id, id) ON DELETE CASCADE,
  CONSTRAINT endpoint_route_match_reason_code_check CHECK (reason_code ~ '^[a-z][a-z0-9_]{1,63}$')
);

CREATE INDEX discovery_scopes_assessment_created_idx ON discovery_scopes (assessment_id, created_at DESC);
CREATE INDEX tool_runs_discovery_lookup_idx ON tool_runs (assessment_id, tool_definition_id, created_at DESC) WHERE tool_definition_id IN ('httpx', 'katana');
CREATE INDEX runtime_endpoints_assessment_path_idx ON runtime_endpoints (assessment_id, scheme, host, port, path);
CREATE INDEX endpoint_route_matches_assessment_class_idx ON endpoint_route_matches (assessment_id, coverage_class, created_at DESC);
CREATE INDEX endpoint_route_matches_endpoint_idx ON endpoint_route_matches (runtime_endpoint_id) WHERE runtime_endpoint_id IS NOT NULL;
