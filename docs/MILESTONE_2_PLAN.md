# Milestone 2 plan: Static tool pipeline

Source issue: https://github.com/dekjefff/Sapphire/issues/3

## Objective

Extend the current local source-intake flow into a bounded, auditable static-analysis pipeline. Run pinned Semgrep and Trivy scanners against the accepted read-only source snapshot, retain raw tool output with provenance, normalize findings into one review schema, and group duplicates without losing original evidence.

## Current architecture and constraints

- The Fastify API creates an assessment, a `source-intake` tool run, and a Redis queue message.
- One Node worker consumes the message, validates/intakes local paths or staged ZIPs, and currently persists technologies/routes/findings.
- PostgreSQL already has `tool_runs`, `audit_events`, `intake_findings`, and `detected_technologies`; raw scan artifacts have a local Docker volume.
- API and worker share the workspace as read-only. Worker is on the internal Docker network and cannot reach the public Internet. The web UI is pinned to host port 8080 in the current worktree and must remain there.
- Source files, manifests, configs, and scanner output are untrusted inputs. No package scripts, builds, tests, or target requests will run.

## Proposed design

### 1. Pin tools and local rules

- Pin Semgrep to `1.185.0` and Trivy to `0.76.2` (verified against the upstream release/package listings on 2026-11-17); pin the scanner image references by digest as well, and record their runtime-reported versions, adapter version, config hash, and config ID on every tool run.
- Keep both the API and queue-coordinator worker images free of scanner tooling; put the pinned binaries only in the isolated scanner-runner image.
- Keep a reviewed, repository-owned Semgrep rules file so the scan does not fetch rule packs from the network. Trivy config and excludes are also local and hashed.
- Run commands with `spawn` argument arrays, never a shell; fixed binary names/flags, bounded timeouts/output, a minimal environment, telemetry/version checks disabled, and source mounted read-only.
- Apply container hardening to the worker: read-only root filesystem where practical, dropped Linux capabilities, no-new-privileges, bounded PIDs/memory/CPU, and only the existing internal network. Scanner commands do not receive network access. Trivy DB-dependent scans may be incomplete unless an operator has provisioned an approved local database cache; missing DB must become an explicit failed/incomplete run.

### 2. Pipeline and run state

- Keep the existing intake run as the pipeline entry point. After successful inventory/identity/detection, create distinct `semgrep` and `trivy` child `tool_runs` and execute them sequentially in the same worker job.
- Preserve the overall assessment as running until both tool runs are terminal. Mark the assessment completed only if both scan adapters completed and produced parseable reports; otherwise mark it failed/incomplete and retain coverage details. Never infer “clean” from a scanner error, timeout, malformed JSON, or missing database.
- Carry cancellation through the pipeline. Stop launching child tools after cancellation, terminate a running process on cancellation/timeout, and atomically resolve its run/assessment status.

### 3. Raw artifacts and provenance

- Store each raw JSON artifact and a metadata sidecar under an assessment-scoped directory on the existing local artifact volume, using opaque IDs rather than repository-controlled names.
- Record artifact format, relative reference, byte count, SHA-256, tool/version, adapter version, config ID/hash, start/end time, and exit code in PostgreSQL. For Trivy, also store a bounded hash and sanitized version/update fields from the exact local DB metadata used by the runner; missing metadata is an incomplete run.
- Do not include source excerpts or raw JSON in logs/audit details. Make artifact references reviewable in the assessment API/UI; retain raw artifacts even when normalization is partial or fails.

### 4. Normalized finding schema and grouping

- Add a common finding table with tool-run/artifact references, rule/CVE identifiers, title/message, severity, confidence, category, source path and start/end line/column, normalized fingerprint, and a safe evidence summary.
- Map Semgrep rule IDs, message, severity, confidence/metadata, location, and raw-result index; map Trivy result target, vulnerability/misconfiguration/secret ID, title/message, severity, CVSS or confidence when available, and location/package data.
- Group duplicate findings by a deterministic fingerprint derived from normalized rule/CVE, source path, location, and normalized title. Keep every original finding and its artifact reference inspectable; groups are an additional summary, not destructive deduplication.
- Preserve unknown severities as `unknown`; never silently promote missing confidence or line data.

### 5. API, dashboard, and review

- Extend assessment details with scanner status/coverage, version/config/Trivy DB/artifact provenance, normalized groups, and original findings. Keep run review available when no findings exist or a tool fails before writing an artifact.
- Show severity, confidence, file/line, rule or CVE, tool/version, grouped count, and evidence/artifact link in the dashboard.
- Add migrations for artifacts, common findings, and duplicate groups; seed tool definitions for Semgrep/Trivy and record started/completed/failed/cancelled audit events.

### 6. Documentation and acceptance review

- Document pinned versions, local rules, resource/time limits, no-network policy, local Trivy DB provisioning, raw artifact retention, and incomplete-coverage semantics. Record the successful test-only fixture run as limited runtime verification; do not generalize it to arbitrary repositories.
- Review Issue #3 acceptance criteria against the API, persisted rows/artifacts, and dashboard response shape.

## Initial limits

- One assessment at a time per worker process.
- Per-tool wall-clock timeout: 10 minutes; terminate then kill after a 5-second grace period.
- Captured diagnostic output capped at 1 MiB per tool; raw JSON artifact capped at 100 MiB. Exceeding limits is an incomplete tool run.
- Scanner target must resolve beneath the configured workspace root or the worker's private ZIP snapshot; path separators/arguments are never derived from archive names for executable options.
- Trivy has no network permission during assessment. Vulnerability coverage requires an already populated local DB; missing/outdated DB is surfaced as incomplete coverage rather than a clean scan.
- Build the amd64 scanner image without installing packages from Debian apt: use the pinned official Semgrep image as the runtime base, copy Node from its pinned official image, and copy the static Trivy binary from its pinned official image. Build-time version checks validate all three binaries.

## Out of scope

- DAST, active HTTP probing, package installation, repository builds/tests, remote cloning, arbitrary shell/plugin execution, Semgrep cloud/registry upload, and AI-generated findings.
