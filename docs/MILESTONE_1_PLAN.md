# Milestone 1 plan: Source intake and stack detection

Source issue: https://github.com/dekjefff/Sapphire/issues/2

## Objective

Allow Sapphire to accept a local repository or ZIP safely, record a stable source identity, detect its technology stack and source-derived routes, and present the results in the dashboard without executing repository code.

## Proposed work

### 1. Source intake contract

- Extend assessment creation with a source type (`local_path` or `zip`).
- Define configured workspace roots and canonical path validation.
- Set explicit limits for archive size, extracted size, file count, per-file size, and nesting depth.
- Treat all repository content as untrusted data.

### 2. Safe local path and ZIP handling

- Resolve real paths before checking workspace boundaries.
- Reject traversal, paths outside configured roots, unsafe symlinks, and special files.
- Extract ZIP files into an isolated intake directory.
- Reject absolute archive entries, traversal entries, unsafe links, and archive expansion beyond limits.
- Keep source data read-only for API and worker processing.

### 3. Stable source identity

- Record the Git commit hash when the selected source is a valid Git worktree.
- Compute a deterministic content hash when no commit is available.
- Store source type, canonical location, hash type, hash value, file count, total size, and intake status.

### 4. Stack detection

- Inspect manifests and source layout without running package managers or lifecycle scripts.
- Detect languages, package ecosystems, frameworks, container files, and API specifications.
- Return structured technology records with evidence paths and confidence/reason fields.
- Report unsupported or incomplete parsing as warnings.

### 5. Route extraction

- Add bounded TypeScript AST parsing for source-derived Express/Fastify routes and Next.js file routes. Resolve Express Router variables structurally, including named/default imports, aliases, relative re-exports, and literal `app.use()` mount chains.
- Capture HTTP method, route path, source file, and line number when available.
- Mark dynamic or partially resolved mounts as incomplete with intake warnings instead of guessing; do not resolve runtime-generated paths, computed imports, or conditional mount logic.
- Deduplicate routes while preserving their source evidence.

### 6. Persistence and audit trail

- Add migrations for source intake metadata, detected technologies, discovered routes, and intake errors/warnings.
- Record intake requested, accepted, completed, and failed events.
- Avoid storing repository file contents in audit events or logs.

### 7. API and worker flow

- Validate input and persist a queued intake job in the API.
- Perform bounded inspection in the worker without executing source code.
- Support cancellation and update assessment/intake status consistently.
- Return source metadata, technologies, routes, warnings, and errors through assessment endpoints.

### 8. Dashboard

- Let the user select a local repository path or upload a ZIP.
- Show intake status, stable source identity, detected technologies, route count, warnings, and errors.
- Add a route view with method, path, source file, and line.

### 9. Documentation and acceptance review

- Document workspace-root configuration, limits, supported stacks, and read-only behavior.
- Review every acceptance criterion in Issue #2 against the implemented API and dashboard flow.

## Suggested implementation order

1. Database schema and typed source-intake contract.
2. Canonical path validation and bounded repository inventory.
3. Stable source hashing and Git revision detection.
4. Manifest-based stack detection.
5. Express and Next.js route extraction.
6. Worker integration and audit events.
7. ZIP intake.
8. Dashboard presentation.
9. Documentation and acceptance review.

## Decisions applied

- `WORKSPACE_HOST_PATH` is bind-mounted read-only at `/workspace`; `WORKSPACE_ROOTS` is configurable.
- ZIP uploads are streamed to the shared `intake` volume and consumed by the worker.
- Limits are 100 MB compressed, 250 MB expanded, 20,000 files, 10 MB per file, and 32 levels.
- The first route pass includes Next.js App and Pages file routes plus Express/Fastify AST-derived literal routes. Router instances can be linked through static relative imports/re-exports and arbitrary identifier aliases; unresolved dynamic mounts produce warnings. Parsing is bounded by a 5,000 file and 64 MiB source limit.

## Out of scope

- Remote Git cloning.
- SAST or DAST execution.
- Package installation, builds, tests, or lifecycle scripts.
- AI-led exploitation or interpretation of repository text as instructions.
