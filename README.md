# Sapphire

Sapphire is a local-first tool for authorized web application assessments. The foundation records scoped assessments and audit events; source intake inventories a local repository or ZIP without executing it; the static pipeline runs pinned Semgrep and Trivy adapters in an isolated scanner runner.

## Requirements

- Docker Desktop with Docker Compose v2, or Docker Engine with the Compose plugin
- Ports 8080 and 8180 available on localhost. Set `WEB_PORT` and `SAPPHIRE_IDENTITY_PORT` in `.env` to change them.
- Internet access the first time images and the web build dependencies are downloaded

## Start

If you are setting up Sapphire for the first time, copy the example environment file from the repository root.

```powershell
Copy-Item .env.example .env
```

On macOS/Linux, use `cp .env.example .env`. Then follow [Account sign-in and registration](#account-sign-in-and-registration).

## Account sign-in and registration

Sapphire opens to **Sign in** until an operator has a valid session. [Auth.js](https://authjs.dev/getting-started) manages Sapphire sessions and [Keycloak](https://www.keycloak.org/) handles sign-in, registration, and passwords. The web service checks the session before serving the dashboard or forwarding same-origin `/api` requests. The backend API and database are reachable only inside Docker. Operators share one workspace.

1. Add these values to your ignored `.env` file. Generate two independent secrets with `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"`, and use a separate strong password for the Keycloak administrator.

   ```dotenv
   SAPPHIRE_AUTH_SECRET=<generated-session-secret>
   SAPPHIRE_OIDC_CLIENT_SECRET=<generated-oidc-client-secret>
   SAPPHIRE_IDENTITY_ADMIN_PASSWORD=<administrator-password>
   ```

2. If an earlier Sapphire proxy is running, stop it to free port 8080.
3. Run `docker compose -f compose.yaml -f compose.authjs.yaml up --build -d`. Use the same pair of Compose files for subsequent commands in this mode.
4. Open `http://localhost:8080`, choose **Sign in or register**, then use **Register** on the Keycloak page. Use the `localhost` URLs consistently for the registered OpenID Connect callback.
5. Sign in to the Keycloak admin console at `http://localhost:8180/admin/` with the bootstrap administrator (`admin` by default). Select realm **sapphire**, open the new user, and assign the realm role **operator** under **Role mapping**. The user can then sign in to Sapphire and sign out from the dashboard.

The Compose setup runs Keycloak in development mode on loopback. Configure SMTP in the **sapphire** realm before relying on password reset or enabling email verification. Keycloak stores accounts in the `identity_data` volume and imports the realm only when it is absent. Role changes are picked up on the next sign-in. Auth.js sessions expire within one hour. Use the Auth.js configuration for the dashboard when migrating from Caddy Basic login.

## Configure the source workspace

The API and worker mount the host directory configured by `WORKSPACE_HOST_PATH` at `/workspace` as read-only. The default is the repository directory (`.`). Set this to a directory containing repositories you are authorized to assess, for example `WORKSPACE_HOST_PATH=C:/Users/you/source` in `.env`; use paths accepted by Docker Desktop. The local-path form only accepts absolute container paths beneath `/workspace` (or another configured `WORKSPACE_ROOTS` mount).

Source intake limits are fixed at 100 MB per ZIP upload, 250 MB expanded source, 20,000 accepted files, 10 MB per file, and 32 directory levels. ZIP entries with absolute paths, traversal, unsupported special file types, malformed archives, and inputs exceeding a hard limit are rejected with a sanitized reason code. Known generated and dependency directories (`node_modules`, `.next`, `dist`, `build`, `vendor`, `coverage`, `out`, `.turbo`, `.cache`, `target`, `.venv`, `venv`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.gradle`, and `.git`) and recognized links are skipped before extraction/inventory. Skips produce an incomplete-intake finding with a total and bounded relative-path sample; longer lists are marked truncated. The API and worker never execute repository files, package scripts, package managers, builds, or tests. Repository contents are treated as untrusted data.

For ZIP uploads, include source files and manifests. Leave out `node_modules`, `.git`, generated folders, symlinks, and junctions to keep the archive small. Known generated/dependency folders and recognized links are safely skipped and reported before extraction; the bounded report includes totals and may truncate the path list. Archives with traversal, unsupported special entries, malformed structure, or files over the 100 MB ZIP, 250 MB expanded, 20,000 accepted-file, 10 MB/file, or 32-level limits are rejected.

## Create an assessment

In the dashboard, choose a mounted repository folder (such as `/workspace/my-app`) or upload a ZIP, then provide a project name and the exact authorized target origin. The default profile is **Static intake only**; leave the runtime-discovery attestation unchecked unless you explicitly authorize the isolated local Juice Shop test profile. That profile is exactly `http://juiceshop:3000`, whole-origin, HTTP `GET` only, and expires after 24 hours. The API does not enqueue discovery without the explicit attestation and an exact configured profile match. Public and third-party targets are not supported. Runtime discovery does not use authentication, cookies, login flows, forms, or state-changing methods; redirects are recorded and denied.

The local test profile uses server-owned fixed limits: crawl depth 3, at most 500 unique URLs, global concurrency 2 (one per host), at most 1 request/second per host, 5-second connect timeout, 10-second request timeout, no retries, at most 1 MiB per response and 50 MiB total, and a 120-second wall-clock limit. Dashboard results show the authorization profile and abbreviated scope/config hashes, run versions and timestamps, matched/source-only/runtime-only/unresolved counts, bounded endpoint and match pages, sanitized source evidence, artifact/raw-line pointers, and incomplete-coverage reasons. A failed, cancelled, empty, or partial run does not mean the target is clean.

Source intake inventories files read-only, computes a Git commit or deterministic content SHA-256 identity, and detects supported technologies. Route extraction covers Next.js file routes and statically resolved Express/Fastify routes; Express routers are linked through relative imports/re-exports and literal `app.use()` mount prefixes, including identifier aliases. Dynamic or unresolved mount paths are reported as warnings and omitted rather than guessed.

Submit the assessment. The API persists the project, assessment, intake job, and audit events, then enqueues it in Redis. The worker records source identity, intake findings, technologies, and routes, then starts Semgrep and Trivy as separate auditable tool runs. The assessment is complete only when both reports are usable; scanner errors, timeouts, cancellation, missing Trivy databases, or malformed output produce failed/incomplete coverage. The dashboard refreshes statuses every three seconds. Browser API requests use the authenticated `/api` prefix.

For a ZIP upload, submit multipart form data to `POST /assessments/zip` with text fields `project_name`, `target_url`, `runtime_discovery_authorized` (`true` only after explicit authorization; omitted/false disables runtime discovery), and a file field `source`. The local-path JSON endpoint accepts the same boolean field. Check component health at `GET /api/health` after signing in. Assessment endpoints are `GET /assessments` and `GET /assessments/{assessment_id}`; detail responses include source identity, intake findings, technologies, routes, scanner coverage, grouped and original findings, tool provenance, raw-artifact links, discovery scope/runs/endpoints/matches/reasons. Discovery detail pages accept `limit` (1–100), `endpoint_cursor`, and `match_cursor`; the web UI provides bounded page-size and pagination controls. Job status is `GET /jobs/{job_id}`.

## Static scan operation

Semgrep `1.185.0` and Trivy `0.76.2` are pinned in `apps/api/Dockerfile.scanner` and the Compose database refresh images. Semgrep uses only repository-owned rules in `apps/api/scanner-config/semgrep.yml`; it does not download rule packs. Trivy scans vulnerabilities and secrets using `apps/api/scanner-config/trivy-config.yml`. Each tool run stores tool and adapter versions, configuration hash, exit status, and raw JSON references (plus Semgrep SARIF). Assessment details expose grouped findings and original records/artifacts.

The scanner runner runs in a separate container with `network_mode: none`, read-only source mounts, a read-only root filesystem, dropped capabilities, and bounded resources. Each tool run has a 10-minute wall-clock limit, raw output is capped at 100 MiB, and diagnostic byte counts are capped at 1 MiB. Scanning skips the generated/dependency directories listed above; these exclusions are also applied to scanner commands. A skip is reported as incomplete intake coverage.

## Runtime discovery operation

Runtime discovery is a separate, opt-in path. The API creates an immutable authorization scope only when the request attestation is true and the exact origin matches a server-side profile. The default local profile is Juice Shop at `http://juiceshop:3000`, pinned to the isolated Compose address; authorization records actor, timestamp, expiry, profile revision, and policy SHA-256. Browser-supplied hosts, paths, methods, budgets, and tool arguments do not configure the runner. The API owns the fixed `discovery-default-v1` budget and creates typed schema-versioned task/result files.

Pinned discovery binaries are httpx `v1.12.0` and Katana `v1.8.0`. Their configured versions, adapter versions, per-tool configuration SHA-256, scope policy SHA-256, counters, run timestamps, and artifact SHA-256 values are recorded. The `discovery-runner` is separate from `scanner-runner`; all egress must pass through `discovery-gateway`, which checks the exact pinned destination and approved path. Redirect following is disabled. Only GET is used. Response bodies and secret-bearing query values are not persisted. Do not attach public or third-party targets to the local Compose profile.

To verify the local discovery flow, start the stack with Juice Shop and create an assessment from the dashboard using the Juice Shop profile and checked authorization attestation. Confirm the exact origin and limits in “Review runtime discovery,” then inspect both tool runs, sanitized endpoints and source matches, policy/config hashes, and coverage reasons. A successful isolated-local run is the end-to-end validation target; a build alone does not prove network scope enforcement. Focused parser, adapter, scope, gateway, and API tests live under `apps/api/test/` and run with `npm test` from `apps/api`; `npm run build` type-checks and compiles the API. Web formatting and production build commands are `npm run format:check` and `npm run build` from `apps/web`.

Trivy does not download databases during assessments. To provision its local vulnerability databases, explicitly run the maintenance profiles while network access is available. They use Trivy's official GHCR database repositories with a 30-minute download timeout:

```powershell
docker compose --profile tool-db-maintenance run --rm trivy-db-refresh
docker compose --profile tool-db-maintenance run --rm trivy-java-db-refresh
```

The runner receives that cache read-only and has no network. Trivy requires bounded `db/metadata.json` provenance from the supplied cache: Sapphire records its SHA-256, schema version, and sanitized update timestamps on the tool run and artifact metadata. Missing or invalid metadata fails the Trivy run with incomplete coverage; it does not report a clean scan. The dashboard's “Review scanner runs” section shows run errors, versions, config provenance, Trivy DB provenance, and raw artifact links even when there are zero findings. The local Semgrep rules are a small initial ruleset, and Trivy's scanner scope is `vuln,secret`; neither output is a complete security assessment.

The intentionally vulnerable, test-only fixture in `samples/security-scan-fixture/` was scanned through ZIP intake and the isolated runner. Assessment `5e1c2d4d-41c0-44a4-9ca9-616402818deb` completed with complete coverage and reported the local Semgrep `eval()` rule at `unsafe-demo.js:3` and Trivy `CVE-2021-44906` for `minimist@1.2.5`. The dashboard/API retained both original findings, raw pointers, and JSON/SARIF artifacts with tool/config/DB provenance. The fixture was never executed and its dependencies were not installed; it contains no real credentials. Its public AWS example key ID was not reported by Trivy. This validates one deterministic finding from each scanner, not broad coverage or the absence of other vulnerabilities.

On this Windows/OneDrive setup, scanning the same fixture through a mounted local path remained in Semgrep for over four minutes without producing an artifact and was cancelled. The ZIP intake run completed from the Docker-managed intake volume. Prefer ZIP intake for this fixture in this environment while the local bind-mount behavior remains unresolved.

## Analyze a HAR with ZAP passive scan

The local Sapphire CLI runs ZAP against recorded HTTP exchanges from a HAR file. Use a sanitized capture with 1–200 exchanges and a maximum size of 10 MiB. The CLI uses a pinned image, runs it with Docker networking disabled, and prints normalized findings. ZAP reads the recorded responses with `sendRequests: false`.

```powershell
docker pull ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af
npm.cmd --prefix apps/api run build
node apps/api/dist/zap-passive-cli.js .\capture.har
```

To attach the result to an existing assessment, supply the web origin and `/api/assessments/<assessment-id>/zap-report` as the second argument. The import requires a valid Sapphire session in `SAPPHIRE_API_COOKIE` for that invocation. The CLI removes its temporary HAR and ZAP report after use. It prints a run ID during analysis and import. A successful upload adds `zap_report.passive_capture` to the assessment detail, with the run ID and the exchange and origin counts reported by the CLI. These counts describe the supplied HAR. Authentication is recorded as `unverified`, and report coverage may remain `unknown`.

Use the [first-party capture recorder](docs/PASSIVE_EVIDENCE.md) to import session evidence, planned coverage, and run progress alongside a redacted HAR.

## Review an existing ZAP report

Build the API package and run `node apps/api/dist/zap-report-cli.js <report.json>` from the repository root to export normalized alerts and redacted HTTP metadata from a local Traditional JSON report. See the [Milestone 4 plan](docs/MILESTONE_4_PLAN.md) for the supported inputs and outputs.

After applying database migration V8, an authenticated operator can associate an existing report with an assessment using `POST /api/assessments/<assessment-id>/zap-report`. This synchronous import stores only normalized metadata and the SHA-256 digest of the exact submitted bytes, never the source report. The POST response and assessment-detail `zap_report` summary expose the lowercase hex digest as `source_sha256`; imports made before V8 have a null digest. The operator chooses the association; Sapphire does not verify that the report belongs to the assessment target. `GET /assessments/<assessment-id>` exposes `zap_report` as missing or imported with coverage and diagnostic reason codes. An accepted import does not mean a scan passed or that coverage is complete. Failed imports leave the last accepted report unchanged.

Retrieve redacted findings from `GET /assessments/<assessment-id>/zap-report/findings?limit=50&offset=0` and instances from `GET /assessments/<assessment-id>/zap-report/findings/<index>/instances?revision_id=<revision-id>&limit=50&offset=0`; limits are 1–100. A finding index is its zero-based position (page offset plus position). Each response has a revision ID; compare revisions across pages. Instance requests require the finding page's revision and return 409 if the report was replaced. No target is contacted by these endpoints.

## AI Code Review

Configure `GROQ_API_KEY` in the local Compose environment. For the Auth.js deployment, also set a random `SAPPHIRE_AI_REVIEW_PROXY_TOKEN` for the web and API containers to share. Keep both values out of Git.

From the authenticated Dashboard, upload the project ZIP and choose **Include AI Code Review** when creating the assessment. The static worker runs Semgrep and Trivy, saves a JSON summary bound to the source fingerprint, and queues the review on the same assessment. The model reviews supported source files based on the ZIP inventory, including files with no scanner findings. Static or intake gaps remain visible as first-pass limitations.

The separate `project-reviewer` service checks the fingerprint before sending batches to Groq. It supports up to 40 requests, 200,000 conservatively estimated token reservations, and 30 minutes per assessment. It tracks files that still need review and keeps confirmed source-line citations with each model suggestion. ZIP snapshots are removed after processing. Open **AI Code Review** on the assessment to see progress, findings and remaining files. The CLI report viewer remains available for reports created outside this workflow.

Temporary errors from Groq and the dependency scanner can trigger up to three retries after the first attempt. Project reviews also retry Groq HTTP 400 responses. Each Groq attempt counts against the assessment budget. The backend records safe error categories, attempt numbers, HTTP statuses, and the provider's machine-readable error code when available. Provider messages and response bodies are discarded. If the review remains incomplete, the dashboard shows saved findings and coverage gaps with user-facing messages.

## Stop and reset

Stop containers while preserving database, queue, and artifact volumes:

```powershell
docker compose down
```

To also discard local state, remove the named volumes:

```powershell
docker compose down --volumes
```

The default PostgreSQL password is for local development only. Set `POSTGRES_PASSWORD` in `.env` before starting if you need a different local value.

## Foundation architecture

- `apps/web`: Next.js and TypeScript dashboard
- `apps/api`: Fastify control API and TypeScript validation
- `apps/api/src/worker.ts`: Redis intake consumer, source inspection coordinator, scan-artifact collector, and normalized finding persister
- `apps/api/src/scanner-runner.ts`: isolated file-queue runner invoking pinned Semgrep and Trivy with fixed argument arrays
- `apps/api/src/discovery/runner.ts`: separate bounded runtime runner for pinned httpx/Katana adapters
- `discovery-gateway`: network boundary enforcing pinned destination and path policy for the discovery runner
- `samples/security-scan-fixture`: intentionally vulnerable test-only fixture for scanner validation; never install or execute it
- PostgreSQL: projects, assessments, intake data, detected technologies/routes, tool definitions/runs, scan artifacts, normalized findings/groups, audit events, and Flyway-managed schema history
- Flyway `12.11.0` applies migrations through `V9__passive_capture_evidence.sql` before the API and worker start. The `flyway_schema_history` table records migration state.
- Redis: persistent queue volume
- `intake` named volume: staged ZIP files and temporary extraction space shared by API/worker
- `artifacts` named volume: raw JSON/SARIF scanner artifacts and metadata sidecars
- `scan_work` named volume: private worker/runner task exchange; scanner output is copied to artifacts after hash and size verification
- `trivy_cache` named volume: offline database cache populated only by the explicit maintenance profiles
- OWASP Juice Shop: isolated benchmark, reachable only from the internal Compose network

Jobs include a `cancel_requested` flag and `POST /jobs/{job_id}/cancel` endpoint so active tool runs can be stopped cooperatively. Runtime discovery is passive and bounded, not exploitation testing. It does not include AI orchestration, authentication, remote cloning, browser execution, or state-changing requests. Stack and route detection is intentionally conservative and reports only source-derived evidence; route extraction does not resolve runtime-generated paths, computed import specifiers, conditional mounts, or router patterns that cannot be statically linked.
