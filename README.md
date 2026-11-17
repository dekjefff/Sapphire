# Sapphire

Sapphire is a local-first tool for authorized web application assessments. The foundation records scoped assessments and audit events; source intake inventories a local repository or ZIP without executing it; the static pipeline runs pinned Semgrep and Trivy adapters in an isolated scanner runner.

## Requirements

- Docker Desktop with Docker Compose v2, or Docker Engine with the Compose plugin
- Ports 8080 and 8000 available on localhost (or set `API_PORT` in `.env`)
- Internet access the first time images and the web build dependencies are downloaded

## Start

From the repository root, copy the example environment file and start the stack:

```powershell
Copy-Item .env.example .env
docker compose up --build -d
```

On macOS/Linux, replace the first command with `cp .env.example .env`.

Wait until the services report healthy:

```powershell
docker compose ps
```

Open the Sapphire dashboard at <http://localhost:8080>. The API health endpoint is <http://localhost:8000/health>. PostgreSQL and Redis have no host port mappings. The dashboard and API bind to localhost only. The worker, database, queue, and Juice Shop benchmark share a dedicated internal network; the scanner runner has no network interface. Juice Shop is available to the API as `http://juiceshop:3000` and is not published to the host.

## Configure the source workspace

The API and worker mount the host directory configured by `WORKSPACE_HOST_PATH` at `/workspace` as read-only. The default is the repository directory (`.`). Set this to a directory containing repositories you are authorized to assess, for example `WORKSPACE_HOST_PATH=C:/Users/you/source` in `.env`; use paths accepted by Docker Desktop. The local-path form only accepts absolute container paths beneath `/workspace` (or another configured `WORKSPACE_ROOTS` mount).

Source intake limits are fixed at 100 MB per ZIP upload, 250 MB expanded source, 20,000 files, 10 MB per file, and 32 directory levels. ZIP entries with absolute paths, traversal, symlinks, or special file types are rejected. Known generated and dependency directories (`node_modules`, `.next`, `dist`, `build`, `vendor`, `coverage`, `out`, `.turbo`, `.cache`, `target`, `.venv`, `venv`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, and `.gradle`) are skipped and reported by name and count as incomplete-scan findings. The API and worker never execute repository files, package scripts, package managers, builds, or tests. Repository contents are treated as untrusted data.

For ZIP uploads, include source files and manifests, and leave out `node_modules`, `.git`, generated folders, symlinks, and junctions. Archives containing entries rejected by path/type checks or exceeding the limits may be rejected.

## Create an assessment

In the dashboard, choose a mounted repository folder (such as `/workspace/my-app`) or upload a ZIP, then provide a project name and target `http://juiceshop:3000` (the Compose service name). The API currently accepts only `localhost`, `127.0.0.1`, `::1`, and the isolated `juiceshop` service as target hosts. This milestone records target scope but makes no requests to it. Source intake inventories files read-only, computes a Git commit or deterministic content SHA-256 identity, and detects supported technologies. Route extraction covers Next.js file routes and statically resolved Express/Fastify routes; Express routers are linked through relative imports/re-exports and literal `app.use()` mount prefixes, including identifier aliases. Dynamic or unresolved mount paths are reported as warnings and omitted rather than guessed.

Submit the assessment. The API persists the project, assessment, intake job, and audit events, then enqueues it in Redis. The worker records source identity, intake findings, technologies, and routes, then starts Semgrep and Trivy as separate auditable tool runs. The assessment is complete only when both reports are usable; scanner errors, timeouts, cancellation, missing Trivy databases, or malformed output produce failed/incomplete coverage. The dashboard refreshes statuses every three seconds. The same flow can be used through the API:

```powershell
$body = @{ project_name = "My app"; repository_path = "/workspace/my-app"; target_url = "http://juiceshop:3000"; source_type = "local_path" } | ConvertTo-Json
$created = Invoke-RestMethod -Method Post -Uri http://localhost:8000/assessments -ContentType "application/json" -Body $body
$created
Invoke-RestMethod -Uri "http://localhost:8000/jobs/$($created.job_id)"
```

For a ZIP upload, submit multipart form data to `POST /assessments/zip` with text fields `project_name`, `target_url`, and a file field `source`. Check component health at <http://localhost:8000/health>. Assessment endpoints are `GET /assessments` and `GET /assessments/{assessment_id}`; detail responses include source identity, intake findings, technologies, routes, scanner coverage, grouped and original findings, tool provenance, and raw-artifact links. Job status is `GET /jobs/{job_id}`.

## Static scan operation

Semgrep `1.185.0` and Trivy `0.76.2` are pinned in `apps/api/Dockerfile.scanner` and the Compose database refresh images. Semgrep uses only repository-owned rules in `apps/api/scanner-config/semgrep.yml`; it does not download rule packs. Trivy scans vulnerabilities and secrets using `apps/api/scanner-config/trivy-config.yml`. Each tool run stores tool and adapter versions, configuration hash, exit status, and raw JSON references (plus Semgrep SARIF). Assessment details expose grouped findings and original records/artifacts.

The scanner runner runs in a separate container with `network_mode: none`, read-only source mounts, a read-only root filesystem, dropped capabilities, and bounded resources. Each tool run has a 10-minute wall-clock limit, raw output is capped at 100 MiB, and diagnostic byte counts are capped at 1 MiB. Scanning skips the generated/dependency directories listed above; these exclusions are also applied to scanner commands. A skip is reported as incomplete intake coverage.

Trivy does not download databases during assessments. To provision its local vulnerability databases, explicitly run the maintenance profiles while network access is available. They use Trivy's official GHCR database repositories with a 30-minute download timeout:

```powershell
docker compose --profile tool-db-maintenance run --rm trivy-db-refresh
docker compose --profile tool-db-maintenance run --rm trivy-java-db-refresh
```

The runner receives that cache read-only and has no network. Trivy requires bounded `db/metadata.json` provenance from the supplied cache: Sapphire records its SHA-256, schema version, and sanitized update timestamps on the tool run and artifact metadata. Missing or invalid metadata fails the Trivy run with incomplete coverage; it does not report a clean scan. The dashboard's “Review scanner runs” section shows run errors, versions, config provenance, Trivy DB provenance, and raw artifact links even when there are zero findings. The local Semgrep rules are a small initial ruleset, and Trivy's scanner scope is `vuln,secret`; neither output is a complete security assessment.

The intentionally vulnerable, test-only fixture in `samples/security-scan-fixture/` was scanned through ZIP intake and the isolated runner. Assessment `5e1c2d4d-41c0-44a4-9ca9-616402818deb` completed with complete coverage and reported the local Semgrep `eval()` rule at `unsafe-demo.js:3` and Trivy `CVE-2021-44906` for `minimist@1.2.5`. The dashboard/API retained both original findings, raw pointers, and JSON/SARIF artifacts with tool/config/DB provenance. The fixture was never executed and its dependencies were not installed; it contains no real credentials. Its public AWS example key ID was not reported by Trivy. This validates one deterministic finding from each scanner, not broad coverage or the absence of other vulnerabilities.

On this Windows/OneDrive setup, scanning the same fixture through a mounted local path remained in Semgrep for over four minutes without producing an artifact and was cancelled. The ZIP intake run completed from the Docker-managed intake volume. Prefer ZIP intake for this fixture in this environment while the local bind-mount behavior remains unresolved.

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
- `samples/security-scan-fixture`: intentionally vulnerable test-only fixture for scanner validation; never install or execute it
- PostgreSQL: projects, assessments, intake data, detected technologies/routes, tool definitions/runs, scan artifacts, normalized findings/groups, audit events, and Flyway-managed schema history
- Flyway `12.11.0`: applies `V1__foundation.sql` through `V5__static_tool_pipeline.sql` before the API and worker start; its `flyway_schema_history` table records migration state
- Redis: persistent queue volume
- `intake` named volume: staged ZIP files and temporary extraction space shared by API/worker
- `artifacts` named volume: raw JSON/SARIF scanner artifacts and metadata sidecars
- `scan_work` named volume: private worker/runner task exchange; scanner output is copied to artifacts after hash and size verification
- `trivy_cache` named volume: offline database cache populated only by the explicit maintenance profiles
- OWASP Juice Shop: isolated benchmark, reachable only from the internal Compose network

Jobs include a `cancel_requested` flag and `POST /jobs/{job_id}/cancel` endpoint so active tool runs can be stopped cooperatively. This milestone does not include DAST, httpx, Katana, AI orchestration, authentication, remote cloning, or active testing. Stack and route detection is intentionally conservative and reports only source-derived evidence; route extraction does not resolve runtime-generated paths, computed import specifiers, conditional mounts, or router patterns that cannot be statically linked.
