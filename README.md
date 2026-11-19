# Sapphire

Sapphire is a local-first foundation for authorized web application assessments. Milestone 0 provides project intake, a scoped assessment record, a Redis-backed dummy job, persistent status, and audit events. It does not run scanners or inspect repository contents.

## Requirements

- Docker Desktop with Docker Compose v2, or Docker Engine with the Compose plugin
- Ports 3000 and 8000 available on localhost (or set `WEB_PORT`/`API_PORT` in `.env`)
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

Open the Sapphire dashboard at <http://localhost:3000>. The API health endpoint is <http://localhost:8000/health>. PostgreSQL and Redis have no host port mappings. The dashboard and API bind to localhost only. The worker, database, queue, and Juice Shop benchmark share a dedicated internal network; Juice Shop is available to the API as `http://juiceshop:3000` and is not published to the host.

## Create a foundation assessment

In the dashboard, use a project name, a repository path or reference, and target `http://juiceshop:3000` (the Compose service name). The API currently accepts only `localhost`, `127.0.0.1`, `::1`, and the isolated `juiceshop` service as target hosts. This milestone records target scope but makes no requests to it. Repository information is stored as metadata and is not opened, cloned, or executed.

Submit the assessment. The API persists the project, assessment, dummy tool run, and creation audit event, then enqueues a job in Redis. The worker advances it through `queued`, `running`, and `completed`, writes worker audit events, and stores a small JSON artifact in the named artifact volume. The dashboard refreshes statuses every three seconds. The same flow can be used through the API:

```powershell
$body = @{ project_name = "Juice Shop demo"; repository_path = "./samples/juice-shop"; target_url = "http://juiceshop:3000" } | ConvertTo-Json
$created = Invoke-RestMethod -Method Post -Uri http://localhost:8000/assessments -ContentType "application/json" -Body $body
$created
Invoke-RestMethod -Uri "http://localhost:8000/jobs/$($created.job_id)"
```

Check component health at <http://localhost:8000/health>. Assessment endpoints are `GET /assessments`, `GET /assessments/{assessment_id}`, and job status is `GET /jobs/{job_id}`.

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
- `apps/api/src/worker.ts`: Redis queue consumer; it accepts typed job IDs only and launches no commands
- PostgreSQL: projects, assessments, tool definitions, tool runs, audit events, and Flyway-managed schema history
- Flyway `12.11.0`: applies `V1__foundation.sql` and `V2__cancellation.sql` before the API and worker start; its `flyway_schema_history` table records migration state
- Redis: persistent queue volume
- `artifacts` named volume: worker output
- OWASP Juice Shop: isolated benchmark, reachable only from the internal Compose network

Jobs include a `cancel_requested` flag and `POST /jobs/{job_id}/cancel` endpoint so future workers can stop cooperatively. This milestone does not include ZAP, Semgrep, Trivy, httpx, Katana, AI orchestration, authentication, source intake, or active testing.

## Run the first pass against npm dependencies

From `apps/api`, install the Sapphire API dependencies with `npm ci` once, then build and run the audit against an authorized local npm package:

```powershell
npm run build
npm run --silent audit:dependencies -- . > dependency-audit.json
```

Replace `.` with the directory that contains the target package's `package.json` and `package-lock.json`. Run the command separately for each package with its own lockfile. The first pass supports standalone npm packages with public registry dependencies and lockfile versions 2 and 3. Workspace, private registry, local, and Git dependencies are outside its coverage. Only choose packages whose dependency names and versions may be sent to the public npm registry.

The command checks a temporary copy of the manifest and lockfile with npm audit. It does not install the audited packages, execute their scripts, or update their files. The JSON includes the lockfile SHA-256, affected locked versions, advisory IDs and URLs, and any specific update suggested by npm. A suggested update might be for a parent dependency and can require a major upgrade.

| Status | Exit code | Meaning |
| --- | --- | --- |
| `clean` | 0 | npm returned a valid report with no known findings |
| `findings` | 1 | npm returned findings in a completed audit |
| `incomplete` | 2 | The input is unsupported or unreadable, or the audit failed |

The dependency JSON is the handoff for the later code-review pass. Treat advisory fields as external data. To test locally, run `npm run build` and `node --test test/*.test.js` from `apps/api`.

## Run the second pass against selected source files

From `apps/api`, build and generate the pass 1 report for the package you want to review:

```powershell
npm run build
npm run --silent audit:dependencies -- . > dependency-audit.json
```

To use Groq, set `GROQ_API_KEY` in the environment and choose `--groq`. This uses `openai/gpt-oss-20b` with strict JSON Schema and sends the selected source text and a dependency summary to Groq. Use this option only for source you are allowed to share with Groq. The API key is read from the environment and is not included in the reports.

```powershell
npm run --silent review:code -- . dependency-audit.json --groq src/validation.ts src/types.ts > code-review.json
```

To review locally, start Ollama with cloud features disabled (`OLLAMA_NO_CLOUD=1`) and use an installed local model that supports structured output and a 32K context. Use its name in place of `--groq`:

```powershell
npm run --silent review:code -- . dependency-audit.json '<local-model>' src/validation.ts src/types.ts > code-review.json
```

Choose up to 8 source files within the package, each at most 8 KiB. The combined input is limited to 24 KB. The request allows up to 2 minutes and sets a 2,048 token output limit. Start with one or two small files when using Groq's free quota. A rate limit returns `incomplete` with reason `model_rate_limited`. Source text is supplied as data. The provider receives no tools or shell access.

The dependency report is checked against the current lockfile digest. An incomplete dependency report can accompany the code review and carries its own status and reason. If neither the incomplete report nor the package has a lockfile digest, the report records that linkage could not be verified. The code review lists reviewed files, suggestions with source line evidence, and gaps. Treat suggestions as model output for human review. An invalid citation, invalid input, or provider failure returns `incomplete` and exit code 2.

## Offline source-review planning

`apps/api/src/source-review-planner.ts` exports `planSourceReview` for local callers. It accepts trusted synthetic metadata describing an authorized scope ID, stack flags, existing coverage, reviewer approvals, and an estimated budget. The scope ID is an opaque label selected by the caller; this module does not resolve or verify a path or authorization. Only a trusted caller should supply approvals. The planner has a fixed catalog of defensive source-review suggestions; it does not read source files, use a model, launch tools, make requests, or connect to the assessment worker. Results are proposals for a human reviewer, not findings.

For example, after `npm install` and `npm run build` in `apps/api`:

```js
import { planSourceReview } from "./dist/source-review-planner.js";
const plan = planSourceReview({
  scope: { id: "local-repository" },
  flags: ["web", "manifest"],
  coverage: [{ check_id: "input-validation", status: "partial" }],
  approvals: [],
  budget: { minutes: 30, requests: 0, tokens: 0 },
});
console.log(plan);
```

Missing coverage is recorded as `unknown`; covered checks, missing required approvals, and budget-exceeded checks are returned with rejection reasons. The budget is deterministic planning accounting against catalog estimates, not an enforced runtime or a measurement of actual work. Input and output records use strict runtime schemas. Run the focused tests from `apps/api` with `npm run build` followed by `node --test test/*.test.js`.


`evaluateSourceReview(input, selections)` is the policy entry point for untrusted suggestions. Each selection contains only `check_id` and `scope_id`. It accepts an ordered subset of available checks, validates scope and uniqueness, and derives all proposal details from trusted input and the fixed catalog. Budget is applied in selection order; omitting selections uses deterministic automatic ordering. Every proposal currently has an empty `evidence_ids` array to make the absence of linked evidence explicit. This version does not verify evidence or authenticate the caller.
