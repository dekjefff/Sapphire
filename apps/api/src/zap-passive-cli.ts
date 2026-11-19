import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { mkdtemp, open, rm, rmdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { normalizeZapReport } from "./zap-report.js";

const run = promisify(execFile);
const image = "ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af";
const byteLimit = 10 * 1024 * 1024;
const entryLimit = 200;

async function readBounded(path: string): Promise<Buffer> {
  const absolutePath = resolve(path);
  if (process.platform === "win32" && absolutePath.startsWith("\\\\")) {
    throw new Error("A local file is required");
  }
  const flags = constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NONBLOCK);
  const file = await open(absolutePath, flags);
  try {
    if (!(await file.stat()).isFile()) throw new Error("A regular file is required");
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of file.createReadStream({ end: byteLimit, autoClose: false })) {
      size += chunk.length;
      if (size > byteLimit) throw new Error("File exceeds 10 MiB");
      chunks.push(chunk);
    }
    return Buffer.concat(chunks, size);
  } finally {
    await file.close();
  }
}

function parseJson(bytes: Buffer): unknown {
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

function inspectHar(har: unknown) {
  const entries = (har as { log?: { entries?: unknown } } | null)?.log?.entries;
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > entryLimit) {
    throw new Error("Expected a HAR file with 1–200 HTTP exchanges");
  }
  const origins = new Set<string>();
  for (const entry of entries) {
    const address = entry?.request?.url;
    const url = typeof address === "string" ? URL.parse(address) : null;
    if (!url || !["http:", "https:"].includes(url.protocol) || url.username || url.password ||
        typeof entry.request.method !== "string" ||
        !Number.isInteger(entry.response?.status) || entry.response.status < 100 || entry.response.status > 599) {
      throw new Error("HAR contains an invalid HTTP exchange");
    }
    origins.add(url.origin);
  }
  return { origins: [...origins], exchanges: entries.length };
}

function importUrl(value: string | undefined): URL | undefined {
  if (!value) return;
  const url = URL.parse(value);
  if (!url || !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
      !["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash ||
      !/^\/(?:api\/)?assessments\/[a-f0-9-]{36}\/zap-report$/i.test(url.pathname)) {
    throw new Error("Expected a loopback Sapphire assessment import URL");
  }
  return url;
}

async function main() {
  const [capturePath, destination, ...extra] = process.argv.slice(2);
  if (!capturePath || extra.length) {
    throw new Error("Usage: node apps/api/dist/zap-passive-cli.js <capture.har> [assessment import URL]");
  }
  const upload = importUrl(destination);
  const capture = await readBounded(capturePath).catch(() => {
    throw new Error("Could not read local HAR file within the 10 MiB limit");
  });
  let data: unknown;
  try { data = parseJson(capture); } catch { throw new Error("Invalid HAR JSON"); }
  const { origins, exchanges } = inspectHar(data);

  const work = await mkdtemp(join(tmpdir(), "sapphire-zap-passive-"));
  const runId = randomUUID();
  const name = "sapphire-zap-passive-" + runId;
  const abort = new AbortController();
  const cancel = () => abort.abort();
  process.once("SIGINT", cancel);
  process.once("SIGTERM", cancel);
  try {
    await writeFile(join(work, "input.har"), capture, { mode: 0o600 });
    await writeFile(join(work, "plan.yaml"), JSON.stringify({
      env: {
        contexts: [{ name: "Recorded traffic", urls: origins }],
        parameters: { failOnError: true, failOnWarning: true, progressToStdout: false },
      },
      jobs: [
        { type: "import", parameters: {
          type: "har", fileName: "/zap/wrk/input.har", sendRequests: false, maxMessages: exchanges,
        } },
        { type: "passiveScan-wait", parameters: { maxDuration: 2 } },
        { type: "report", parameters: {
          template: "traditional-json-plus", reportDir: "/zap/wrk", reportFile: "report.json", displayReport: false,
        } },
      ],
    }));
    process.stderr.write(`Passive run ${runId}: analyzing ${exchanges} recorded HTTP exchanges with ZAP.\n`);
    try {
      await run("docker", [
        "run", "--pull", "never", "--rm", "--name", name, "--network", "none", "--hostname", "localhost",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "1536m",
        "--mount", `type=bind,source=${work},target=/zap/wrk`, image,
        "zap.sh", "-cmd", "-autorun", "/zap/wrk/plan.yaml",
      ], { timeout: 180_000, signal: abort.signal });
    } catch {
      throw new Error(abort.signal.aborted ? "Passive scan cancelled" : "ZAP passive scan failed or timed out. Check Docker and the pinned ZAP image.");
    }

    let report: Buffer;
    let normalized: ReturnType<typeof normalizeZapReport>;
    try {
      report = await readBounded(join(work, "report.json"));
      normalized = normalizeZapReport(parseJson(report));
    } catch {
      throw new Error("ZAP did not produce a usable report");
    }
    if (normalized.coverageReasons.includes("zap_plan_errors")) {
      throw new Error("ZAP reported errors during passive analysis");
    }
    if (upload) {
      upload.searchParams.set("passive_run_id", runId);
      upload.searchParams.set("capture_exchanges", String(exchanges));
      upload.searchParams.set("capture_origins", String(origins.length));
      process.stderr.write(`Passive run ${runId}: importing report.\n`);
      const headers: Record<string, string> = { "Content-Type": "application/json", Origin: upload.origin };
      const cookie = process.env.SAPPHIRE_API_COOKIE;
      if (cookie) headers.Cookie = cookie;
      const result = await fetch(upload, {
        method: "POST", headers, body: new Uint8Array(report), redirect: "error",
        signal: AbortSignal.any([abort.signal, AbortSignal.timeout(20_000)]),
      }).catch(() => { throw new Error("Could not reach Sapphire report import API"); });
      if (!result.ok) throw new Error(`Sapphire rejected the report (HTTP ${result.status})`);
      process.stderr.write("Imported the report into Sapphire.\n");
    }
    process.stdout.write(JSON.stringify({
      recordedExchanges: exchanges,
      passiveRun: { id: runId, status: "completed", recordedOrigins: origins.length, authentication: "unverified" },
      ...normalized,
    }, null, 2) + "\n");
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Passive run ${runId} ${abort.signal.aborted ? "cancelled" : "failed"}: ${error.message}`);
    }
    throw error;
  } finally {
    process.removeListener("SIGINT", cancel);
    process.removeListener("SIGTERM", cancel);
    await run("docker", ["rm", "-f", name], { timeout: 10_000 }).catch(() => {});
    for (const file of ["input.har", "plan.yaml", "report.json"]) {
      await rm(join(work, file), { force: true });
    }
    await rmdir(work).catch(() => {});
  }
}

try { await main(); } catch (error) {
  process.stderr.write((error instanceof Error ? error.message : "Passive scan failed") + "\n");
  process.exitCode = 1;
}
