import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { access, lstat, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { startLocalTarget } from "./fixtures/wp8/local-target.mjs";
import { buildZip } from "./fixtures/wp8/zip-fixtures.mjs";

const root = resolve(import.meta.dirname, "..");
const targetFixture = resolve(root, "test/fixtures/wp8/vulnerable-source");
const intakeDir = () => join(scratch, "intake");
let primary;
let peer;
let scratch;
let api;

before(async () => {
  peer = await startLocalTarget();
  primary = await startLocalTarget({ peerOrigin: peer.origin, slowMs: 40, largeBytes: 64 * 1024 });
  scratch = await mkdtemp(join(tmpdir(), "sapphire-wp8-"));
  const intakeModule = resolve(root, "apps/api/dist/intake.js");
  const validationModule = resolve(root, "apps/api/dist/validation.js");
  const scopeModule = resolve(root, "apps/api/dist/discovery-scope-policy.js");
  const contractModule = resolve(root, "apps/api/dist/discovery-contracts.js");
  try {
    await Promise.all([access(intakeModule), access(validationModule), access(scopeModule), access(contractModule)]);
    api = {
      intake: await import(pathToFileURL(intakeModule)),
      validation: await import(pathToFileURL(validationModule)),
      scope: await import(pathToFileURL(scopeModule)),
      contracts: await import(pathToFileURL(contractModule)),
    };
  } catch {
    api = null;
  }
});

after(async () => {
  if (primary) await primary.close();
  if (peer) await peer.close();
  if (scratch) await rm(scratch, { recursive: true, force: true });
});

function validApproval(overrides = {}) {
  return {
    scope_id: "11111111-1111-4111-8111-111111111111",
    assessment_id: "22222222-2222-4222-8222-222222222222",
    origin: "http://example.test",
    path_mode: "prefix",
    path_prefixes: ["/api"],
    pinned_ips: ["192.0.2.10"],
    policy_revision: "wp2-test-v1",
    authorization_actor: "WP8 test",
    authorized_at: "2026-01-01T00:00:00.000Z",
    expires_at: "2030-01-01T00:00:00.000Z",
    ...overrides,
  };
}

async function inspectZip(name, entries) {
  await mkdir(intakeDir(), { recursive: true });
  await writeFile(join(intakeDir(), name), Buffer.isBuffer(entries) ? entries : buildZip(entries));
  return api.intake.inspectSource({ type: "zip", path: name }, `wp8-${name}`);
}

async function expectIntakeReason(name, entries, reasonCode) {
  await mkdir(intakeDir(), { recursive: true });
  await writeFile(join(intakeDir(), name), Buffer.isBuffer(entries) ? entries : buildZip(entries));
  await assert.rejects(
    api.intake.inspectSource({ type: "zip", path: name }, `wp8-${name}`),
    error => error.reasonCode === reasonCode
      && !error.message.includes(intakeDir())
      && !error.message.includes("SECRET_SOURCE_MARKER"),
  );
}

test("local target exposes bounded test cases and records method/path without side effects", async () => {
  const cases = ["/", "/in-scope", "/prefix/child", "/redirect/path", "/redirect/host", "/redirect/loop-a", "/slow", "/oversized", "/rate-limit", "/server-error", "/items/42", "/vulnerable"];
  for (const path of cases) await fetch(`${primary.origin}${path}`, { redirect: "manual" });
  const unsafeMethod = await fetch(`${primary.origin}/in-scope`, { method: "POST", body: "harmless marker" });
  assert.equal(unsafeMethod.status, 405);
  assert.ok(primary.ledger.some(entry => entry.method === "POST" && entry.path === "/in-scope"));
  assert.ok(primary.ledger.some(entry => entry.path === "/redirect/host"));
  assert.equal(primary.ledger.filter(entry => entry.method !== "GET" && entry.method !== "HEAD").length, 1);
  assert.equal((await fetch(`${peer.origin}/peer-only`)).status, 404);
});

test("fixture contains a real source-derived route and an inert vulnerable eval example", async () => {
  const source = await readFile(join(targetFixture, "routes.js"), "utf8");
  assert.match(source, /app\.get\("\/vulnerable"/);
  assert.match(source, /eval\(req\.query\.input\)/);
  // The vulnerable source file is never imported. The executable target ignores query input.
  const response = await fetch(`${primary.origin}/vulnerable?input=marker`);
  assert.equal(await response.text(), "harmless marker; query ignored");
});

test("source intake identifies vulnerable and parameterized routes", async t => {
  if (!api) return t.skip("API dist modules are unavailable; run npm --prefix apps/api run build");
  process.env.WORKSPACE_ROOTS = root;
  const result = await api.intake.inspectSource({ type: "local_path", path: targetFixture }, "wp8-fixture");
  assert.ok(result.routes.some(route => route.method === "GET" && route.path === "/vulnerable"), JSON.stringify(result.routes));
  assert.ok(result.routes.some(route => route.method === "GET" && route.path === "/items/:itemId"), JSON.stringify(result.routes));
});

test("public target validation accepts only configured local fixture origins", async t => {
  if (!api) return t.skip("API dist modules are unavailable; run npm --prefix apps/api run build");
  assert.equal(api.validation.validateTarget(primary.origin), `${primary.origin}/`);
  assert.throws(() => api.validation.validateTarget("https://example.com"));
  assert.throws(() => api.validation.validateTarget(`${primary.origin.replace("http://", "http://user:pass@")}`));
});

test("intake skips recognized generated directories and reports a bounded warning", async t => {
  if (!api) return t.skip("API dist modules are unavailable; run npm --prefix apps/api run build");
  const sourceRoot = join(scratch, "intake-sample");
  await mkdir(join(sourceRoot, "src"), { recursive: true });
  await mkdir(join(sourceRoot, "node_modules"), { recursive: true });
  await mkdir(join(sourceRoot, ".git", "objects"), { recursive: true });
  await mkdir(join(sourceRoot, "src", "nested", "dist"), { recursive: true });
  await writeFile(join(sourceRoot, "src", "index.js"), "export const ok = true;\n");
  await writeFile(join(sourceRoot, "node_modules", "ignored.js"), "not source\n");
  await writeFile(join(sourceRoot, ".git", "HEAD"), "not indexed\n");
  await writeFile(join(sourceRoot, "src", "nested", "dist", "ignored.js"), "not source\n");
  for (let i = 0; i < 55; i++) await mkdir(join(sourceRoot, `generated-${String(i).padStart(2, "0")}`, "node_modules"), { recursive: true });
  process.env.WORKSPACE_ROOTS = scratch;
  const result = await api.intake.inspectSource({ type: "local_path", path: sourceRoot }, "wp8-intake");
  assert.equal(result.fileCount, 1);
  assert.ok(result.findings.some(item => item.code === "generated_content_skipped" && item.message.includes("node_modules")));
  const generated = result.findings.find(item => item.code === "generated_content_skipped");
  assert.match(generated.message, /\.git/);
  assert.match(generated.message, /omitted from this bounded report/);
  assert.ok(generated.message.length < 20_000);
});

test("local intake skips links and reports only bounded safe relative evidence", async t => {
  if (!api) return t.skip("API dist modules are unavailable; run npm --prefix apps/api run build");
  const sourceRoot = join(scratch, "link-sample");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(join(sourceRoot, "kept.txt"), "safe source");
  try { await symlink(join(sourceRoot, "kept.txt"), join(sourceRoot, "linked-secret.txt")); }
  catch (error) { return t.skip(`Filesystem symlink creation unavailable on this platform: ${error.code ?? error.message}`); }
  process.env.WORKSPACE_ROOTS = scratch;
  const result = await api.intake.inspectSource({ type: "local_path", path: sourceRoot }, "wp8-link");
  const linkFinding = result.findings.find(item => item.code === "intake_link_skipped");
  assert.equal(result.fileCount, 1);
  assert.ok(linkFinding?.message.includes("linked-secret.txt"));
  assert.ok(!linkFinding?.message.includes(sourceRoot));
  assert.equal((await lstat(join(sourceRoot, "linked-secret.txt"))).isSymbolicLink(), true);
});

test("local intake skips a real Windows junction without traversing its target", async t => {
  if (process.platform !== "win32") return t.skip("Windows junction fixture applies only on Windows");
  if (!api) return t.skip("API dist modules are unavailable; run npm --prefix apps/api run build");
  const sourceRoot = join(scratch, "junction-sample");
  const outsideRoot = join(scratch, "junction-outside");
  await Promise.all([mkdir(sourceRoot, { recursive: true }), mkdir(outsideRoot, { recursive: true })]);
  await writeFile(join(sourceRoot, "kept.txt"), "safe source");
  await writeFile(join(outsideRoot, "must-not-be-read.txt"), "junction target secret");
  const junctionPath = join(sourceRoot, "linked-directory");
  try { await symlink(outsideRoot, junctionPath, "junction"); }
  catch (error) { return t.skip(`Filesystem junction creation unavailable on this platform: ${error.code ?? error.message}`); }
  process.env.WORKSPACE_ROOTS = scratch;
  const result = await api.intake.inspectSource({ type: "local_path", path: sourceRoot }, "wp8-junction");
  const linkFinding = result.findings.find(item => item.code === "intake_link_skipped");
  assert.equal(result.fileCount, 1);
  assert.ok(linkFinding?.message.includes("linked-directory"));
  assert.ok(!linkFinding?.message.includes(sourceRoot));
  assert.equal((await lstat(junctionPath)).isSymbolicLink(), true);
});

test("ZIP intake excludes generated trees before file quotas and safely skips link entries", async t => {
  if (!api) return t.skip("API dist modules are unavailable; run npm --prefix apps/api run build");
  process.env.INTAKE_DIR = intakeDir();
  const result = await inspectZip("excluded.zip", [
    { name: "src/app.js", data: "export const ok = true;" },
    { name: "node_modules/oversized.js", data: Buffer.alloc(api.intake.LIMITS.fileBytes + 1, 65), deflate: true },
    { name: "nested/.git/config", data: "ignored" },
    { name: "linked.txt", data: "target-not-followed", mode: 0o120777 },
  ]);
  assert.equal(result.fileCount, 1);
  assert.ok(result.findings.some(item => item.code === "generated_content_skipped" && item.message.includes("node_modules")));
  assert.ok(result.findings.some(item => item.code === "intake_link_skipped" && item.message.includes("linked.txt")));
  assert.ok(result.findings.every(item => !item.message.includes(intakeDir())));
});

test("ZIP intake rejects malformed, traversal, special and hard-limit archives with safe reasons", async t => {
  if (!api) return t.skip("API dist modules are unavailable; run npm --prefix apps/api run build");
  process.env.INTAKE_DIR = intakeDir();
  await expectIntakeReason("malformed.zip", Buffer.from("not a zip SECRET_SOURCE_MARKER"), "intake_archive_malformed");
  await expectIntakeReason("traversal.zip", [{ name: "../SECRET_SOURCE_MARKER.txt", data: "secret" }], "intake_unsafe_entry");
  await expectIntakeReason("special.zip", [{ name: "device", data: "SECRET_SOURCE_MARKER", mode: 0o020644 }], "intake_unsafe_entry");
  await expectIntakeReason("oversized.zip", [{ name: "big.txt", data: Buffer.alloc(api.intake.LIMITS.fileBytes + 1), deflate: true }], "intake_limit_exceeded");
});

test("WP2 scope canonicalizes IDN/default ports and enforces exact origin", async t => {
  if (!api) return t.skip("API dist modules are unavailable; run npm --prefix apps/api run build");
  const scope = api.scope.createDiscoveryScope(validApproval({ origin: "http://BÜCHER.example:80" }));
  assert.equal(scope.host, "xn--bcher-kva.example");
  assert.equal(scope.port, 80);
  assert.equal(api.scope.assertUrlInDiscoveryScope("http://xn--bcher-kva.example/api/items", scope).pathname, "/api/items");
  assert.throws(() => api.scope.assertUrlInDiscoveryScope("http://other.example/api/items", scope));
  assert.throws(() => api.scope.assertUrlInDiscoveryScope("http://xn--bcher-kva.example:81/api/items", scope));
  const defaultHttps = api.scope.createDiscoveryScope(validApproval({ origin: "https://EXAMPLE.test:443", path_mode: "whole_origin", path_prefixes: [] }));
  assert.equal(defaultHttps.port, 443);
});

test("WP2 HTTP segment prefixes, HTTPS whole-origin and ambiguous path spellings fail closed", async t => {
  if (!api) return t.skip("API dist modules are unavailable; run npm --prefix apps/api run build");
  const scope = api.scope.createDiscoveryScope(validApproval());
  for (const path of ["/api", "/api/v1/health"]) assert.doesNotThrow(() => api.scope.assertUrlInDiscoveryScope(`http://example.test${path}`, scope));
  assert.throws(() => api.scope.assertUrlInDiscoveryScope("http://example.test/apix", scope));
  assert.throws(() => api.scope.assertUrlInDiscoveryScope("http://example.test/api%2Fadmin", scope));
  assert.throws(() => api.scope.assertUrlInDiscoveryScope("http://example.test/api%5cadmin", scope));
  assert.throws(() => api.scope.assertUrlInDiscoveryScope("http://example.test/api/%2e%2e/admin", scope));
  assert.throws(() => api.scope.assertUrlInDiscoveryScope("http://example.test/api/%ZZ", scope));
  assert.throws(() => api.scope.assertUrlInDiscoveryScope("http://example.test/api/%2e/health", scope));
  assert.throws(() => api.scope.createDiscoveryScope(validApproval({ origin: "https://example.test", path_mode: "prefix" })));
});

test("WP2 scope expiry, policy hash tampering, GET-only budgets and strict schemas", async t => {
  if (!api) return t.skip("API dist modules are unavailable; run npm --prefix apps/api run build");
  const scope = api.scope.createDiscoveryScope(validApproval());
  assert.equal(api.scope.verifyDiscoveryScope(scope), true);
  const altered = { ...scope, host: "evil.example" };
  assert.equal(api.scope.verifyDiscoveryScope(altered), false);
  assert.throws(() => api.scope.assertUrlInDiscoveryScope("http://example.test/api", scope, new Date("2030-01-01T00:00:00.000Z")));
  assert.deepEqual(scope.allowed_methods, ["GET"]);
  assert.equal(api.contracts.DiscoveryScopeSchema.safeParse({ ...scope, allowed_methods: ["POST"] }).success, false);
  assert.equal(api.contracts.DiscoveryBudgetProfileSchema.safeParse({ ...api.contracts.DEFAULT_DISCOVERY_BUDGET, retries: 1 }).success, false);
  assert.equal(api.contracts.DiscoveryBudgetProfileSchema.safeParse({ ...api.contracts.DEFAULT_DISCOVERY_BUDGET, unique_urls: 501 }).success, false);
  assert.equal(api.contracts.DiscoveryBudgetProfileSchema.safeParse({ ...api.contracts.DEFAULT_DISCOVERY_BUDGET, crawl_depth: 4 }).success, false);
  assert.equal(api.contracts.DiscoveryBudgetProfileSchema.safeParse({ ...api.contracts.DEFAULT_DISCOVERY_BUDGET, extra: true }).success, false);
  assert.equal(api.contracts.DiscoveryScopeSchema.safeParse({ ...scope, extra: true }).success, false);
});

