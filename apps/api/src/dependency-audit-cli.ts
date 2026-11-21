import { resolve } from "node:path";
import { auditDependencies, incompleteDependencyAudit } from "./dependency-audit.js";

const [directory, ...extra] = process.argv.slice(2);
const npmCli = process.env.npm_execpath;

function writeResult(result: Awaited<ReturnType<typeof auditDependencies>>) {
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = { clean: 0, findings: 1, incomplete: 2 }[result.status];
}

if (!directory || extra.length || !npmCli) {
  console.error("Usage: npm run --silent audit:dependencies -- <npm-package-directory>");
  writeResult(incompleteDependencyAudit("invalid_arguments"));
} else {
  try {
    writeResult(await auditDependencies(resolve(directory), npmCli));
  } catch {
    writeResult(incompleteDependencyAudit("local_audit_error"));
  }
}
