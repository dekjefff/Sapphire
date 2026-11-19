import { open } from "node:fs/promises";
import { constants } from "node:fs";
import { resolve } from "node:path";
import { normalizeZapReport } from "./zap-report.js";

const MAX_REPORT_BYTES = 10 * 1024 * 1024;

async function readReport(path: string): Promise<Buffer | null> {
  // Mapped drives and symlinks can still point to remote storage.
  if (process.platform === "win32" && resolve(path).startsWith("\\\\")) {
    process.stderr.write("zap_report_read_failed\n");
    return null;
  }
  try {
    const flags = constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NONBLOCK);
    const file = await open(path, flags);
    try {
      if (!(await file.stat()).isFile()) throw new Error("not a regular file");
      const chunks: Buffer[] = [];
      let bytes = 0;
      for await (const chunk of file.createReadStream({ end: MAX_REPORT_BYTES, autoClose: false })) {
        bytes += chunk.length;
        if (bytes > MAX_REPORT_BYTES) {
          process.stderr.write("zap_report_size_limit\n");
          return null;
        }
        chunks.push(chunk);
      }
      return Buffer.concat(chunks, bytes);
    } finally {
      await file.close();
    }
  } catch {
    process.stderr.write("zap_report_read_failed\n");
    return null;
  }
}

async function main(): Promise<number> {
  if (process.argv.length !== 3) {
    process.stderr.write("Usage: node apps/api/dist/zap-report-cli.js <report.json>\n");
    return 2;
  }

  const bytes = await readReport(process.argv[2]);
  if (bytes === null) return 1;

  try {
    const raw: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    process.stdout.write(JSON.stringify(normalizeZapReport(raw), null, 2) + "\n");
    return 0;
  } catch {
    process.stderr.write("zap_report_invalid_or_unsupported\n");
    return 1;
  }
}

process.exitCode = await main();
