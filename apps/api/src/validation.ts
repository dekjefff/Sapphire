import { z } from "zod";

const text = (max: number) => z.string().trim().min(1).max(max).refine((value) => !value.includes("\0"));

export const createAssessmentSchema = z.object({
  project_name: text(120),
  repository_path: text(2048),
  target_url: z.url().max(2048),
  source_type: z.literal("local_path").default("local_path"),
}).strict();

export const createZipAssessmentSchema = z.object({
  project_name: text(120),
  target_url: z.url().max(2048),
}).strict();

export function validateTarget(value: string): string {
  let target: URL;
  try { target = new URL(value); }
  catch { throw new Error("Target URL is invalid"); }
  const allowed = new Set(["localhost", "127.0.0.1", "[::1]", "juiceshop"]);
  if (!["http:", "https:"].includes(target.protocol) || !allowed.has(target.hostname.toLowerCase())) {
    throw new Error("Foundation targets must be localhost or the isolated Juice Shop service");
  }
  if (target.username || target.password) throw new Error("Credentials in target URLs are not accepted");
  return target.toString();
}
