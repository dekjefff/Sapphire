import { z } from "zod";
import { isBuiltInLocalTargetHost, isConfiguredDiscoveryOrigin } from "./discovery/authorization-profiles.js";

const text = (max: number) => z.string().trim().min(1).max(max).refine((value) => !value.includes("\0"));
const discoveryAttestation = z.preprocess((value) => value === "true" ? true : value === "false" ? false : value, z.boolean().optional());

export const createAssessmentSchema = z.object({
  project_name: text(120),
  repository_path: text(2048),
  target_url: z.url().max(2048),
  source_type: z.literal("local_path").default("local_path"),
  runtime_discovery_authorized: discoveryAttestation,
}).strict();

export const createZipAssessmentSchema = z.object({
  project_name: text(120),
  target_url: z.url().max(2048).optional(),
  runtime_discovery_authorized: discoveryAttestation,
  ai_review_authorized: discoveryAttestation,
  ai_review_provider: z.enum(["groq", "qwencloud"]).optional(),
}).strict().refine(
  (input) => Boolean(input.target_url) || (input.ai_review_authorized === true && input.runtime_discovery_authorized !== true),
  { path: ["target_url"], message: "A target URL is required unless this is a source-only AI review" },
);

const pageOffset = z.coerce.number().int().min(0).max(1_000_000).default(0);
export const assessmentDetailQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  endpoint_cursor: pageOffset,
  match_cursor: pageOffset,
}).strict();

export function validateTarget(value: string): string {
  let target: URL;
  try { target = new URL(value); }
  catch { throw new Error("Target URL is invalid"); }
  if (!["http:", "https:"].includes(target.protocol) || target.hostname.includes("*") || target.hostname.endsWith(".")
    || (!isBuiltInLocalTargetHost(target.hostname) && !isConfiguredDiscoveryOrigin(target.origin))) {
    throw new Error("Foundation targets must be localhost or the isolated Juice Shop service");
  }
  if (target.username || target.password) throw new Error("Credentials in target URLs are not accepted");
  if (target.search || target.hash) throw new Error("Query and fragment data are not accepted in target URLs");
  return target.toString();
}
