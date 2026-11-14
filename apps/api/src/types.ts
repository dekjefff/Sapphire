export const QUEUE_NAME = "sapphire:jobs";

export type JobMessage = { job_id: string; assessment_id: string };
export type JobStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_PATTERN.test(value);
}
