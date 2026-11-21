export const maxReviewAttempts = 4;

export function reviewBackoffMs(attempt: number, retryAfterMs = 0) {
  return Math.max(2_000 * 2 ** (attempt - 1), retryAfterMs);
}

const retryableDependencyFailures = new Set([
  "timeout", "scanner_runner_timeout", "scanner_runner_failure", "runner_failure",
  "scanner_exit_nonzero", "scanner_incomplete", "scanner_json_invalid", "trivy_json_invalid",
]);

export function shouldRetryDependencyScan(reason: string | null, attempt: number) {
  return attempt < maxReviewAttempts && reason !== null && retryableDependencyFailures.has(reason);
}
