import { getReasonCode } from "../reason-codes.js";

/** Intake and discovery coverage gaps are determined only by the shared reason catalog. */
export function hasCoverageGaps(reasonCodes: readonly unknown[]): boolean {
  return reasonCodes.some((code) => getReasonCode(code)?.coverage_impact === "incomplete");
}
