import { getReasonCode, isReasonCode, type ReasonCode } from "./reason-codes.js";

export type IntakeReasonCode = Extract<ReasonCode, `intake_${string}`>;

export class IntakeError extends Error {
  readonly reasonCode: IntakeReasonCode;

  constructor(reasonCode: IntakeReasonCode) {
    super(reasonCode);
    this.name = "IntakeError";
    this.reasonCode = reasonCode;
  }
}

export function isIntakeReasonCode(value: unknown): value is IntakeReasonCode {
  return isReasonCode(value) && value.startsWith("intake_");
}

export function intakeReasonMessage(reasonCode: IntakeReasonCode): string {
  return getReasonCode(reasonCode)?.message ?? "Source intake could not be completed safely.";
}

export function intakeReasonCode(error: unknown): IntakeReasonCode {
  return error instanceof IntakeError && isIntakeReasonCode(error.reasonCode)
    ? error.reasonCode
    : "intake_archive_malformed";
}
