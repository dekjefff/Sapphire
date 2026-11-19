import { z } from "zod";

// Metadata supplied by the local caller describes existing evidence; no source is opened here.
const id = z.string().min(1).max(120).regex(/^[a-zA-Z0-9._-]+$/);
const count = z.number().int().min(0).max(1_000_000);
const checkId = z.enum(["dependency-manifest", "input-validation", "authorization-boundaries"]);
const flag = z.enum(["manifest", "web", "authorization"]);
const coverage = z.enum(["covered", "partial", "unknown"]);
const estimate = z.object({ minutes: count, requests: count, tokens: count }).strict();

export const proposalSchema = z.object({
  check_id: checkId,
  scope_id: id,
  rationale: z.string().min(1).max(500),
  coverage: coverage,
  evidence_gap: z.string().min(1).max(500),
  evidence_ids: z.array(id).max(20),
  estimate,
}).strict();

const approvalSchema = z.object({ check_id: checkId, scope_id: id, approved_by: id }).strict();
export const plannerInputSchema = z.object({
  scope: z.object({ id }).strict(),
  flags: z.array(flag).max(3),
  coverage: z.array(z.object({ check_id: checkId, status: coverage }).strict()).max(3),
  approvals: z.array(approvalSchema).max(3),
  budget: estimate,
}).strict().superRefine((input, ctx) => {
  for (const [name, values] of [["flags", input.flags], ["coverage", input.coverage.map(x => x.check_id)], ["approvals", input.approvals.map(x => x.check_id)]] as const) {
    if (new Set(values).size !== values.length) ctx.addIssue({ code: "custom", path: [name], message: "Duplicate entries are not allowed" });
  }
  input.approvals.forEach((approval, index) => {
    if (approval.scope_id !== input.scope.id) ctx.addIssue({ code: "custom", path: ["approvals", index, "scope_id"], message: "Approval must match authorized scope" });
  });
});

export const decisionSchema = z.object({
  proposal: proposalSchema,
  decision: z.enum(["proposed", "rejected"]),
  reason: z.enum(["eligible", "already-covered", "approval-required", "budget-exceeded"]),
  approval: approvalSchema.optional(),
}).strict();
export type Proposal = z.infer<typeof proposalSchema>;
export type Decision = z.infer<typeof decisionSchema>;
export type PlannerInput = z.infer<typeof plannerInputSchema>;

const catalog = [
  { check_id: "authorization-boundaries", flag: "authorization", priority: 3, approval: true, rationale: "Review authorization decisions at trust boundaries.", gap: "Authorization boundary review is incomplete or unrecorded.", estimate: { minutes: 30, requests: 0, tokens: 0 } },
  { check_id: "input-validation", flag: "web", priority: 2, approval: false, rationale: "Review validation of input at application boundaries.", gap: "Input validation review is incomplete or unrecorded.", estimate: { minutes: 20, requests: 0, tokens: 0 } },
  { check_id: "dependency-manifest", flag: "manifest", priority: 1, approval: false, rationale: "Review declared dependencies and their maintenance evidence.", gap: "Dependency manifest review is incomplete or unrecorded.", estimate: { minutes: 10, requests: 0, tokens: 0 } },
] as const;

/** Deterministically proposes human source-review work from trusted metadata, without accessing sources. */
export function planSourceReview(raw: unknown) {
  return evaluateSourceReview(raw);
}

/** Optional selections are untrusted; all proposal details come from trusted input and the catalog. */
export function evaluateSourceReview(raw: unknown, rawProposals?: unknown) {
  const input = plannerInputSchema.parse(raw);
  const used = { minutes: 0, requests: 0, tokens: 0 };
  const decisions: Decision[] = [];
  let candidates = catalog.filter(item => input.flags.includes(item.flag)).map(item => ({
    item, status: input.coverage.find(c => c.check_id === item.check_id)?.status ?? "unknown" as const,
  })).sort((a, b) => {
    const rank = { unknown: 0, partial: 1, covered: 2 };
    return rank[a.status] - rank[b.status] || b.item.priority - a.item.priority || a.item.check_id.localeCompare(b.item.check_id, "en");
  });
  if (rawProposals !== undefined) {
    const selections = z.array(z.object({ check_id: checkId, scope_id: id }).strict()).max(3).parse(rawProposals);
    if (new Set(selections.map(p => p.check_id)).size !== selections.length) throw new Error("Duplicate selections are not allowed");
    candidates = selections.map(selection => {
      if (selection.scope_id !== input.scope.id) throw new Error("Selection is outside authorized scope");
      const candidate = candidates.find(c => c.item.check_id === selection.check_id);
      if (!candidate) throw new Error("Selection is unavailable for the supplied flags");
      return candidate;
    });
  }
  for (const { item, status } of candidates) {
    const proposal = proposalSchema.parse({ check_id: item.check_id, scope_id: input.scope.id, rationale: item.rationale, coverage: status, evidence_gap: status === "covered" ? "No coverage gap reported; verify evidence if scope changes." : item.gap, evidence_ids: [], estimate: item.estimate });
    const approval = input.approvals.find(a => a.check_id === item.check_id);
    const fits = (Object.keys(used) as (keyof typeof used)[]).every(key => used[key] + proposal.estimate[key] <= input.budget[key]);
    const reason = status === "covered" ? "already-covered" : item.approval && !approval ? "approval-required" : !fits ? "budget-exceeded" : "eligible";
    if (reason === "eligible") for (const key of Object.keys(used) as (keyof typeof used)[]) used[key] += proposal.estimate[key];
    decisions.push(decisionSchema.parse({ proposal, decision: reason === "eligible" ? "proposed" : "rejected", reason, ...(approval ? { approval } : {}) }));
  }
  return { scope: { ...input.scope }, decisions, budget: { limit: { ...input.budget }, estimated_used: used } };
}
