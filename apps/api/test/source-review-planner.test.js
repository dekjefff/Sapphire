import test from "node:test";
import assert from "node:assert/strict";
import { planSourceReview, evaluateSourceReview, proposalSchema } from "../dist/source-review-planner.js";
const input = () => ({ scope: { id: "repo-1" }, flags: ["manifest", "web", "authorization"], coverage: [], approvals: [], budget: { minutes: 30, requests: 0, tokens: 0 } });
test("stable ordering, exact budget boundary and explicit rejections", () => {
  const value = input();
  const result = planSourceReview(value);
  assert.deepEqual(result, planSourceReview({ ...value, flags: [...value.flags].reverse() }));
  assert.deepEqual(result.decisions.map(d => d.reason), ["approval-required", "eligible", "eligible"]);
  assert.equal(result.budget.estimated_used.minutes, 30);
  assert.equal(planSourceReview({ ...value, budget: { ...value.budget, minutes: 29 } }).decisions[2].reason, "budget-exceeded");
});
test("coverage and trusted scoped approval affect decisions", () => {
  const value = input();
  value.coverage = [{ check_id: "input-validation", status: "covered" }];
  value.approvals = [{ check_id: "authorization-boundaries", scope_id: "repo-1", approved_by: "reviewer" }];
  const result = planSourceReview(value);
  assert.equal(result.decisions[0].reason, "eligible");
  assert.equal(result.decisions.find(d => d.proposal.check_id === "input-validation").reason, "already-covered");
  assert.throws(() => planSourceReview({ ...value, approvals: [{ ...value.approvals[0], scope_id: "other" }] }));
});
test("strict validation rejects unknown fields, coverage, duplicates and overflows", () => {
  const value = input();
  assert.throws(() => planSourceReview({ ...value, target_url: "http://example.test" }));
  assert.throws(() => planSourceReview({ ...value, coverage: [{ check_id: "other", status: "unknown" }] }));
  assert.throws(() => planSourceReview({ ...value, coverage: [{ check_id: "input-validation", status: "unrecognized" }] }));
  assert.throws(() => planSourceReview({ ...value, flags: ["web", "web"] }));
  assert.throws(() => planSourceReview({ ...value, budget: { ...value.budget, minutes: Number.MAX_SAFE_INTEGER + 1 } }));
  assert.equal(proposalSchema.safeParse({ ...planSourceReview(value).decisions[0].proposal, extra: true }).success, false);
});

test("policy accepts ordered subsets and derives trusted proposal details", () => {
  const value = input();
  const selected = [{ check_id: "dependency-manifest", scope_id: "repo-1" }, { check_id: "input-validation", scope_id: "repo-1" }];
  const result = evaluateSourceReview({ ...value, budget: { ...value.budget, minutes: 20 } }, selected);
  assert.deepEqual(result.decisions.map(d => d.proposal.check_id), selected.map(s => s.check_id));
  assert.deepEqual(result.decisions.map(d => d.reason), ["eligible", "budget-exceeded"]);
  assert.deepEqual(result.decisions[0].proposal.evidence_ids, []);
  assert.deepEqual(evaluateSourceReview(value, []).decisions, []);
  for (const selections of [
    [{ ...selected[0], scope_id: "other" }],
    [{ ...selected[0], estimate: { minutes: 0 } }],
    [{ ...selected[0], coverage: "covered" }],
    [{ check_id: "invalid", scope_id: "repo-1" }],
    [selected[0], selected[0]],
  ]) assert.throws(() => evaluateSourceReview(value, selections));
  assert.throws(() => evaluateSourceReview({ ...value, flags: ["web"] }, [selected[0]]));
});
