import { z } from "zod";
import { ReviewModelRequestError, type ReviewMetrics, type ReviewModel } from "./code-review.js";
import { reviewInputSchema, reviewMessages, requestReviewJson } from "./review-model-request.js";

const model = "openai/gpt-oss-20b";
const endpoint = "https://api.groq.com/openai/v1/chat/completions";
const { $schema, ...schema } = reviewInputSchema;
const usageSchema = z.object({
  usage: z.object({
    prompt_tokens: z.number().int().positive().max(1_000_000),
    total_tokens: z.number().int().positive().max(1_000_000),
  }),
});
const replySchema = z.object({
  choices: z.tuple([z.object({
    finish_reason: z.string(),
    message: z.object({
      content: z.string().nullable(),
      refusal: z.string().nullable().optional(),
      tool_calls: z.union([z.null(), z.tuple([])]).optional(),
    }),
  })]),
});

function rateMetrics(headers: Headers): ReviewMetrics {
  const remaining = headers.get("x-ratelimit-remaining-tokens");
  const reset = headers.get("x-ratelimit-reset-tokens");
  if (!remaining || !/^\d{1,9}$/.test(remaining) || !reset || !/^(?:\d+(?:\.\d+)?(?:m|s))+$/.test(reset)) return {};
  let milliseconds = 0;
  for (const [, amount, unit] of reset.matchAll(/(\d+(?:\.\d+)?)(m|s)/g)) {
    milliseconds += Number(amount) * (unit === "m" ? 60_000 : 1000);
  }
  return Number.isFinite(milliseconds) ? { remainingTokens: Number(remaining), resetAfterMs: Math.min(milliseconds, 60_000) } : {};
}

export function groqReview(apiKey: string, request: typeof fetch = fetch): ReviewModel {
  return {
    name: `groq:${model}`,
    async review(data, signal, observe) {
      const raw = await requestReviewJson(request, endpoint, {
        model,
        stream: false,
        reasoning_effort: "low",
        max_completion_tokens: 2048,
        messages: reviewMessages(data),
        response_format: {
          type: "json_schema",
          json_schema: { name: "source_review", strict: true, schema },
        },
      }, apiKey, signal, observe ? headers => observe(rateMetrics(headers)) : undefined);
      const metrics = usageSchema.safeParse(raw);
      if (metrics.success && metrics.data.usage.prompt_tokens <= metrics.data.usage.total_tokens) {
        observe?.({ promptTokens: metrics.data.usage.prompt_tokens, totalTokens: metrics.data.usage.total_tokens });
      }
      const reply = replySchema.safeParse(raw);
      if (!reply.success) throw new ReviewModelRequestError("model_invalid_response");
      const { finish_reason, message } = reply.data.choices[0];
      if (finish_reason === "length") throw new ReviewModelRequestError("model_response_truncated");
      if (finish_reason !== "stop" || message.refusal) throw new ReviewModelRequestError("model_response_rejected");
      if (message.content === null) throw new ReviewModelRequestError("model_invalid_response");
      try {
        return JSON.parse(message.content);
      } catch {
        throw new ReviewModelRequestError("model_invalid_response");
      }
    },
  };
}
