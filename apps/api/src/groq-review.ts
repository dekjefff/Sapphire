import { z } from "zod";
import type { ReviewModel } from "./code-review.js";
import { reviewInputSchema, reviewMessages, requestReviewJson } from "./review-model-request.js";

const model = "openai/gpt-oss-20b";
const endpoint = "https://api.groq.com/openai/v1/chat/completions";
const { $schema, ...schema } = reviewInputSchema;
const replySchema = z.object({
  choices: z.tuple([z.object({
    finish_reason: z.literal("stop"),
    message: z.object({
      content: z.string(),
      refusal: z.null().optional(),
      tool_calls: z.union([z.null(), z.tuple([])]).optional(),
    }),
  })]),
});

export function groqReview(apiKey: string, request: typeof fetch = fetch): ReviewModel {
  return {
    name: `groq:${model}`,
    async review(data) {
      const raw = await requestReviewJson(request, endpoint, {
        model,
        stream: false,
        max_completion_tokens: 2048,
        messages: reviewMessages(data),
        response_format: {
          type: "json_schema",
          json_schema: { name: "source_review", strict: true, schema },
        },
      }, apiKey);
      const reply = replySchema.parse(raw);
      return JSON.parse(reply.choices[0].message.content);
    },
  };
}
