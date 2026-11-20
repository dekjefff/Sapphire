import { z } from "zod";
import { ReviewModelRequestError, type ReviewModel } from "./code-review.js";
import { reviewInputSchema, reviewMessages, requestReviewJson } from "./review-model-request.js";

const model = "openai/gpt-oss-20b";
const endpoint = "https://api.groq.com/openai/v1/chat/completions";
const { $schema, ...schema } = reviewInputSchema;
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

export function groqReview(apiKey: string, request: typeof fetch = fetch): ReviewModel {
  return {
    name: `groq:${model}`,
    async review(data, signal) {
      const raw = await requestReviewJson(request, endpoint, {
        model,
        stream: false,
        max_completion_tokens: 2048,
        messages: reviewMessages(data),
        response_format: {
          type: "json_schema",
          json_schema: { name: "source_review", strict: true, schema },
        },
      }, apiKey, signal);
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
