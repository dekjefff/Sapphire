import { z } from "zod";
import { modelReviewSchema, ReviewModelRequestError, type ReviewModel } from "./code-review.js";
import { reviewInputSchema, reviewMessages, requestReviewJson } from "./review-model-request.js";

export const model = "qwen3.7-flash";
const endpoint = "https://ap-southeast-1.maas.qwencloudapi.com/compatible-mode/v1/chat/completions";
const defaultCompletionTokens = 2048;
const { $schema, ...schema } = reviewInputSchema;
const replySchema = z.object({
  choices: z.tuple([z.object({
    finish_reason: z.string(),
    message: z.object({
      content: z.string().nullable(),
      refusal: z.string().nullable().optional(),
      tool_calls: z.tuple([]).nullable().optional(),
    }),
  })]),
});
const usageSchema = z.object({
  usage: z.object({
    prompt_tokens: z.number().int().positive(),
    total_tokens: z.number().int().positive(),
  }),
});

export function qwenReview(key: string, request: typeof fetch = fetch): ReviewModel {
  return {
    name: `qwencloud:${model}`,
    async review(data, signal, observe) {
      const raw = await requestReviewJson(request, endpoint, {
        model, stream: false, enable_thinking: false, max_completion_tokens: defaultCompletionTokens,
        messages: reviewMessages(data),
        response_format: {
          type: "json_schema",
          json_schema: { name: "source_review", strict: true, schema },
        },
      }, key, signal);

      const usage = usageSchema.safeParse(raw);
      if (usage.success && usage.data.usage.prompt_tokens <= usage.data.usage.total_tokens) {
        observe?.({ promptTokens: usage.data.usage.prompt_tokens, totalTokens: usage.data.usage.total_tokens });
      }
      const reply = replySchema.safeParse(raw);
      if (!reply.success) throw new ReviewModelRequestError("model_invalid_response");
      const { finish_reason, message } = reply.data.choices[0];
      if (finish_reason === "length") throw new ReviewModelRequestError("model_response_truncated");
      if (finish_reason !== "stop" || message.refusal) throw new ReviewModelRequestError("model_response_rejected");
      if (message.content === null) throw new ReviewModelRequestError("model_invalid_response");
      try {
        return modelReviewSchema.parse(JSON.parse(message.content));
      } catch {
        throw new ReviewModelRequestError("model_invalid_response");
      }
    },
  };
}
