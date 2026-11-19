import { z } from "zod";
import type { ReviewModel } from "./code-review.js";
import { reviewInputSchema, reviewMessages, requestReviewJson } from "./review-model-request.js";

const endpoint = "http://127.0.0.1:11434/api/chat";
const replySchema = z.object({
  done: z.literal(true),
  done_reason: z.literal("stop"),
  message: z.object({ content: z.string() }),
});

export function ollamaReview(model: string, request: typeof fetch = fetch): ReviewModel {
  if (!/^[\w.-]+(?::[\w.-]+)?$/.test(model) || /cloud/i.test(model)) {
    throw new Error("Choose the name of an installed local Ollama model");
  }
  return {
    name: `ollama:${model}`,
    async review(data) {
      const raw = await requestReviewJson(request, endpoint, {
        model,
        stream: false,
        format: reviewInputSchema,
        options: { temperature: 0, num_ctx: 32_768, num_predict: 2048 },
        messages: reviewMessages(data),
      });
      const reply = replySchema.parse(raw);
      return JSON.parse(reply.message.content);
    },
  };
}
