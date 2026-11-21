import { model as groqModel } from "./groq-review.js";
import { model as qwenModel } from "./qwen-review.js";

export type ProjectReviewProvider = "groq" | "qwencloud";

export function projectReviewKeys(): Record<ProjectReviewProvider, string | undefined> {
  return {
    groq: process.env.GROQ_API_KEY?.trim() || undefined,
    qwencloud: process.env.DASHSCOPE_API_KEY?.trim() || undefined,
  };
}

export function projectReviewCatalog() {
  const keys = projectReviewKeys();
  const preferred = process.env.SAPPHIRE_PROJECT_REVIEW_PROVIDER === "groq" ? "groq" : "qwencloud";
  return {
    preferred,
    models: [
      { provider: "qwencloud", model: qwenModel, available: Boolean(keys.qwencloud) },
      { provider: "groq", model: groqModel, available: Boolean(keys.groq) },
    ],
  };
}
