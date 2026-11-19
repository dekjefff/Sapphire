import { incompleteCodeReview, reviewCode } from "./code-review.js";
import { groqReview } from "./groq-review.js";
import { ollamaReview } from "./ollama-review.js";

const [project, report, provider, ...files] = process.argv.slice(2);
const groqKey = provider === "--groq" ? process.env.GROQ_API_KEY?.trim() : undefined;
let result;
try {
  if (!project || !report || !provider || files.length === 0) {
    console.error("Usage: npm run --silent review:code -- <project> <audit.json> <--groq|local-model> <file> [more-files...]");
    result = incompleteCodeReview("invalid_arguments");
  } else if (provider === "--groq" && !groqKey) {
    console.error("Set GROQ_API_KEY before using --groq.");
    result = incompleteCodeReview("missing_groq_api_key");
  } else {
    const model = groqKey ? groqReview(groqKey) : ollamaReview(provider);
    result = await reviewCode(project, report, files, model);
  }
} catch {
  result = incompleteCodeReview("local_review_error");
}
console.log(JSON.stringify(result, null, 2));
process.exitCode = result.status === "reviewed" ? 0 : 2;
