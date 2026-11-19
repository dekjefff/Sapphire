import { incompleteCodeReview, reviewCode } from "./code-review.js";
import { ollamaReview } from "./ollama-review.js";

const [project, report, model, ...files] = process.argv.slice(2);
let result;
try {
  if (!project || !report || !model || files.length === 0) {
    console.error("Usage: npm run --silent review:code -- <project> <audit.json> <local-model> <file> [more-files...]");
    result = incompleteCodeReview("invalid_arguments");
  } else {
    result = await reviewCode(project, report, files, ollamaReview(model));
  }
} catch {
  result = incompleteCodeReview("local_review_error");
}
console.log(JSON.stringify(result, null, 2));
process.exitCode = result.status === "reviewed" ? 0 : 2;
