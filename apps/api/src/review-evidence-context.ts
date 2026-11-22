export type EvidenceContext = { first_line: number; lines: string[] };

const surroundingLines = 20;
const maxChars = 4000;

export function evidenceContext(lines: readonly string[], citation: number): EvidenceContext | undefined {
  const index = citation - 1;
  const cited = lines[index];
  if (cited === undefined || cited.length > maxChars) return undefined;

  let first = index;
  let end = index + 1;
  let length = cited.length;
  let before = true;
  let after = true;

  for (let distance = 1; distance <= surroundingLines && (before || after); distance++) {
    if (before) {
      const preceding = lines[index - distance];
      if (preceding !== undefined && length + preceding.length + 1 <= maxChars) {
        first--;
        length += preceding.length + 1;
      } else before = false;
    }
    if (after) {
      const next = lines[index + distance];
      if (next !== undefined && length + next.length + 1 <= maxChars) {
        end++;
        length += next.length + 1;
      } else after = false;
    }
  }

  return end - first > 1 ? { first_line: first + 1, lines: lines.slice(first, end) } : undefined;
}
