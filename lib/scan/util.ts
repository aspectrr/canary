import { POPULAR_PACKAGES, SOURCE_EXTENSIONS } from "./patterns";
import type { Severity } from "../types";

/** Shared helpers for scanners. */

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** Higher = more severe. */
export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export function ext(path: string): string {
  const base = path.split("/").pop() ?? path;
  const dot = base.lastIndexOf(".");
  return dot >= 0 ? base.slice(dot).toLowerCase() : "";
}

export function basename(path: string): string {
  return path.split("/").pop() ?? path;
}

export function isSourceFile(path: string): boolean {
  return SOURCE_EXTENSIONS.has(ext(path));
}

/** Lines most relevant to a match, trimmed for display. */
export function snippetAround(
  content: string,
  index: number,
  width = 80,
): string {
  const start = Math.max(0, content.lastIndexOf("\n", index) + 1);
  let end = content.indexOf("\n", index);
  if (end === -1) end = content.length;
  const line = content.slice(start, end).trim();
  return line.length > width ? `${line.slice(0, width)}…` : line;
}

/** 1-based line number for a character index. */
export function lineNumber(content: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === "\n") n++;
  }
  return n;
}

/** Shannon entropy in bits/char — used to spot packed blobs. */
export function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Classic edit distance, bounded for speed. */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  let curr = new Array<number>(b.length + 1);
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length];
}

const TEST_FILE_RE =
  /(?:^|[-_./])(?:tests?|specs?|fuzz(?:er)?|bench(?:marks?)?|fixtures?|mocks?|stubs?)(?:[-_./]|$)/i;

/** Filenames that look like tests/benches/fixtures, not shipping code. */
export function isLikelyTestFile(path: string): boolean {
  const base = basename(path).toLowerCase();
  return /\.(?:test|spec)\.[^.]+$/i.test(base) || TEST_FILE_RE.test(base);
}

/** Find the closest popular package name within `maxDist` edits, or null. */
export function closestPopular(
  name: string,
  maxDist = 2,
): { name: string; dist: number } | null {
  const clean = name.replace(/^@[^/]+\//, "").toLowerCase();
  // Names shorter than 4 chars collide too easily to be meaningful.
  if (clean.length < 4) return null;
  let best: { name: string; dist: number } | null = null;
  for (const pop of POPULAR_PACKAGES) {
    const popClean = pop.replace(/^@[^/]+\//, "").toLowerCase();
    if (popClean.length < 4) continue;
    if (Math.abs(popClean.length - clean.length) > maxDist) continue;
    // Short names only match on a near-exact hit to avoid false alarms
    // (e.g. "node" vs "core", "foo" vs "koa" are distance 2 but unrelated).
    const allowed = clean.length < 6 || popClean.length < 6 ? 1 : maxDist;
    const d = levenshtein(clean, popClean);
    if (d > 0 && d <= allowed && (!best || d < best.dist)) {
      best = { name: pop, dist: d };
    }
  }
  return best;
}

