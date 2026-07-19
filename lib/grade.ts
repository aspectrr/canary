import type { Finding, RepoMeta, Severity, Verdict } from "./types";
import { severityRank } from "./scan/util";

/**
 * Turns aggregated findings into a verdict and a 0-100 safety score.
 *
 * Conservative by design: it takes red flags seriously and is slow to call
 * something "safe." But common low-severity patterns (a CLI using
 * child_process, one ordinary postinstall) don't single-handedly condemn an
 * established, well-regarded project.
 */

// Per-rule penalty (findings are already aggregated, so each rule counts once).
const PENALTY: Record<Severity, number> = {
  critical: 100,
  high: 25,
  medium: 8,
  low: 1.5,
  info: 0.2,
};

const BAND: Record<Verdict, [number, number]> = {
  risky: [5, 40],
  caution: [45, 74],
  safe: [75, 100],
  unknown: [0, 0],
};

export interface Grade {
  verdict: Verdict;
  score: number;
  counts: Record<Severity, number>;
  goodSignals: Finding[];
  concerns: Finding[];
  headline: string;
}

function emptyCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

const clamp = (n: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, n));

export function grade(
  findings: Finding[],
  meta: RepoMeta,
  treeSize: number,
): Grade {
  const goodSignals = findings.filter((f) => f.id.startsWith("signal.good."));
  const concerns = findings
    .filter((f) => !f.id.startsWith("signal.good."))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  const counts = emptyCounts();
  for (const c of concerns) counts[c.severity]++;

  if (treeSize === 0) {
    return {
      verdict: "unknown",
      score: 0,
      counts,
      goodSignals,
      concerns,
      headline:
        "There wasn't enough in this repository to evaluate. It may be empty.",
    };
  }

  const ageDays = Math.max(
    0,
    Math.round((Date.now() - new Date(meta.createdAt).getTime()) / 86_400_000),
  );
  const ownerAge = meta.ownerCreatedAt
    ? Math.max(
        0,
        Math.round((Date.now() - new Date(meta.ownerCreatedAt).getTime()) / 86_400_000),
      )
    : 9999;
  const sketchyOrigin = ageDays < 30 && ownerAge < 60;

  const { critical, high, medium, low } = counts;
  const goodCount = goodSignals.length;

  let verdict: Verdict;
  if (critical > 0 || high >= 2 || (high >= 1 && sketchyOrigin)) {
    verdict = "risky";
  } else if (high === 1) {
    verdict = "caution";
  } else if (medium >= 1) {
    // A strong track record forgives a few medium-grade notes (e.g. a bundler
    // that legitimately uses `new Function` / `vm`, with a normal postinstall).
    verdict = medium <= 3 && goodCount >= 4 ? "safe" : "caution";
  } else if (low >= 1) {
    verdict = goodCount >= 2 ? "safe" : "caution";
  } else {
    verdict = goodCount >= 2 ? "safe" : "caution";
  }

  let raw = 100;
  for (const c of concerns) raw -= PENALTY[c.severity];
  raw += Math.min(goodCount, 5) * 2;
  const [lo, hi] = BAND[verdict];
  const score = clamp(Math.round(clamp(raw, 0, 100)), lo, hi);

  const headline = makeHeadline(verdict, counts, goodCount, sketchyOrigin);

  return { verdict, score, counts, goodSignals, concerns, headline };
}

function makeHeadline(
  verdict: Verdict,
  counts: Record<Severity, number>,
  goodCount: number,
  sketchyOrigin: boolean,
): string {
  switch (verdict) {
    case "risky":
      if (counts.critical > 0)
        return "This project shows strong signs of being dangerous. Avoid using it until you understand exactly what's going on.";
      return sketchyOrigin
        ? "High risk: serious red flags from a very new account. Be very cautious."
        : "There are real red flags here. Use this only if you can investigate the warnings yourself.";
    case "caution":
      return counts.high > 0
        ? "This project is probably usable, but there's at least one thing worth checking before you rely on it."
        : "Nothing obviously malicious, but a few details are worth a closer look before you depend on this.";
    case "safe":
      return goodCount >= 4
        ? "This looks like a normal, well-run project. The usual cautions about third-party code still apply."
        : "Nothing suspicious turned up, and there are some signs this is a legitimate project.";
    case "unknown":
    default:
      return "There wasn't enough here to make a call. Treat it as unknown.";
  }
}
