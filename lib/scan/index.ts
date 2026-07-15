import type { Finding, RepoFile, RepoMeta } from "../types";
import { scanDependencies } from "./dependencies";
import { scanInstallScripts } from "./install-scripts";
import { scanObfuscation } from "./obfuscation";
import { scanSecretsAndEndpoints } from "./secrets-endpoints";
import { scanSignals, type RepoFlags } from "./signals";
import { severityRank } from "./util";

export type { RepoFlags };

export function runScans(
  meta: RepoMeta,
  files: RepoFile[],
  flags: RepoFlags,
  treeSize: number,
): Finding[] {
  const all: Finding[] = [
    ...scanSignals(meta, flags, treeSize),
    ...scanInstallScripts(files),
    ...scanDependencies(files),
    ...scanObfuscation(files),
    ...scanSecretsAndEndpoints(files),
  ];

  // Dedupe exact repeats (same rule in the same place).
  const seen = new Set<string>();
  const unique: Finding[] = [];
  for (const f of all) {
    const key = `${f.id}|${f.file ?? ""}|${f.line ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(f);
  }

  // Aggregate by rule id: the same rule firing in many files becomes one
  // finding that reports how widespread it is, instead of N identical cards.
  const byId = new Map<string, Finding[]>();
  for (const f of unique) {
    const arr = byId.get(f.id) ?? [];
    arr.push(f);
    byId.set(f.id, arr);
  }

  const out: Finding[] = [];
  for (const arr of byId.values()) {
    arr.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    const rep: Finding = { ...arr[0] };
    if (arr.length > 1) {
      rep.locations = arr.length;
      rep.detail = `${rep.detail} Found in ${arr.length} location${arr.length === 1 ? "" : "s"}.`;
    }
    out.push(rep);
  }

  return out;
}
