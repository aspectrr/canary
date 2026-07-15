import type { PackageRef, Severity, VulnHit } from "./types";

/**
 * Looks up known vulnerabilities for the repo's declared dependencies via
 * OSV.dev (the open vulnerability database that powers GitHub's alerts).
 *
 * Free, unauthenticated, batched. We query versions in one batch call, then
 * fetch details for the first N hits so we can show severity + summary.
 */

const BATCH = "https://api.osv.dev/v1/querybatch";
const DETAIL = "https://api.osv.dev/v1/vulns";

const MAX_QUERIES = 80; // keep one batch payload sane
const MAX_DETAILS = 12; // bound the number of detail fetches

interface BatchResult {
  results: { vulns?: { id: string }[] }[] | null;
}

function severityFromVector(vectors?: { score?: string }[]): Severity {
  for (const v of vectors ?? []) {
    const s = v.score ?? "";
    if (/CRITICAL/i.test(s)) return "critical";
    if (/HIGH/i.test(s)) return "high";
    if (/MEDIUM|MODERATE/i.test(s)) return "medium";
    if (/LOW/i.test(s)) return "low";
  }
  return "medium";
}

function firstFixed(record: unknown, pkgName: string): string | undefined {
  try {
    const affected = (record as { affected?: { package?: { name?: string }; ranges?: { events?: { fixed?: string }[] }[] }[] }).affected;
    for (const a of affected ?? []) {
      if (a.package?.name?.toLowerCase() !== pkgName.toLowerCase()) continue;
      for (const r of a.ranges ?? []) {
        for (const ev of r.events ?? []) if (ev.fixed) return ev.fixed;
      }
    }
  } catch {
    /* ignore */
  }
  return undefined;
}

export async function queryVulnerabilities(
  packages: PackageRef[],
): Promise<VulnHit[]> {
  const refs = packages.slice(0, MAX_QUERIES);
  if (!refs.length) return [];

  // 1. Batch query.
  let batch: BatchResult;
  try {
    const res = await fetch(BATCH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: refs.map((p) => ({
          package: { name: p.name, ecosystem: p.ecosystem },
          version: p.version,
        })),
      }),
    });
    if (!res.ok) return [];
    batch = (await res.json()) as BatchResult;
  } catch {
    return [];
  }

  // 2. Collect vuln ids per package.
  type Pending = { ref: PackageRef; ids: string[] };
  const pending: Pending[] = [];
  const allIds = new Set<string>();
  (batch.results ?? []).forEach((r, i) => {
    const ids = (r?.vulns ?? []).map((v) => v.id).filter(Boolean);
    if (!ids.length) return;
    pending.push({ ref: refs[i], ids });
    for (const id of ids) allIds.add(id);
  });

  if (!allIds.size) return [];

  // 3. Fetch details for a bounded set (concurrent).
  const idsToFetch = [...allIds].slice(0, MAX_DETAILS);
  const details = await Promise.all(
    idsToFetch.map(async (id): Promise<Record<string, unknown> | null> => {
      try {
        const res = await fetch(`${DETAIL}/${encodeURIComponent(id)}`);
        if (!res.ok) return null;
        return (await res.json()) as Record<string, unknown>;
      } catch {
        return null;
      }
    }),
  );
  const detailById = new Map<string, Record<string, unknown>>();
  idsToFetch.forEach((id, i) => {
    if (details[i]) detailById.set(id, details[i]!);
  });

  // 4. Build hits (dedupe by vuln id + package).
  const seen = new Set<string>();
  const hits: VulnHit[] = [];
  for (const { ref, ids } of pending) {
    for (const id of ids) {
      const key = `${id}@${ref.ecosystem}:${ref.name.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const d = detailById.get(id);
      const sevVectors = (d?.severity as { type?: string; score?: string }[]) ?? undefined;
      const rawSeverity = sevVectors?.[0]?.type ?? undefined;
      hits.push({
        id,
        package: ref.name,
        ecosystem: ref.ecosystem,
        version: ref.version,
        severity: severityFromVector(sevVectors),
        rawSeverity,
        summary: (d?.summary as string) ?? (d?.details as string | undefined)?.slice(0, 160),
        url: (d?.references as { type?: string; url?: string }[] | undefined)?.find((r) => r?.type?.toUpperCase() === "ADVISORY")?.url,
        fixedIn: d ? firstFixed(d, ref.name) : undefined,
      });
    }
  }

  // Crits/highs first, then by id.
  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  hits.sort((a, b) => (rank[a.severity] - rank[b.severity]) || a.id.localeCompare(b.id));
  return hits;
}
