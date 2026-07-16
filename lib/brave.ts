/**
 * Brave Search client.
 *
 * Docs: https://api-dashboard.search.brave.com/app/documentation/web-search/get-started
 * Endpoint: GET https://api.search.brave.com/res/v1/web/search
 * Auth: X-Subscription-Token header.
 *
 * Env:
 *   BRAVE_SEARCH_API_KEY  (required for web search; without it, search is skipped)
 *
 * Web search is an ENRICHMENT layer, not a hard requirement. When the key is
 * missing or a request fails, we return an empty array and the rest of the
 * pipeline continues unaffected.
 */

import type { WebResult } from "./types";

const BASE = "https://api.search.brave.com/res/v1/web/search";

export function isConfigured(): boolean {
  return Boolean(process.env.BRAVE_SEARCH_API_KEY);
}

interface BraveResponse {
  web?: {
    results?: Array<{
      title?: string;
      url?: string;
      description?: string;
      extra_snippets?: string[];
    }>;
  };
}

/**
 * Run a web search and return normalized results. Returns [] when not
 * configured or on any failure (search never blocks an investigation).
 */
export async function searchWeb(query: string, count = 6): Promise<WebResult[]> {
  const key = process.env.BRAVE_SEARCH_API_KEY;
  if (!key) return [];

  const params = new URLSearchParams({
    q: query,
    count: String(Math.min(count, 20)),
    safesearch: "moderate",
  });

  try {
    const res = await fetch(`${BASE}?${params}`, {
      headers: {
        Accept: "application/json",
        "X-Subscription-Token": key,
      },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      console.error(`[canary] Brave search failed: ${res.status}`);
      return [];
    }
    const data = (await res.json()) as BraveResponse;
    const results = data.web?.results ?? [];
    return results
      .filter((r): r is { title: string; url: string; description?: string; extra_snippets?: string[] } =>
        Boolean(r.url && r.title),
      )
      .slice(0, count)
      .map((r) => ({
        title: r.title,
        url: r.url,
        snippet: r.description ?? r.extra_snippets?.[0] ?? "",
        source: safeHost(r.url),
      }));
  } catch (err) {
    console.error(`[canary] Brave search error: ${err instanceof Error ? err.message : "unknown"}`);
    return [];
  }
}

function safeHost(url: string): string {
  try {
    return new URL(url).host.replace(/^www\./, "");
  } catch {
    return url;
  }
}

/**
 * Build repo-aware search queries. We run a couple of targeted queries so the
 * model gets independent signals: one for safety/malware reputation, one for
 * known vulnerabilities. Results are merged and deduped by URL.
 */
export async function searchProjectReputation(
  fullName: string,
  signal: string,
): Promise<WebResult[]> {
  const queries = [
    `${fullName} open source safe malware security`,
    `${fullName} vulnerability CVE`,
  ];
  if (signal) queries.push(`${fullName} ${signal}`);

  const batches = await Promise.all(queries.map((q) => searchWeb(q, 4)));
  const seen = new Set<string>();
  const merged: WebResult[] = [];
  for (const batch of batches) {
    for (const r of batch) {
      if (seen.has(r.url)) continue;
      seen.add(r.url);
      merged.push(r);
    }
  }
  return merged.slice(0, 10);
}
