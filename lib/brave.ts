/**
 * Brave Search client.
 *
 * Docs: https://api-dashboard.search.brave.com/app/documentation/web-search/get-started
 * Endpoint: GET https://api.search.brave.com/res/v1/web/search
 * Auth: X-Subscription-Token header.
 *
 * Env: BRAVE_SEARCH_API_KEY (required for the web_search tool; without it,
 * searches return [] and the agent works with its other tools).
 */

import type { WebResult } from "./types";

const BASE = "https://api.search.brave.com/res/v1/web/search";

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

/** Run a web search and return normalized results. Returns [] when not
 * configured or on any failure (search never blocks an investigation). */
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
      headers: { Accept: "application/json", "X-Subscription-Token": key },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      console.error(`[canary] Brave search failed: ${res.status}`);
      return [];
    }
    const data = (await res.json()) as BraveResponse;
    const results = data.web?.results ?? [];
    return results
      .filter(
        (r): r is { title: string; url: string; description?: string; extra_snippets?: string[] } =>
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
