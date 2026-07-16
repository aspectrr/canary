/**
 * Tools the agent can call during its investigation loop.
 *
 * Three tools, deliberately minimal (per the design brief): the model drives
 * its own external research instead of receiving force-gathered data.
 *   - web_search : Brave Search (reputation, news, CVEs)
 *   - fetch_url  : pull readable text/markdown from any URL
 *   - github     : GitHub REST API, scoped to the repo under investigation
 *
 * Each execution records an EvidenceStep so the report can show what was
 * actually checked (honest, model-driven, not a static checklist).
 */

import { searchWeb } from "./brave";
import { fetchApiJson } from "./github";
import type { EvidenceStep } from "./types";

/** Cap tool output so one verbose result can't blow up the context window. */
const MAX_RESULT_CHARS = 6000;

export interface ToolCtx {
  owner: string;
  repo: string;
}

/** OpenAI-style tool definitions sent with each agent turn. */
export const AGENT_TOOLS = [
  {
    type: "function" as const,
    function: {
      name: "web_search",
      description:
        "Search the public web for information about this project or its dependencies: security reputation, known vulnerabilities (CVEs), malware reports, news, and community discussion. Returns titles, URLs, and snippets. Use fetch_url to read a promising result in full.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "The search query." },
        },
        required: ["query"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "fetch_url",
      description:
        "Fetch a web page and return its text. Use this to read advisories, security blog posts, package-registry pages, or documentation found via web_search. Also works for raw GitHub file URLs.",
      parameters: {
        type: "object",
        properties: {
          url: { type: "string", description: "The full https URL to fetch." },
        },
        required: ["url"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "github",
      description:
        "Query the GitHub REST API for THIS repository only. Read specific files, issues, pull requests, releases, commits, or contributors. Pass a path like /repos/{owner}/{repo}/issues?state=open or /repos/{owner}/{repo}/contents/src/index.js. Returns JSON.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "GitHub API path beginning with /repos/{owner}/{repo}/..." },
        },
        required: ["path"],
      },
    },
  },
];

function cap(s: string): string {
  return s.length > MAX_RESULT_CHARS ? `${s.slice(0, MAX_RESULT_CHARS)}\n…[truncated]` : s;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host.replace(/^www\./, "");
  } catch {
    return url.slice(0, 40);
  }
}

/** Fetch a URL and return readable text: raw for text/json, stripped for HTML. */
async function fetchAsText(url: string): Promise<string> {
  const res = await fetch(url, {
    headers: { "User-Agent": "canary-investigation-agent", Accept: "text/*,application/json,*/*" },
    signal: AbortSignal.timeout(12_000),
    redirect: "follow",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const ct = res.headers.get("content-type") ?? "";
  const raw = await res.text();
  if (ct.includes("json") || ct.includes("text/plain") || ct.includes("markdown")) {
    return raw;
  }
  if (ct.includes("html")) {
    return raw
      .replace(/<script[\s\S]*?<\/script>/gi, "")
      .replace(/<style[\s\S]*?<\/style>/gi, "")
      .replace(/<[^>]+>/g, " ")
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&#39;/g, "'")
      .replace(/&quot;/g, '"')
      .replace(/&nbsp;/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }
  return raw;
}

/** A short, human-readable label for a tool call, shown in the progress feed. */
export function toolCallLabel(name: string, args: Record<string, unknown>): string {
  switch (name) {
    case "web_search":
      return `Searching the web: "${String(args.query ?? "").slice(0, 60)}"`;
    case "fetch_url":
      return `Reading ${hostOf(String(args.url ?? ""))}`;
    case "github":
      return `GitHub: ${String(args.path ?? "").split("?")[0].replace(/^\/repos\/[^/]+\/[^/]+/, "")}`;
    default:
      return name;
  }
}

/**
 * Execute one tool call, record what it did, and return the string content to
 * feed back to the model. Never throws — errors become tool-result messages so
 * the model can recover and try a different approach.
 */
export async function executeTool(
  name: string,
  args: Record<string, unknown>,
  ctx: ToolCtx,
  evidence: EvidenceStep[],
): Promise<string> {
  try {
    switch (name) {
      case "web_search": {
        const query = String(args.query ?? "").slice(0, 200);
        const results = await searchWeb(query, 6);
        evidence.push({ action: "web_search", detail: query, summary: `${results.length} result${results.length === 1 ? "" : "s"}` });
        return cap(JSON.stringify(results));
      }
      case "fetch_url": {
        const url = String(args.url ?? "").slice(0, 500);
        if (!/^https?:\/\//i.test(url)) throw new Error("Only http(s) URLs are allowed.");
        const text = await fetchAsText(url);
        evidence.push({ action: "fetch_url", detail: hostOf(url), summary: `${Math.max(1, Math.round(text.length / 1024))} KB read` });
        return cap(text);
      }
      case "github": {
        const path = String(args.path ?? "").slice(0, 300);
        const json = await fetchApiJson(ctx.owner, ctx.repo, path);
        const brief =
          Array.isArray(json) ? `${json.length} item${json.length === 1 ? "" : "s"}` : "1 object";
        evidence.push({ action: "github", detail: path.split("?")[0].replace(/^\/repos\/[^/]+\/[^/]+/, "") || "/", summary: brief });
        return cap(JSON.stringify(json));
      }
      default:
        return `Unknown tool "${name}". Available: web_search, fetch_url, github.`;
    }
  } catch (err) {
    return `Tool "${name}" failed: ${err instanceof Error ? err.message : "unknown error"}. Try a different approach.`;
  }
}
