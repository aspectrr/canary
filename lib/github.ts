import type { RepoMeta } from "./types";

/**
 * Minimal GitHub client.
 *
 * Uses the REST API for metadata + the recursive git tree (2 authenticated
 * requests), then fetches individual file bodies from raw.githubusercontent.com
 * (a CDN, not rate-limited like the API) so we can scan many files cheaply.
 *
 * Pass `GITHUB_TOKEN` to lift the API limit from 60 → 5000 req/hour per IP.
 */

const API = "https://api.github.com";
const RAW = "https://raw.githubusercontent.com";

export class GitHubError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly kind: "not-found" | "rate-limit" | "network" | "unknown",
  ) {
    super(message);
    this.name = "GitHubError";
  }
}

function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "aspectrr-investigation-agent",
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function ghFetch<T>(path: string): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API}${path}`, { headers: authHeaders() });
  } catch (err) {
    throw new GitHubError(
      `Network error contacting GitHub: ${(err as Error).message}`,
      0,
      "network",
    );
  }

  if (res.status === 404) {
    throw new GitHubError(
      "Repository not found. Check that the URL is correct and the repo is public.",
      404,
      "not-found",
    );
  }
  if (res.status === 403) {
    const remaining = res.headers.get("x-ratelimit-remaining");
    if (remaining === "0") {
      throw new GitHubError(
        "GitHub API rate limit reached (60/hour without a token). Set GITHUB_TOKEN to raise it to 5000/hour, then try again in a bit.",
        403,
        "rate-limit",
      );
    }
    throw new GitHubError(
      "GitHub returned 403 Forbidden. The repo may require authentication or the rate limit was hit.",
      403,
      "rate-limit",
    );
  }
  if (!res.ok) {
    throw new GitHubError(
      `GitHub API error (${res.status}) for ${path}`,
      res.status,
      "unknown",
    );
  }
  return (await res.json()) as T;
}

/** Parse many GitHub URL shapes into {owner, repo, branch?}. */
export function parseRepoUrl(input: string): {
  owner: string;
  repo: string;
  branch?: string;
} | null {
  const raw = input.trim();
  if (!raw) return null;

  // owner/repo shorthand (no slashes allowed in owner, repo has no slash)
  if (/^[\w.-]+\/[\w.-]+$/.test(raw)) {
    return { owner: raw.split("/")[0], repo: raw.split("/")[1] };
  }

  let url = raw;
  try {
    // Allow inputs without a protocol.
    url = /^https?:\/\//.test(raw) ? raw : `https://${raw}`;
    const u = new URL(url);

    // SSH form: git@github.com:owner/repo(.git)
    if (raw.startsWith("git@")) {
      const m = raw.match(/git@github\.com:([^/]+)\/([^/]+?)(?:\.git)?(?:\/.*)?$/);
      if (m) return { owner: m[1], repo: m[2] };
    }

    const host = u.hostname.toLowerCase();
    if (!["github.com", "www.github.com"].includes(host)) return null;

    const parts = u.pathname.replace(/^\/|\/$/g, "").split("/");
    if (parts.length < 2) return null;
    const owner = parts[0];
    let repo = parts[1];
    if (repo.endsWith(".git")) repo = repo.slice(0, -4);

    let branch: string | undefined;
    // /owner/repo/tree/branch[/sub/path]
    if (parts[2] === "tree" && parts[3]) branch = decodeURIComponent(parts[3]);
    // /owner/repo/blob/branch/...  (user pasted a file link — use its branch)
    if (parts[2] === "blob" && parts[3]) branch = decodeURIComponent(parts[3]);

    return { owner, repo, branch };
  } catch {
    return null;
  }
}

interface RawRepo {
  name: string;
  full_name: string;
  html_url: string;
  default_branch: string;
  description: string | null;
  homepage: string | null;
  stargazers_count: number;
  forks_count: number;
  open_issues_count: number;
  subscribers_count: number;
  license: { spdx_id: string } | null;
  language: string | null;
  topics: string[];
  created_at: string;
  pushed_at: string;
  updated_at: string;
  archived: boolean;
  disabled: boolean;
  fork: boolean;
  size: number;
  owner: { login: string; type: string; created_at: string };
}

export async function getMeta(owner: string, repo: string): Promise<RepoMeta> {
  const r = await ghFetch<RawRepo>(`/repos/${owner}/${repo}`);
  return {
    owner,
    name: r.name,
    fullName: r.full_name,
    url: r.html_url,
    defaultBranch: r.default_branch,
    description: r.description,
    homepage: r.homepage,
    stars: r.stargazers_count,
    forks: r.forks_count,
    openIssues: r.open_issues_count,
    watchers: r.subscribers_count,
    license: r.license?.spdx_id ?? null,
    primaryLanguage: r.language,
    languages: [],
    topics: r.topics ?? [],
    createdAt: r.created_at,
    pushedAt: r.pushed_at,
    updatedAt: r.updated_at,
    archived: r.archived,
    disabled: r.disabled,
    isFork: r.fork,
    sizeKb: r.size,
    ownerType: (["User", "Organization", "Bot"].includes(r.owner.type)
      ? r.owner.type
      : "Unknown") as RepoMeta["ownerType"],
    ownerCreatedAt: r.owner.created_at ?? null,
  };
}

export interface IssueRaw {
  number: number;
  title: string;
  state: "open" | "closed";
  html_url: string;
  pull_request?: unknown;
  labels: { name: string }[];
}

/** Recent issues (and only issues — PRs are filtered out). */
export async function getRecentIssues(
  owner: string,
  repo: string,
  perPage = 60,
): Promise<IssueRaw[]> {
  try {
    const data = await ghFetch<IssueRaw[]>(
      `/repos/${owner}/${repo}/issues?state=all&sort=updated&direction=desc&per_page=${perPage}`,
    );
    return (data ?? []).filter((i) => !i.pull_request);
  } catch {
    return [];
  }
}

export interface TreeEntry {
  path: string;
  type: "blob" | "tree" | "commit";
  size?: number;
  sha?: string;
}

export async function getTree(
  owner: string,
  repo: string,
  branch: string,
): Promise<{ entries: TreeEntry[]; truncated: boolean }> {
  const data = await ghFetch<{
    tree: TreeEntry[];
    truncated: boolean;
  }>(`/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
  return { entries: data.tree ?? [], truncated: data.truncated ?? false };
}

export async function getLanguages(
  owner: string,
  repo: string,
): Promise<string[]> {
  try {
    const data = await ghFetch<Record<string, number>>(
      `/repos/${owner}/${repo}/languages`,
    );
    return Object.entries(data)
      .sort((a, b) => b[1] - a[1])
      .map(([lang]) => lang);
  } catch {
    return [];
  }
}

/** Fetch a single file's text from the raw CDN. Returns null on failure. */
export async function getRawFile(
  owner: string,
  repo: string,
  branch: string,
  path: string,
): Promise<string | null> {
  const url = `${RAW}/${owner}/${repo}/${encodeURIComponent(branch)}/${path
    .split("/")
    .map(encodeURIComponent)
    .join("/")}`;
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "aspectrr-investigation-agent" },
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

/**
 * Proxy a GitHub REST API path for the agent's `github` tool. Restricted to
 * the repo being investigated (path must reference owner/repo) so the model
 * can't wander into other accounts. Returns parsed JSON, or throws on failure.
 */
export async function fetchApiJson(
  owner: string,
  repo: string,
  path: string,
): Promise<unknown> {
  const clean = path.startsWith("/") ? path : `/${path}`;
  const prefix = `/repos/${owner}/${repo}`.toLowerCase();
  if (!clean.toLowerCase().startsWith(prefix)) {
    throw new Error(
      `Refused: the github tool can only query ${owner}/${repo}. Use a path like /repos/${owner}/${repo}/issues.`,
    );
  }
  return ghFetch<unknown>(clean);
}
