/**
 * Shared types for the safety-check investigation engine.
 *
 * The engine is split into three layers:
 *   1. Deterministic scanners  -> produce structured `Finding[]` evidence
 *   2. Grader                   -> turns findings + repo signals into a `Verdict`
 *   3. Synthesizer (LLM)        -> turns everything into a plain-English report
 *
 * Layer 3 degrades gracefully to a rules-only report when no LLM key is set,
 * so the app always returns something useful.
 */

export type Verdict = "safe" | "caution" | "risky" | "unknown";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Category =
  | "install-script"
  | "dependency"
  | "obfuscation"
  | "secret-endpoint"
  | "network"
  | "crypto"
  | "signal"
  | "readme"
  | "metadata";

/**
 * A single piece of evidence produced by a scanner.
 *
 * `detail` is written for a non-technical reader — explain *what it means*
 * and *why it matters*, not the raw rule that fired.
 */
export interface Finding {
  /** Stable rule id, e.g. "pkg.postinstall.network". */
  id: string;
  category: Category;
  severity: Severity;
  /** Short technical label, e.g. "Network call in install script". */
  title: string;
  /** Plain-English explanation aimed at a non-technical reader. */
  detail: string;
  /** File path the finding came from, when applicable. */
  file?: string;
  /** 1-based line number when known. */
  line?: number;
  /** The substring that triggered the rule. */
  evidence?: string;
  /** A short code excerpt for context. */
  snippet?: string;
  /** How many distinct locations this same rule fired in (after aggregation). */
  locations?: number;
}

/** Normalized repository metadata from the GitHub API. */
export interface RepoMeta {
  owner: string;
  name: string;
  fullName: string;
  url: string;
  defaultBranch: string;
  description: string | null;
  homepage: string | null;
  stars: number;
  forks: number;
  openIssues: number;
  watchers: number;
  license: string | null;
  primaryLanguage: string | null;
  languages: string[];
  topics: string[];
  createdAt: string;
  pushedAt: string;
  updatedAt: string;
  archived: boolean;
  disabled: boolean;
  isFork: boolean;
  sizeKb: number;
  ownerType: "User" | "Organization" | "Bot" | "Unknown";
  ownerCreatedAt: string | null;
}

/** A file we fetched for scanning. */
export interface RepoFile {
  path: string;
  content: string;
  sizeBytes: number;
  truncated: boolean;
}

/** A path we know exists but did not fetch (size/cap reasons). */
export interface SkippedFile {
  path: string;
  sizeBytes: number;
  reason: string;
}

/** What the engine collected before grading/synthesis. */
export type Ecosystem =
  | "npm"
  | "PyPI"
  | "crates.io"
  | "Go"
  | "RubyGems"
  | "Packagist"
  | "Maven"
  | "NuGet";

/** A package reference extracted from a manifest, used for vuln lookups. */
export interface PackageRef {
  name: string;
  ecosystem: Ecosystem;
  version: string;
}

/** A known vulnerability hit from OSV.dev. */
export interface VulnHit {
  id: string;
  package: string;
  ecosystem: Ecosystem;
  version: string;
  severity: Severity;
  /** CVSS-like or textual severity string from the source, if any. */
  rawSeverity?: string;
  summary?: string;
  url?: string;
  fixedIn?: string;
}

/** A web-search result (Brave Search API). Used to pull independent community /
 * advisory signals about a project that aren't in the repo itself. */
export interface WebResult {
  title: string;
  url: string;
  snippet: string;
  /** Source domain, e.g. "reddit.com" or "nvd.nist.gov". */
  source: string;
}

/** A GitHub issue relevant to safety/maintenance. */
export interface IssueRef {
  number: number;
  title: string;
  state: "open" | "closed";
  url: string;
  labels: string[];
  securityRelated: boolean;
}

/** Summary of a repo's issues. */
export interface RepoIssues {
  total: number;
  open: number;
  /** Issues mentioning security/vulns/malware/etc. */
  securityRelated: IssueRef[];
  /** A small recent sample for context. */
  recent: IssueRef[];
}

/** A GitHub Discussion (community Q&A, separate from Issues). */
export interface DiscussionRef {
  number: number;
  title: string;
  url: string;
  securityRelated: boolean;
}

/** Summary of a repo's discussions (GraphQL endpoint; null if disabled). */
export interface RepoDiscussions {
  total: number;
  /** Discussions mentioning security/vulns/malware/etc. */
  securityRelated: DiscussionRef[];
  recent: DiscussionRef[];
}

/** What the engine collected before synthesis. */
export interface ScanResult {
  meta: RepoMeta;
  files: RepoFile[];
  skipped: SkippedFile[];
  partialScan: boolean;
  totalFilesInRepo: number;
  findings: Finding[];
  readmeExcerpt: string | null;
  packages: PackageRef[];
  vulnerabilities: VulnHit[];
  issues: RepoIssues | null;
  discussions: RepoDiscussions | null;
  /** Independent web-search signals (Brave). Empty when search isn't configured. */
  webResults: WebResult[];
}


/** Integration guidance for AI tools, when the repo looks compatible. */
export interface IntegrationGuide {
  /** Detected kind of integration, or "general" when none detected. */
  kind:
    | "mcp-server"
    | "claude-skill"
    | "cli"
    | "library"
    | "vscode-extension"
    | "general";
  /** Markdown instructions a non-technical user can follow. */
  instructions: string;
}

/** The full report returned to the UI. */
export interface Report {
  repo: RepoMeta;
  generatedAt: string;
  /** True when an LLM was used for synthesis. */
  llmUsed: boolean;
  verdict: Verdict;
  /** 0-100 confidence-of-safety score (higher = safer). */
  score: number;
  /** One-line plain-English headline. */
  headline: string;
  /** A few sentences: what the project is. */
  summary: string;
  /** Positive signals (always severity "info"). */
  goodSignals: Finding[];
  /** Concerns, sorted most-severe first. */
  findings: Finding[];
  counts: Record<Severity, number>;
  /** Plain-English steps to install/use the project. */
  howToUse: string;
  /** Setup guidance for Claude / Claude Code / Codex / Cursor, when relevant. */
  integration: IntegrationGuide | null;
  /** Known vulnerabilities found in declared dependencies (OSV.dev). */
  vulnerabilities: VulnHit[];
  /** Issue-tracker signals. */
  issues: RepoIssues | null;
  /** Discussion-board signals. */
  discussions: RepoDiscussions | null;
  /** Independent web-search signals (Brave). Empty when search isn't configured. */
  webResults: WebResult[];
  scannedFiles: number;
  totalFilesInRepo: number;
  partialScan: boolean;
  /** LLM model info when an LLM was used. */
  model: { provider: string; model: string } | null;
  /** Honest disclaimer — heuristics, not a guarantee. */
  disclaimer: string;
}

/** Error shape returned by the API on failure. */
export interface ApiError {
  error: string;
  detail?: string;
}
