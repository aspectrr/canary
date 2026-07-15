import {
  getLanguages,
  getMeta,
  getRawFile,
  getRecentIssues,
  getTree,
  parseRepoUrl,
} from "./github";
import { grade } from "./grade";
import { synthesize, vulnsAsFindings } from "./llm";
import { summarizeIssues } from "./issues";
import { queryVulnerabilities } from "./osv";
import {
  DOC_FILES,
  IGNORE_FILE_RE,
  MANIFEST_FILES,
  NON_SHIPPING_DIRS,
  SKIP_DIRS,
} from "./scan/patterns";
import { runScans, type RepoFlags } from "./scan";
import { collectPackages } from "./scan/dependencies";
import { basename, isLikelyTestFile, isSourceFile } from "./scan/util";
import type {
  Finding,
  Report,
  RepoFile,
  RepoMeta,
  ScanResult,
  Severity,
  SkippedFile,
} from "./types";

/** A user-correctable problem (bad URL, empty repo). Maps to HTTP 400. */
export class UserInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UserInputError";
  }
}

const DISCLAIMER =
  "This report is produced by automated heuristics. It can flag suspicious patterns and common malware indicators, but it cannot guarantee a project is safe — and a clever attacker can evade it. Treat the verdict as a starting point, not a guarantee. When in doubt, ask someone technical to review the code, or run it in a sandbox.";

const MAX_SOURCE_FILES = 120;
const MAX_MANIFEST_FILES = 30;
const MAX_FILE_BYTES = 150_000;
const FETCH_CONCURRENCY = 12;

function inSkippedDir(path: string): boolean {
  const parts = path.split("/");
  return parts.some((p) => SKIP_DIRS.includes(p));
}

/** Test/fixture/example/docs paths produce false positives — skip deep scans. */
function inNonShippingDir(path: string): boolean {
  const parts = path.split("/");
  return parts.some((p) => NON_SHIPPING_DIRS.includes(p));
}

function computeFlags(paths: string[]): RepoFlags {
  const set = new Set(paths.map((p) => p.toLowerCase()));
  const has = (pred: (p: string) => boolean) => paths.some((p) => pred(p.toLowerCase()));

  return {
    hasReadme: has((p) => basename(p).startsWith("readme")),
    hasSecurityMd: set.has("security.md") || set.has("security"),
    hasContributing: set.has("contributing.md") || set.has("contributing"),
    hasLicenseFile: has((p) => ["license", "license.md", "license.txt", "copying"].includes(basename(p))),
    hasCI:
      has((p) => p.startsWith(".github/workflows/") && /\.(ya?ml)$/.test(p)) ||
      set.has(".gitlab-ci.yml") ||
      has((p) => p.startsWith(".circleci/")) ||
      set.has("azure-pipelines.yml"),
    hasTests:
      has((p) => /(^|\/)(test|tests|spec|specs|__tests__)(\/|$)/.test(p)) ||
      has((p) => /\.(test|spec)\.(js|mjs|cjs|ts|tsx|jsx|py|go|rs|rb)$/.test(p)),
    hasLockfile: has((p) =>
      [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lockb",
        "cargo.lock",
        "go.sum",
        "poetry.lock",
        "gemfile.lock",
        "composer.lock",
        "uv.lock",
      ].includes(basename(p)),
    ),
  };
}

function selectFiles(entries: { path: string; type?: string; size?: number }[]): {
  mustFetch: Set<string>;
} {
  const manifestPaths: { path: string; depth: number }[] = [];
  const sourceCandidates: { path: string; size: number; depth: number }[] = [];

  for (const entry of entries) {
    if (entry.type !== "blob" && entry.type !== undefined) continue;
    const { path, size } = entry;
    if (inSkippedDir(path) || inNonShippingDir(path) || isLikelyTestFile(path)) continue;
    if (IGNORE_FILE_RE.test(path)) continue;

    const base = basename(path).toLowerCase();
    const depth = path.split("/").length;

    if (MANIFEST_FILES.has(base) || DOC_FILES.has(base) || /^readme(\.|$)/i.test(base)) {
      manifestPaths.push({ path, depth });
      continue;
    }
    if (isSourceFile(path) && (size ?? 0) <= MAX_FILE_BYTES) {
      sourceCandidates.push({ path, size: size ?? 0, depth });
    }
  }

  // Root/shallow manifests first; cap so huge monorepos don't explode.
  manifestPaths.sort((a, b) => a.depth - b.depth);
  const mustFetch = new Set<string>(
    manifestPaths.slice(0, MAX_MANIFEST_FILES).map((m) => m.path),
  );

  // Fill remaining budget with shallow + smaller source files.
  const remaining = Math.max(0, MAX_SOURCE_FILES - mustFetch.size);
  sourceCandidates.sort((a, b) =>
    a.depth !== b.depth ? a.depth - b.depth : a.size - b.size,
  );
  for (const c of sourceCandidates.slice(0, remaining)) mustFetch.add(c.path);

  return { mustFetch };
}

async function fetchMany(
  owner: string,
  repo: string,
  branch: string,
  paths: string[],
): Promise<{ files: RepoFile[]; skipped: SkippedFile[] }> {
  const files: RepoFile[] = [];
  const skipped: SkippedFile[] = [];
  const queue = [...paths];

  async function worker(): Promise<void> {
    while (queue.length) {
      const path = queue.shift()!;
      const content = await getRawFile(owner, repo, branch, path);
      if (content === null) {
        skipped.push({ path, sizeBytes: 0, reason: "fetch failed" });
        continue;
      }
      const truncated = content.length > MAX_FILE_BYTES;
      files.push({
        path,
        content: truncated ? content.slice(0, MAX_FILE_BYTES) : content,
        sizeBytes: content.length,
        truncated,
      });
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(FETCH_CONCURRENCY, paths.length) }, () => worker()),
  );
  return { files, skipped };
}

function findReadme(files: RepoFile[]): RepoFile | null {
  return (
    files.find((f) => /^readme(\.|$)/i.test(basename(f.path))) ??
    files.find((f) => basename(f.path).toLowerCase().startsWith("readme")) ??
    null
  );
}

export async function investigate(input: string): Promise<Report> {
  const parsed = parseRepoUrl(input);
  if (!parsed) {
    throw new UserInputError(
      "That doesn't look like a GitHub repository URL. Try something like https://github.com/owner/repo",
    );
  }

  const { owner, repo } = parsed;

  // 1. Metadata + language breakdown.
  const baseMeta = await getMeta(owner, repo);
  const languages = await getLanguages(owner, repo);
  const meta: RepoMeta = { ...baseMeta, languages };

  // 2. Resolve branch — prefer URL hint, fall back to default.
  let branch = parsed.branch ?? meta.defaultBranch;
  let tree = await safeTree(owner, repo, branch);
  if (!tree) {
    branch = meta.defaultBranch;
    tree = await safeTree(owner, repo, branch);
  }
  if (!tree) {
    throw new Error("Couldn't read the repository's file list. It may be empty or restricted.");
  }

  const allPaths = tree.entries
    .filter((e) => e.type === "blob")
    .map((e) => ({ path: e.path, size: e.size }));
  const totalFilesInRepo = allPaths.length;

  // 3. Flags + file selection.
  const flags = computeFlags(tree.entries.map((e) => e.path));
  const { mustFetch } = selectFiles(tree.entries);

  // 4. Fetch selected files.
  const { files } = await fetchMany(owner, repo, branch, [...mustFetch]);
  const partialScan = tree.truncated || files.length < totalFilesInRepo;

  // 5. README excerpt.
  const readme = findReadme(files);
  const readmeExcerpt = readme
    ? readme.content.slice(0, 4000).replace(/\r/g, "")
    : null;

  // 6. Scanners + vulnerability (OSV) + issue (GitHub) intake, in parallel.
  const packages = collectPackages(files);
  const [scanFindings, vulnerabilities, issueSummary] = await Promise.all([
    Promise.resolve(runScans(meta, files, flags, totalFilesInRepo)),
    queryVulnerabilities(packages),
    getRecentIssues(owner, repo).then(summarizeIssues),
  ]);
  // Fold known dependency vulns into the evidence so they influence the grade.
  const vulnFindings = vulnsAsFindings(vulnerabilities);
  const findings: Finding[] = [...scanFindings, ...vulnFindings];
  const gradeResult = grade(findings, meta, totalFilesInRepo);

  const scanResult: ScanResult = {
    meta,
    files,
    skipped: [],
    partialScan,
    totalFilesInRepo,
    findings,
    readmeExcerpt,
    packages: collectPackages(files),
    vulnerabilities,
    issues: issueSummary,
  };

  // 7. Synthesize (model-authored report, with deterministic fallback).
  const synth = await synthesize(scanResult, gradeResult);

  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of synth.findings) counts[f.severity]++;

  return {
    repo: meta,
    generatedAt: new Date().toISOString(),
    llmUsed: synth.llmUsed,
    verdict: synth.verdict,
    score: synth.score,
    headline: synth.headline,
    summary: synth.summary,
    goodSignals: synth.goodSignals,
    findings: synth.findings,
    counts,
    howToUse: synth.howToUse,
    integration: synth.integration,
    vulnerabilities,
    issues: scanResult.issues,
    scannedFiles: files.length,
    totalFilesInRepo,
    partialScan,
    model: synth.model,
    disclaimer: DISCLAIMER,
  };
}

async function safeTree(owner: string, repo: string, branch: string) {
  try {
    return await getTree(owner, repo, branch);
  } catch {
    return null;
  }
}
