import type { ProgressFn } from "./progress";
import type { Grade } from "./grade";
import {
  activeModel,
  chatComplete,
  isConfigured,
  type AgentMessage,
} from "./openrouter";
import { AGENT_TOOLS, executeTool, toolCallLabel, type ToolCtx } from "./tools";
import { checklistForPrompt } from "./checklist";
import type {
  EvidenceStep,
  Finding,
  IntegrationGuide,
  RepoFile,
  RepoMeta,
  ScanResult,
  Severity,
  Verdict,
} from "./types";

/**
 * The model is the report author.
 *
 * All gathered intelligence is handed to it — repo metadata, README excerpt,
 * deterministic scanner findings (good signals + concerns), GitHub issues
 * signals, known dependency vulnerabilities (OSV.dev), the detected
 * integration kind, and an explicit cybersecurity checklist — and it returns a
 * structured JSON report. We validate, clamp, and safety-merge its output.
 *
 * Reliability: the call retries transient failures (rate limits, server
 * errors, stalls, network blips) and cascades to a fallback model if the
 * primary fails entirely. Only if everything fails do we surface an error to
 * the caller — we never silently fall back to a rules-only report.
 *
 * The deterministic verdict/score are always computed and passed in as a
 * strong prior; the model may adjust them when the issues/vulns/repo signals
 * justify it, but its score is clamped into the verdict's band so the two stay
 * consistent, and it can never drop a critical/high red flag.
 */

const VERDICT_BAND: Record<Verdict, [number, number]> = {
  risky: [0, 40],
  caution: [41, 74],
  safe: [75, 100],
  unknown: [0, 0],
};

/** Ordering used by the "no unjustified downgrade" guardrail. */
const VERDICT_RANK: Record<Verdict, number> = { safe: 0, caution: 1, risky: 2, unknown: 3 };

function hasHighOrCritical(concerns: Finding[]): boolean {
  return concerns.some((c) => c.severity === "high" || c.severity === "critical");
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const VERDICTS: Verdict[] = ["safe", "caution", "risky", "unknown"];

export interface Synthesis {
  verdict: Verdict;
  score: number;
  headline: string;
  summary: string;
  howToUse: string;
  integration: IntegrationGuide | null;
  goodSignals: Finding[];
  findings: Finding[];
  /** What the agent actually did during its investigation loop. */
  evidence: EvidenceStep[];
  llmUsed: boolean;
  model: { provider: string; model: string } | null;
}

// ---------------------------------------------------------------------------
// Deterministic integration detection (unchanged): reliable, model-independent.
// ---------------------------------------------------------------------------

export function detectIntegration(
  meta: RepoMeta,
  files: RepoFile[],
): IntegrationGuide["kind"] | null {
  const pkgFiles = files.filter((f) => f.path.split("/").pop() === "package.json");
  const parsePkg = (content: string): Record<string, unknown> | null => {
    try {
      return JSON.parse(content) as Record<string, unknown>;
    } catch {
      return null;
    }
  };
  const rootPkg = parsePkg(pkgFiles.find((f) => f.path === "package.json")?.content ?? "{}");
  const paths = new Set(files.map((f) => f.path.toLowerCase()));
  const haystack = `${meta.name} ${meta.description ?? ""} ${meta.topics.join(" ")}`.toLowerCase();

  const allDeps = new Set<string>();
  for (const f of pkgFiles) {
    const p = parsePkg(f.content);
    if (!p) continue;
    for (const section of ["dependencies", "devDependencies", "peerDependencies"]) {
      const deps = p[section];
      if (deps && typeof deps === "object") {
        for (const k of Object.keys(deps as Record<string, unknown>)) allDeps.add(k);
      }
    }
  }

  if (rootPkg && (rootPkg as { engines?: { vscode?: string } }).engines?.vscode) return "vscode-extension";
  if (allDeps.has("@modelcontextprotocol/sdk")) return "mcp-server";
  if (/\bmodel context protocol\b|\bmcp\b/.test(haystack)) return "mcp-server";
  if ([...paths].some((p) => p.endsWith("/mcp.json") || p === ".mcp.json")) return "mcp-server";
  if ([...paths].some((p) => p.split("/").pop() === "skill.md")) return "claude-skill";
  if ([...paths].some((p) => p.startsWith(".claude/"))) return "claude-skill";
  if (/claude.*(skill|agent|extension)/i.test(haystack)) return "claude-skill";
  if (rootPkg && (rootPkg as { bin?: unknown }).bin) return "cli";
  const pyproject = files.find((f) => f.path === "pyproject.toml");
  if (pyproject && /\[project\.scripts\]/i.test(pyproject.content)) return "cli";
  const setupPy = files.find((f) => f.path === "setup.py");
  if (setupPy && /console_scripts|entry_points/i.test(setupPy.content)) return "cli";
  if (rootPkg && ((rootPkg as { main?: unknown }).main || (rootPkg as { exports?: unknown }).exports || (rootPkg as { module?: unknown }).module)) return "library";
  if (pyproject || setupPy || files.some((f) => f.path.endsWith("Cargo.toml") || f.path.endsWith("go.mod"))) return "library";
  return null;
}

function integrationTemplate(kind: IntegrationGuide["kind"], meta: RepoMeta): string {
  const repo = meta.url;
  switch (kind) {
    case "mcp-server":
      return `This project is an **MCP server**, a tool that plugs into AI apps like Claude Desktop, Claude Code, Cursor, or Codex.

1. Install it as described in its README (often \`npx\` or \`node\`).
2. Add it to your AI app's MCP config.
   - **Claude Desktop / Claude Code:** edit \`~/Library/Application Support/Claude/claude_desktop_config.json\` (macOS) and add an entry under \`mcpServers\`, e.g. \`${meta.name}\` pointing at the start command from the README.
   - **Cursor / Codex:** add the same server via their MCP settings UI.
3. Restart the app. The server's tools will be available in chat.

Get the exact command from the repo: <${repo}>`;
    case "claude-skill":
      return `This project is a **Claude skill/agent**.

1. Follow the README's install instructions (often cloning into a skills directory).
2. In Claude Desktop or Claude Code, enable the skill per its README.
3. Restart and invoke it by name.

Repo: <${repo}>`;
    case "cli":
      return `This project is a **command-line tool**.

1. Install it exactly as the README shows (often \`npm install -g\`, \`pipx install\`, or \`cargo install\`).
2. Run it from a terminal using the command in the README.

If you're not comfortable with a terminal, ask someone to help. CLI tools run on your machine with your permissions.

Repo: <${repo}>`;
    case "vscode-extension":
      return `This project is a **VS Code extension**.

1. Download the \`.vsix\` build (or build it per the README).
2. In VS Code: View → Extensions → \`…\` menu → "Install from VSIX".
3. Reload the window.

Repo: <${repo}>`;
    case "library":
      return `This project is a **library/package** meant to be used inside other code.

1. Install it with the package manager it targets (the README will say which, e.g. \`npm install\`, \`pip install\`, \`cargo add\`).
2. Import or require it in your project as the README shows.

If you don't write code yourself, you'll want a developer to do this part.

Repo: <${repo}>`;
    default:
      return `Open the README for setup instructions tailored to this project: <${repo}>`;
  }
}

// ---------------------------------------------------------------------------
// Validation + coercion of the model's output.
// ---------------------------------------------------------------------------

function clampScoreForVerdict(score: number, verdict: Verdict): number {
  const [lo, hi] = VERDICT_BAND[verdict];
  return Math.max(lo, Math.min(hi, Math.round(score)));
}

function asString(v: unknown, max = 2000): string {
  return typeof v === "string" ? v.slice(0, max) : "";
}
function asVerdict(v: unknown, fallback: Verdict): Verdict {
  return typeof v === "string" && (VERDICTS as string[]).includes(v) ? (v as Verdict) : fallback;
}
function asSeverity(v: unknown, fallback: Severity): Severity {
  return typeof v === "string" && (SEVERITIES as string[]).includes(v) ? (v as Severity) : fallback;
}

function asFindingArray(v: unknown, fallbackSeverity: Severity): Finding[] {
  if (!Array.isArray(v)) return [];
  const out: Finding[] = [];
  for (const item of v) {
    if (!item || typeof item !== "object") continue;
    const title = asString((item as { title?: unknown }).title, 200);
    const detail = asString((item as { detail?: unknown }).detail, 800);
    if (!title) continue;
    const file = asString((item as { file?: unknown }).file, 300);
    out.push({
      id: `llm.${out.length}`,
      category: "metadata",
      severity: asSeverity((item as { severity?: unknown }).severity, fallbackSeverity),
      title,
      detail: detail || title,
      ...(file ? { file } : {}),
    });
  }
  return out;
}

/** Ensure any deterministic critical/high concern the model dropped is kept. */
function safetyMerge(modelFindings: Finding[], deterministic: Finding[]): Finding[] {
  const present = new Set(
    modelFindings.map((f) => f.title.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 40)),
  );
  const appended: Finding[] = [];
  for (const d of deterministic) {
    if (d.severity !== "critical" && d.severity !== "high") continue;
    const key = d.title.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 40);
    if (present.has(key)) continue;
    appended.push(d);
  }
  return [...modelFindings, ...appended];
}

interface ModelReport {
  verdict: Verdict;
  score: number;
  headline: string;
  summary: string;
  howToUse: string;
  integrationInstructions: string | null;
  goodSignals: Finding[];
  findings: Finding[];
}

function validateModelOutput(raw: unknown, grade: Grade): ModelReport | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;

  const verdictRaw = asVerdict(o.verdict, grade.verdict);
  // Guardrail: the model may only make the verdict MORE cautious than the
  // deterministic prior when there's genuine high/critical evidence. Stops a
  // mid-tier model from downgrading a clearly-safe popular project (e.g.
  // esbuild) to "caution" over medium-only noise. When we override, also use
  // the deterministic score so the number matches the enforced verdict.
  const override =
    grade.verdict !== "unknown" &&
    VERDICT_RANK[verdictRaw] > VERDICT_RANK[grade.verdict] &&
    !hasHighOrCritical(grade.concerns);
  const verdict = override ? grade.verdict : verdictRaw;
  const scoreRaw = override ? grade.score : typeof o.score === "number" ? o.score : grade.score;
  const score = clampScoreForVerdict(scoreRaw, verdict);
  const headline = asString(o.headline, 400).trim() || grade.headline;
  const summary = asString(o.summary, 2500).trim();
  const howToUse = asString(o.howToUse, 2500).trim();
  const integrationInstructions =
    typeof o.integrationInstructions === "string" && o.integrationInstructions.trim().length > 20
      ? o.integrationInstructions.trim()
      : null;

  const goodSignals = asFindingArray(o.goodSignals, "info");
  const findings = safetyMerge(asFindingArray(o.findings, "medium"), grade.concerns);

  if (!summary || !howToUse) return null;
  if (findings.length === 0 && goodSignals.length === 0 && verdict !== "safe" && grade.concerns.length > 0) {
    // Model produced nothing usable.
    return null;
  }

  return {
    verdict,
    score,
    headline,
    summary,
    howToUse,
    integrationInstructions,
    goodSignals,
    findings,
  };
}

function extractJsonObject(text: string): unknown | null {
  const trimmed = text.trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced ? fenced[1] : trimmed;
  const start = candidate.indexOf("{");
  const end = candidate.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    return JSON.parse(candidate.slice(start, end + 1));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Prompt building.
// ---------------------------------------------------------------------------

/** Derive a coarse "shape" of the project from fetched files, so the model
 * can tell a single app from a collection/monorepo and describe it honestly. */
function deriveProjectShape(files: RepoFile[]): {
  packageNames: string[];
  subDirs: string[];
} {
  const packageNames = new Set<string>();
  const subDirs = new Set<string>();
  const MONOREPO_ROOTS = new Set(["src", "packages", "apps", "servers", "cmd", "services"]);

  for (const f of files) {
    if (f.path.endsWith("package.json") && !f.path.includes("node_modules")) {
      try {
        const p = JSON.parse(f.content) as { name?: unknown };
        if (typeof p.name === "string" && p.name) packageNames.add(p.name);
      } catch {
        /* ignore */
      }
    }
    const parts = f.path.split("/");
    if (parts.length > 2 && MONOREPO_ROOTS.has(parts[0])) {
      subDirs.add(`${parts[0]}/${parts[1]}`);
    }
  }
  return {
    packageNames: [...packageNames].sort(),
    subDirs: [...subDirs].sort().slice(0, 40),
  };
}

function buildInitialMessages(
  scan: ScanResult,
  grade: Grade,
  kind: IntegrationGuide["kind"] | null,
): AgentMessage[] {
  const { meta } = scan;
  const shape = deriveProjectShape(scan.files);

  const system = `You are a careful, clear-eyed open-source safety investigator. A non-technical person is deciding whether to use the project you're investigating, and they're trusting your judgment. Imagine a knowledgeable friend who's good with computers, explaining things patiently and honestly.

You are given an AUTOMATED SCAN as a starting baseline: repository metadata, a README excerpt, the project's file structure, and findings from deterministic code scanners (install scripts, obfuscation, secrets/endpoints, dependency and reputation signals). That baseline is reliable but incomplete. Your job is to INVESTIGATE FURTHER using your tools, then write a plain-English safety report.

YOU HAVE THREE TOOLS. Use them as you see fit; you are not required to use all of them, and you decide when you have enough:
- web_search(query): check the project's public reputation, look for known vulnerabilities (CVEs), malware reports, supply-chain incidents, or community warnings.
- fetch_url(url): read a web page in full (an advisory, a blog post, a package-registry page, a raw file).
- github(path): read this repo's issues, pull requests, releases, commits, contributors, or specific files via the GitHub API.

Investigate with judgment, and ALWAYS verify independently — never rely on the baseline scan alone. At a minimum:
- Run at least one web_search to check the project's public reputation and any known vulnerabilities or supply-chain incidents.
- Use github to look at open issues (especially anything security-related) or pull a specific file the baseline flagged.
- Use fetch_url to read a promising search result in full when a snippet isn't enough.
A popular, well-known project may need only a couple of confirming checks. An unfamiliar one, or one with scanner red flags, deserves more. Don't pad the investigation with pointless calls, but don't skip real due diligence either. If you write the report without calling any tools, you have not done your job.

WHEN YOU'RE DONE investigating, write the final report as a single JSON object (no markdown fences, no prose around it). Use this schema:
{
  "verdict": "safe" | "caution" | "risky" | "unknown",
  "score": integer 0-100 (higher = safer),
  "headline": one warm, specific sentence,
  "summary": 2-4 plain sentences: what the project IS and DOES (describe it as a whole; if it's a collection/monorepo, name the parts),
  "howToUse": concrete install/use steps from the README (never invent commands or package names),
  "integrationInstructions": setup steps for Claude/Claude Code/Codex/Cursor when relevant, else null,
  "goodSignals": [{"title":..., "detail":...}],
  "findings": [{"severity":"critical|high|medium|low|info", "title":..., "detail":..., "file": optional}]
}

TONE & VOICE:
- Warm and honest. Reassuring when the project is solid; clear and specific when there's real risk.
- Sound like a real person, not a press release. Short, plain sentences. Mix in the occasional fragment.
- NEVER use em dashes. Use commas, periods, or parentheses.
- No filler: "leverage," "robust," "seamless," "comprehensive," "delve," "holistic." State facts plainly.

VERDICT CALIBRATION:
- You may adjust the automated baseline verdict when your investigation justifies it.
- Never downplay a critical or high red flag. Never call third-party code perfectly safe.

When you're ready, respond with ONLY the JSON object and no tool calls.`;

  const user = JSON.stringify({
    repository: {
      name: meta.fullName,
      description: meta.description,
      url: meta.url,
      stars: meta.stars,
      forks: meta.forks,
      license: meta.license,
      primaryLanguage: meta.primaryLanguage,
      createdAt: meta.createdAt,
      lastPush: meta.pushedAt,
      archived: meta.archived,
      isFork: meta.isFork,
      ownerType: meta.ownerType,
      ownerAgeDays: meta.ownerCreatedAt
        ? Math.max(0, Math.round((Date.now() - new Date(meta.ownerCreatedAt).getTime()) / 86_400_000))
        : null,
    },
    readmeExcerpt: scan.readmeExcerpt,
    projectStructure: {
      publishedPackages: shape.packageNames,
      componentDirs: shape.subDirs,
      note:
        shape.subDirs.length > 1 || shape.packageNames.length > 1
          ? "Collection/monorepo with multiple parts. Describe the whole, then the parts."
          : null,
    },
    detectedIntegrationKind: kind,
    automatedScan: {
      verdict: grade.verdict,
      score: grade.score,
      filesScanned: scan.files.length,
      totalFilesInRepo: scan.totalFilesInRepo,
      partialScan: scan.partialScan,
    },
    goodSignals: grade.goodSignals.map((g) => ({ title: g.title, detail: g.detail })),
    concerns: grade.concerns.map((c) => ({
      severity: c.severity,
      title: c.title,
      detail: c.detail,
      file: c.file ?? null,
    })),
    packages: scan.packages.map((p) => ({ name: p.name, ecosystem: p.ecosystem, version: p.version })),
    cybersecurityChecklist: checklistForPrompt(),
  });

  return [
    { role: "system", content: system },
    { role: "user", content: user },
  ];
}

// ---------------------------------------------------------------------------
// Agent loop.
// ---------------------------------------------------------------------------

/** Backup model tried if the primary model fails. Fast and tool-capable. */
const FALLBACK_MODEL = process.env.OPENROUTER_FALLBACK_MODEL ?? "google/gemini-2.5-flash";

/** Hard cap on tool-call rounds, so a looping model can't run forever. */
const MAX_TOOL_ROUNDS = 12;

interface LoopResult {
  report: ModelReport;
  evidence: EvidenceStep[];
}

/** Parse the JSON-string arguments a model sends with a tool call. */
function parseToolArgs(raw: string): Record<string, unknown> {
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** Run one full agent investigation with a single model. Throws on failure. */
async function runAgentLoop(
  scan: ScanResult,
  grade: Grade,
  kind: IntegrationGuide["kind"] | null,
  model: string,
  ctx: ToolCtx,
  onProgress?: ProgressFn,
): Promise<LoopResult> {
  const messages = buildInitialMessages(scan, grade, kind);
  const evidence: EvidenceStep[] = [];
  let toolCallIndex = 0;
  let lastContent: string | null = null;

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    const reply = await chatComplete(messages, { tools: AGENT_TOOLS, model, maxTokens: 1800, temperature: 0.3 });
    messages.push(reply);

    // No tool calls => the model is handing back its final answer.
    if (!reply.tool_calls || reply.tool_calls.length === 0) {
      // Guardrail: if it tried to finish before investigating at all, push it
      // back to do real research first. (A model that answers from the
      // baseline alone has not verified anything independently.)
      if (toolCallIndex === 0) {
        messages.push({
          role: "user",
          content:
            "You haven't investigated yet. Use your tools to verify this project independently before writing the report. Start with a web search for its reputation and any known vulnerabilities, and check its open issues via the github tool. Only write the report once you've gathered real evidence.",
        });
        continue;
      }
      lastContent = reply.content;
      break;
    }

    // Execute each tool call and feed results back.
    for (const tc of reply.tool_calls) {
      toolCallIndex += 1;
      const args = parseToolArgs(tc.function.arguments);
      const label = toolCallLabel(tc.function.name, args);
      const pct = Math.min(90, 62 + toolCallIndex * 3);
      onProgress?.(pct, `agent-${toolCallIndex}`, label);
      const result = await executeTool(tc.function.name, args, ctx, evidence);
      messages.push({ role: "tool", tool_call_id: tc.id, content: result });
    }
  }

  // If the model burned through every round still calling tools, force a finish.
  if (lastContent === null) {
    messages.push({
      role: "user",
      content:
        "You've gathered enough. Stop calling tools and write the final report now as a single JSON object, nothing else.",
    });
    const reply = await chatComplete(messages, { model, maxTokens: 3000, temperature: 0.2 });
    lastContent = reply.content;
  }

  const raw = lastContent ? extractJsonObject(lastContent) : null;
  const report = validateModelOutput(raw, grade);
  if (!report) {
    throw new Error("The model finished its investigation but didn't return a valid report.");
  }
  return { report, evidence };
}

export async function synthesize(
  scan: ScanResult,
  grade: Grade,
  onProgress?: ProgressFn,
): Promise<Synthesis> {
  const kind = detectIntegration(scan.meta, scan.files);
  const ctx: ToolCtx = { owner: scan.meta.owner, repo: scan.meta.name };

  if (!isConfigured()) {
    throw new Error("No AI key is configured. Set OPENROUTER_API_KEY to run an investigation.");
  }

  onProgress?.(60, "report", "The investigator is thinking and gathering evidence…");

  let usedModel = activeModel();
  let result: LoopResult;
  try {
    result = await runAgentLoop(scan, grade, kind, usedModel, ctx, onProgress);
  } catch (err) {
    console.warn(`[canary] primary model failed (${err instanceof Error ? err.message : "unknown"}); cascading to ${FALLBACK_MODEL}`);
    onProgress?.(62, "report", "The first model hit trouble. Retrying with a backup…");
    usedModel = FALLBACK_MODEL;
    result = await runAgentLoop(scan, grade, kind, usedModel, ctx, onProgress);
  }

  const { report, evidence } = result;
  return {
    verdict: report.verdict,
    score: report.score,
    headline: report.headline,
    summary: report.summary,
    howToUse: report.howToUse,
    integration:
      kind && report.integrationInstructions
        ? { kind, instructions: report.integrationInstructions }
        : kind
          ? { kind, instructions: integrationTemplate(kind, scan.meta) }
          : null,
    goodSignals: report.goodSignals,
    findings: report.findings,
    evidence,
    llmUsed: true,
    model: { provider: "OpenRouter", model: usedModel },
  };
}
