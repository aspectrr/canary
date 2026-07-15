import type { ProgressFn } from "./progress";
import type { Grade } from "./grade";
import { activeModel, completeJson, isConfigured, type ChatMessage } from "./openrouter";
import { checklistForPrompt } from "./checklist";
import type {
  Finding,
  IntegrationGuide,
  RepoFile,
  RepoMeta,
  ScanResult,
  Severity,
  Verdict,
  VulnHit,
} from "./types";

/**
 * The model is the report author.
 *
 * All gathered intelligence is handed to it — repo metadata, README excerpt,
 * deterministic scanner findings (good signals + concerns), GitHub issues
 * signals, known dependency vulnerabilities (OSV.dev), the detected
 * integration kind, and an explicit cybersecurity checklist — and it returns a
 * structured JSON report. We validate, clamp, and safety-merge its output, and
 * degrade to a deterministic report when no key is set or the model fails.
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
      return `This project is an **MCP server** — a tool that plugs into AI apps like Claude Desktop, Claude Code, Cursor, or Codex.

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

If you're not comfortable with a terminal, ask someone to help — CLI tools run on your machine with your permissions.

Repo: <${repo}>`;
    case "vscode-extension":
      return `This project is a **VS Code extension**.

1. Download the \`.vsix\` build (or build it per the README).
2. In VS Code: View → Extensions → \`…\` menu → "Install from VSIX".
3. Reload the window.

Repo: <${repo}>`;
    case "library":
      return `This project is a **library/package** meant to be used inside other code.

1. Install it with the package manager it targets (the README will say — e.g. \`npm install\`, \`pip install\`, \`cargo add\`).
2. Import or require it in your project as the README shows.

If you don't write code yourself, you'll want a developer to do this part.

Repo: <${repo}>`;
    default:
      return `Open the README for setup instructions tailored to this project: <${repo}>`;
  }
}

// ---------------------------------------------------------------------------
// Deterministic fallbacks (used when no key, or when the model fails).
// ---------------------------------------------------------------------------

function fallbackSummary(meta: RepoMeta, readme: string | null): string {
  const parts: string[] = [];
  const what = meta.description?.trim();
  parts.push(
    what
      ? `**${meta.fullName}** is described as: ${what}.`
      : `**${meta.fullName}** is a${meta.primaryLanguage ? ` ${meta.primaryLanguage}` : ""} project on GitHub.`,
  );
  if (readme) {
    const firstLines = readme.slice(0, 400).replace(/[#>*`]/g, "").trim();
    if (firstLines) parts.push(firstLines);
  }
  parts.push(
    `It has ${meta.stars.toLocaleString()} star${meta.stars === 1 ? "" : "s"} and is written primarily in ${meta.primaryLanguage ?? "a mix of languages"}.`,
  );
  return parts.join("\n\n");
}

function fallbackHowToUse(readme: string | null): string {
  if (!readme) {
    return "The repository has no README, so there are no setup steps to show. Open the repo on GitHub to look for install instructions in other files.";
  }
  return "See the **Installation** or **Getting Started** section of the project's README for setup steps. (A human-readable version of those steps appears here when an AI model is connected.)";
}

function deterministic(scan: ScanResult, grade: Grade, kind: IntegrationGuide["kind"] | null): Synthesis {
  return {
    verdict: grade.verdict,
    score: grade.score,
    headline: grade.headline,
    summary: fallbackSummary(scan.meta, scan.readmeExcerpt),
    howToUse: fallbackHowToUse(scan.readmeExcerpt),
    integration: kind ? { kind, instructions: integrationTemplate(kind, scan.meta) } : null,
    goodSignals: grade.goodSignals,
    findings: grade.concerns,
    llmUsed: false,
    model: null,
  };
}

// ---------------------------------------------------------------------------
// JSON schema the model is asked to follow (strict:false — we validate anyway).
// ---------------------------------------------------------------------------

const OUTPUT_SCHEMA = {
  name: "safety_report",
  schema: {
    type: "object",
    properties: {
      verdict: { type: "string", enum: VERDICTS, description: "safe | caution | risky | unknown" },
      score: { type: "integer", minimum: 0, maximum: 100, description: "Confidence-of-safety: higher = safer." },
      headline: { type: "string", description: "One plain-English sentence summarizing the verdict." },
      summary: { type: "string", description: "2-4 sentences: what this project is and does, for a non-technical reader." },
      howToUse: { type: "string", description: "Plain-English install/use steps from the README." },
      integrationInstructions: { type: ["string", "null"], description: "Setup steps for Claude/Claude Code/Codex/Cursor, or null." },
      goodSignals: {
        type: "array",
        items: {
          type: "object",
          properties: {
            title: { type: "string" },
            detail: { type: "string" },
          },
          required: ["title", "detail"],
        },
      },
      findings: {
        type: "array",
        items: {
          type: "object",
          properties: {
            severity: { type: "string", enum: SEVERITIES },
            title: { type: "string" },
            detail: { type: "string" },
            file: { type: ["string", "null"] },
          },
          required: ["severity", "title", "detail"],
        },
      },
    },
    required: ["verdict", "score", "headline", "summary", "howToUse", "goodSignals", "findings"],
  },
};

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
// Vuln -> Finding helpers (so known vulns always appear as concerns).
// ---------------------------------------------------------------------------

export function vulnsAsFindings(vulns: VulnHit[]): Finding[] {
  return vulns.map((v) => ({
    id: `vuln.${v.id}.${v.package}`,
    category: "secret-endpoint",
    severity: v.severity,
    title: `Known vulnerability in \`${v.package}\`: ${v.id}`,
    detail: `The dependency \`${v.package}\` (version ${v.version}) has a known security issue (${v.id})${
      v.summary ? `: ${v.summary}` : ""
    }.${v.fixedIn ? ` Fix available in version ${v.fixedIn}.` : " No fixed version was listed."} Known dependency vulnerabilities like this are the most concrete, verifiable risk in a project.`,
    evidence: v.id,
    ...(v.url ? { snippet: v.url } : {}),
  }));
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

function buildMessages(scan: ScanResult, grade: Grade, kind: IntegrationGuide["kind"] | null): ChatMessage[] {
  const { meta } = scan;

  const system = `You are Aspectrr, a friendly, clear-eyed security guide. You write a plain-English safety report for a NON-TECHNICAL person deciding whether to use an open-source project. Imagine a knowledgeable friend who's good with computers, explaining things patiently and honestly.

You receive structured intelligence gathered automatically: repository metadata, a README excerpt, the project's structure, the detected integration type, an automated scanner's verdict/score plus its findings (good signals and concerns), recent GitHub issues (with security-related ones flagged), known vulnerabilities in the project's dependencies, and a cybersecurity checklist.

Synthesize ALL of it into ONE report as JSON.

DESCRIBING THE PROJECT (most important):
- Describe the project AS A WHOLE. Anchor on the repo description and the README, not on a single file or component.
- If the project bundles several apps, servers, packages, or modules (a collection or monorepo), SAY SO: name the overall project, then list its main parts. Never describe the whole project as if it were just one of its components. The "projectStructure" field tells you what parts exist — use it.
- Two or three plain sentences: what it is, what it's for, and who uses it. No jargon.

TONE:
- Warm and honest. Reassuring when the project is solid; clear and specific when there's real risk.
- No fearmongering, no hype, no marketing fluff. No code in the summary.
- Speak to a beginner, but don't be vague.

VERDICT & SCORE:
- You may adjust the automated verdict/score when the issues, vulnerabilities, or repo signals clearly justify it. Stay calibrated.
- Never downplay a critical/high red flag or a known critical/high vulnerability. Never call third-party code perfectly safe.

FIELDS:
- headline: one warm, specific sentence capturing the verdict.
- summary: what the project IS and DOES (see DESCRIBING THE PROJECT above).
- howToUse: concrete install/use steps from the README. If the project has multiple parts, give the general setup pattern and point readers to the README for the specifics of each part. Never invent commands or package names that aren't in the README or projectStructure.
- findings: everything worth checking — scanner concerns, known vulns, issue-tracker warnings. Each gets a plain-English title and an explanation of why it matters and what (if anything) to do. Keep severe items; trim trivial duplicates.
- goodSignals: positive signs (popularity, maintenance, license, tests, CI, docs, etc.).
- Use the cybersecurity checklist as your lens for what to look for.

Output ONLY a single JSON object. No prose, no markdown fences.`;

  const vulns = scan.vulnerabilities.map((v) => ({
    id: v.id,
    package: v.package,
    version: v.version,
    severity: v.severity,
    summary: v.summary,
    fixedIn: v.fixedIn ?? null,
    url: v.url ?? null,
  }));

  const issues = scan.issues
    ? {
        totalSeen: scan.issues.total,
        openApprox: scan.issues.open,
        securityRelated: scan.issues.securityRelated.map((i) => ({
          number: i.number,
          title: i.title,
          state: i.state,
          url: i.url,
        })),
        recentSample: scan.issues.recent.slice(0, 4).map((i) => ({ title: i.title, state: i.state })),
      }
    : null;

  const shape = deriveProjectShape(scan.files);

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
      note: shape.subDirs.length > 1 || shape.packageNames.length > 1
        ? "This looks like a collection/monorepo with multiple parts — describe the whole, then the parts."
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
    concerns: grade.concerns.map((c) => ({ severity: c.severity, title: c.title, detail: c.detail, file: c.file ?? null })),
    knownVulnerabilities: vulns,
    issues,
    cybersecurityChecklist: checklistForPrompt(),
  });

  return [
    { role: "system", content: system },
    { role: "user", content: user },
  ];
}

// ---------------------------------------------------------------------------
// Public entrypoint.
// ---------------------------------------------------------------------------

export async function synthesize(
  scan: ScanResult,
  grade: Grade,
  onProgress?: ProgressFn,
): Promise<Synthesis> {
  const kind = detectIntegration(scan.meta, scan.files);

  if (!isConfigured()) {
    return deterministic(scan, grade, kind);
  }

  const messages = buildMessages(scan, grade, kind);
  onProgress?.(80, "report", "Asking the AI to write your report…", activeModel());
  let lastReportPct = 80;
  const text = await completeJson(messages, OUTPUT_SCHEMA, 3000, (chars) => {
    // Inch the bar from 82% to 95% as tokens stream in (~3000 char report).
    // Only emit when the rounded percentage changes to avoid flooding the stream.
    const pct = Math.min(95, 82 + Math.round(chars / 200));
    if (pct !== lastReportPct) {
      lastReportPct = pct;
      onProgress?.(pct, "report", "AI is writing your report…", undefined);
    }
  });
  const raw = text ? extractJsonObject(text) : null;
  const model = validateModelOutput(raw, grade);

  if (!model) {
    return deterministic(scan, grade, kind);
  }

  return {
    verdict: model.verdict,
    score: model.score,
    headline: model.headline,
    summary: model.summary,
    howToUse: model.howToUse,
    integration:
      kind && model.integrationInstructions
        ? { kind, instructions: model.integrationInstructions }
        : kind
          ? { kind, instructions: integrationTemplate(kind, scan.meta) }
          : null,
    goodSignals: model.goodSignals,
    findings: model.findings,
    llmUsed: true,
    model: { provider: "OpenRouter", model: activeModel() },
  };
}
