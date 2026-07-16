# Canary

**Is this open-source project safe to use?**

This is a web app for non-technical people. Paste a GitHub repository URL
and it reads the code, checks for malware red flags, and explains in plain
English whether you can trust it, what it does, and how to use it (including
how to wire it into Claude Desktop, Claude Code, Codex, or Cursor when
relevant).

It's an automated first pass, not a guarantee. It catches the common patterns
malicious packages use; a sophisticated attacker can still evade it. When in
doubt, ask someone technical to review the code or run it in a sandbox.

---

## Quick start

Requires Node.js 20.9+ and [Bun](https://bun.sh) (the project uses Bun, but
npm/pnpm/yarn work too).

```bash
bun install
bun run dev
# open http://localhost:3000
```

That's it for a fully working, **rules-only** experience. To get AI-written
summaries and tailored setup steps, add an API key (see [Configuration](#configuration)).

### Verify it works

```bash
bun run typecheck   # TypeScript
bun run build       # production build
bun run selftest    # confirms the malware detectors fire on synthetic inputs
```

## Configuration

The app needs an OpenRouter key to run (without it, investigations error rather
than silently falling back to a shallow rules-only report). Web search and a
GitHub token are optional enrichments.

Create a `.env.local` file (gitignored) in the project root:

| Variable                     | Required | What it does                                                          |
| ---------------------------- | -------- | --------------------------------------------------------------------- |
| `OPENROUTER_API_KEY`         | **yes**  | Key for the AI model that writes the report. Get one at <https://openrouter.ai/keys>. |
| `OPENROUTER_MODEL`           | no       | Primary model. Default `anthropic/claude-sonnet-4.5`.                 |
| `OPENROUTER_FALLBACK_MODEL`  | no       | Backup model if the primary fails after retries. Default `google/gemini-2.5-flash`. |
| `OPENROUTER_TIMEOUT_MS`      | no       | Stall-detection window (default `120000` = 2 min). Not a hard cap.    |
| `BRAVE_SEARCH_API_KEY`       | no       | Brave Search key for web-reputation signals. Without it, search is skipped. |
| `GITHUB_TOKEN`               | no       | Raises GitHub API limit from 60 to 5000 req/hour.                     |

Example:

```bash
# .env.local
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_MODEL=anthropic/claude-sonnet-4.5
BRAVE_SEARCH_API_KEY=BSA...
GITHUB_TOKEN=github_pat_...
```

A fine-grained GitHub token with public read-only access is enough. Get a
Brave Search key at <https://api.search.brave.com/> (free tier: 2,000
queries/month).

> **Reliability.** The model call retries transient failures (rate limits,
> server errors, stalls, network blips) up to 3 times, then cascades to a
> backup model. Only if everything fails does the user see an error — Canary
> never silently drops to a rules-only report.

> **Model speed matters.** The report is generated via streaming, but total
> time depends on the model. Claude Sonnet, GPT-4o-mini, and Mistral finish in
> 5–15s. Large reasoning/MoE models like Kimi k2.5 can take 60–120s. The
> streaming timeout is a *stall detector* (abort only if no tokens arrive for
> `OPENROUTER_TIMEOUT_MS`), so even slow models won't be cut off mid-generation.

## How it works

This is a Next.js 16 app (App Router). Everything happens server-side.

```
GitHub URL
   │
   ▼
1. GitHub API ── repo metadata + recursive file tree + recent issues
2. Select files ── manifests, README, and a capped sample of source
                   (test/fixture/example/doc paths are excluded to avoid noise)
3. Intake ────── five parallel evidence streams:
   • Scanners     ── deterministic rules → findings (install hooks, obfuscation,
                     secrets/endpoints, dependency sources, repo signals…)
   • OSV.dev      ── known CVEs/advisories for RUNTIME dependencies (batch query)
   • Issues       ── recent issues, with security-related ones flagged
   • Discussions  ── recent GitHub Discussions (GraphQL), security-related flagged
   • Web search   ── Brave Search for independent reputation signals
4. Grader ────── findings (incl. known vulns) → verdict + score as a prior
5. Synthesizer ─ all of the above + a cybersecurity checklist → the AI model
                   (via OpenRouter) writes the FULL structured report as JSON.
                   Output is validated, score-clamped to the verdict band, and
                   safety-merged so no critical/high red flag is ever dropped.
                   Retries transient failures, cascades to a backup model, and
                   surfaces an error if everything fails (never a silent
                   rules-only fallback). Integration kind (MCP server, CLI,
                   library…) is detected and setup steps generated for
                   Claude / Claude Code / Codex / Cursor.
```

The model is the report author; the deterministic layer is the evidence floor
and the guardrail. The model can adjust the verdict when the issues, vulns, or
repo signals justify it, but it can never invent safety or drop a serious flag.

### Design choices worth knowing

- **Deterministic evidence, model-authored report.** The scanners, OSV.dev,
  issue/discussion intake, and web search gather ground truth; the
  verdict/score are computed as a strong prior; the model then writes the full
  structured JSON report from all of it. The model's output is validated, its
  score is clamped into the verdict's band, and any critical/high red flag it
  drops is re-added.
- **Reading vs. exfiltrating.** Reading all of `process.env` or touching
  credential files is *medium* (suspicious but not definitive — some tools do
  it legitimately). Sending data to a Discord/Telegram webhook or a raw IP is
  *high*. Real infostealers do both, so they still aggregate to "risky."
- **Runtime-only vulnerability lookups.** OSV.dev is queried only for a
  project's *runtime* dependencies (npm `dependencies`/`optionalDependencies`,
  not `devDependencies`; cargo `dependencies`, not `dev-dependencies`), and
  manifests inside test/fixture/demo harness dirs (`require/`, `compat/`, …)
  are ignored. Dev-only and comparison-fixture deps aren't what end users
  install, so flagging them would mislead. What's left are the real CVEs.
- **Verified vulnerabilities, not guesses.** OSV hits are concrete published
  advisories with fixed versions where available — surfaced in their own
  "Known vulnerabilities" section.
- **No per-dependency typo-squat guessing.** Without registry download-count
  data it's too noisy; the *repository-name* typo-squat check stays (a no-name
  repo mimicking a popular package is the dangerous case).
- **Capped scans.** Large repos get a bounded sample (shallow + smaller source
  files, plus all root manifests). The report notes when a scan was partial.

## Project layout

```
app/
  page.tsx                  landing page (hero + input form)
  api/investigate/route.ts  POST → returns a Report
components/
  InvestigatorForm.tsx      client form, loading state, error handling
  ReportView.tsx            verdict, findings, good signs, next steps
  markdown.tsx              tiny dependency-free Markdown renderer
lib/
  types.ts                  shared types (Finding, Report, Verdict, VulnHit…)
  github.ts                 GitHub API + raw-CDN client (meta, tree, issues, files)
  osv.ts                    OSV.dev vulnerability lookup (batch query + details)
  issues.ts                 GitHub issues → security-related summary
  checklist.ts              the "cybersecurity no-nos" framework fed to the model
  openrouter.ts             fetch-based OpenRouter client (json_schema → json_object)
  investigate.ts            top-level orchestration
  grade.ts                  findings → verdict + score (prior for the model)
  llm.ts                    synthesis: model-authored JSON report + validation + fallback
  scan/
    patterns.ts             rule data (manifests, suspicious hosts/TLDs…)
    util.ts                 Levenshtein, entropy, helpers
    signals.ts              repo metadata → good/bad signals
    install-scripts.ts      lifecycle/install hooks
    dependencies.ts         manifest parsing, dep sources, runtime packages for OSV
    obfuscation.ts          eval/vm/blobs/dynamic-imports
    secrets-endpoints.ts    hosts/IPs/webhooks/secrets/wallets
    index.ts                run + aggregate all scanners
scripts/
  selftest.ts               synthetic checks that detectors fire correctly
```

## API

`POST /api/investigate`

```jsonc
// request
{ "url": "https://github.com/owner/repo" }

// response (200) — a Report object: verdict, score, headline, summary,
// goodSignals[], findings[], howToUse, integration, disclaimer, …
```

Errors: `400` (bad URL), `404` (repo not found), `429` (GitHub rate limit),
`500` (unexpected). All error bodies are `{ "error": "…", "detail"?: "…" }`.

## Deployment

Any Node host works (Vercel, Railway, Fly, a VPS). The investigation can take
10–20s on large repos, so pick a plan with a generous request timeout (the
route sets `maxDuration = 60`). Set the same env vars on your host.

```bash
bun run build
bun run start    # or: next start
```

## Limitations & honest expectations

- It analyzes **public GitHub repositories only**.
- It reads source statically — it does **not** execute the code, so anything
  that only misbehaves at runtime (e.g. a payload fetched at run time from a
  rotating domain) can be missed.
- Heuristics produce **false positives and false negatives**. Use the verdict
  as a starting point, not a verdict of record.
- The "safe" rating is relative to what the scanners can see, not a guarantee.

## License

MIT
