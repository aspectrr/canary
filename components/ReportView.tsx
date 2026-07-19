import type { Finding, Report, Severity, Verdict } from "@/lib/types";
import { Markdown } from "./markdown";

/**
 * Monochrome verdict treatment. Risky inverts to a solid ink block, which in
 * editorial terms reads louder than any color would.
 */
const VERDICT_META: Record<Verdict, { word: string; inverted: boolean }> = {
  safe: { word: "Safe to use", inverted: false },
  caution: { word: "Use caution", inverted: false },
  risky: { word: "High risk", inverted: true },
  unknown: { word: "Can't tell", inverted: false },
};

/** Severity expressed through ink density, not hue. */
const SEVERITY_META: Record<Severity, { marker: string; label: string }> = {
  critical: { marker: "bg-ink", label: "Critical" },
  high: { marker: "bg-ink", label: "High" },
  medium: { marker: "bg-ink/45", label: "Medium" },
  low: { marker: "bg-ink/25", label: "Low" },
  info: { marker: "bg-ink/15", label: "Note" },
};

function relativeDays(iso: string): string {
  const days = Math.round((Date.now() - new Date(iso).getTime()) / 86_400_000);
  if (days < 1) return "today";
  if (days < 30) return `${days}d ago`;
  if (days < 365) return `${Math.round(days / 30)}mo ago`;
  return `${Math.round(days / 365)}y ago`;
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="mb-4 border-t border-ink pt-4 text-xs font-semibold uppercase tracking-[0.18em] text-ink/55">
      {children}
    </h2>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const sev = SEVERITY_META[finding.severity];
  return (
    <li className="border-t border-ink/15 py-4 first:border-t-0 first:pt-0">
      <div className="flex items-start gap-3">
        <span className={`mt-1.5 h-2 w-2 flex-shrink-0 ${sev.marker}`} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-ink/45">
              {sev.label}
            </span>
            {finding.file && (
              <code className="truncate bg-stone px-1.5 py-0.5 font-mono text-[11px] text-ink/60">
                {finding.file}
              </code>
            )}
            {finding.locations && finding.locations > 1 ? (
              <span className="bg-stone px-1.5 py-0.5 text-[11px] text-ink/55">
                in {finding.locations} places
              </span>
            ) : null}
          </div>
          <p className="mt-1 font-medium">{finding.title}</p>
          <p className="mt-1 text-sm leading-relaxed text-ink/65">{finding.detail}</p>
          {(finding.snippet || finding.evidence) && (
            <details className="mt-2 group">
              <summary className="cursor-pointer border-b border-ink/40 pb-0.5 text-xs font-medium text-ink hover:border-ink">
                Show technical detail
              </summary>
              <pre className="mt-2 overflow-x-auto bg-ink p-3 font-mono text-[11px] leading-relaxed text-bone">
                {finding.snippet ?? finding.evidence}
              </pre>
            </details>
          )}
        </div>
      </div>
    </li>
  );
}

export function ReportView({ report }: { report: Report }) {
  const meta = VERDICT_META[report.verdict];
  const r = report.repo;
  const inverted = meta.inverted;

  return (
    <div className="space-y-10">
      {/* Header: repo identity */}
      <div className="flex flex-col gap-2">
        <a
          href={r.url}
          target="_blank"
          rel="noopener noreferrer"
          className="w-fit border-b border-ink/40 pb-0.5 font-mono text-sm font-medium text-ink hover:border-ink"
        >
          {r.fullName}
        </a>
        <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs text-ink/55">
          <span>★ {r.stars.toLocaleString()}</span>
          {r.license && <span>{r.license}</span>}
          {r.primaryLanguage && <span>{r.primaryLanguage}</span>}
          <span>Updated {relativeDays(r.pushedAt)}</span>
          {r.archived && <span>Archived</span>}
        </div>
      </div>

      {/* Verdict */}
      <section
        className={
          inverted
            ? "border-t-2 border-ink bg-ink px-6 py-7 text-bone"
            : "border-t-2 border-ink px-1 py-7"
        }
      >
        <div className="flex items-end justify-between gap-4">
          <div>
            <p
              className={`text-xs font-semibold uppercase tracking-[0.18em] ${
                inverted ? "text-bone/55" : "text-ink/45"
              }`}
            >
              Verdict
            </p>
            <p className="mt-1.5 text-3xl font-semibold tracking-tight sm:text-4xl">{meta.word}</p>
          </div>
          <div className="text-right">
            <p className="font-mono text-5xl font-semibold leading-none tabular-nums">
              {report.score}
            </p>
            <p
              className={`mt-1.5 font-mono text-xs uppercase tracking-wide ${
                inverted ? "text-bone/45" : "text-ink/40"
              }`}
            >
              / 100
            </p>
          </div>
        </div>
        <div className={`mt-5 h-1.5 w-full ${inverted ? "bg-bone/20" : "bg-stone"}`}>
          <div
            className={`h-full ${inverted ? "bg-bone" : "bg-ink"}`}
            style={{ width: `${report.score}%` }}
          />
        </div>
        <p className={`mt-5 text-[15px] leading-relaxed ${inverted ? "text-bone/85" : "text-ink/80"}`}>
          {report.headline}
        </p>
      </section>

      {/* What it is */}
      <section>
        <SectionLabel>What this project is</SectionLabel>
        <div className="text-[15px] leading-relaxed text-ink/80">
          <Markdown source={report.summary} />
        </div>
      </section>

      {/* Concerns */}
      {report.findings.length > 0 && (
        <section>
          <SectionLabel>Worth checking ({report.findings.length})</SectionLabel>
          <ul>
            {report.findings.map((f, i) => (
              <FindingRow key={`${f.id}-${i}`} finding={f} />
            ))}
          </ul>
        </section>
      )}

      {/* Good signs */}
      {report.goodSignals.length > 0 && (
        <section>
          <SectionLabel>Good signs</SectionLabel>
          <ul className="grid gap-x-6 gap-y-2.5 sm:grid-cols-2">
            {report.goodSignals.map((g, i) => (
              <li key={`${g.id}-${i}`} className="flex items-start gap-2.5 text-sm text-ink/80">
                <svg
                  className="mt-0.5 h-3.5 w-3.5 flex-shrink-0"
                  viewBox="0 0 20 20"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2.5}
                  aria-hidden
                >
                  <path d="M4 10.5l4 4 8-9" strokeLinecap="square" strokeLinejoin="miter" />
                </svg>
                <span>{g.title}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* How to use */}
      <section>
        <SectionLabel>How to use it</SectionLabel>
        <div className="text-[15px] leading-relaxed text-ink/80">
          <Markdown source={report.howToUse} />
        </div>
      </section>

      {/* Integration */}
      {report.integration && (
        <section>
          <SectionLabel>Set it up in your AI app</SectionLabel>
          <p className="mb-4 text-sm text-ink/55">Detected as: {labelForKind(report.integration.kind)}</p>
          <div className="text-[15px] leading-relaxed text-ink/80">
            <Markdown source={report.integration.instructions} />
          </div>
        </section>
      )}

      {/* How the investigator checked — real tool calls from the agent loop */}
      {report.evidence.length > 0 && (
        <section>
          <SectionLabel>How the investigator checked ({report.evidence.length})</SectionLabel>
          <ul className="space-y-2.5">
            {report.evidence.map((step, i) => (
              <li key={i} className="flex items-start gap-3 text-sm">
                <span
                  className="mt-0.5 flex-shrink-0 border border-ink/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.1em] text-ink/55"
                  title={step.action}
                >
                  {EVIDENCE_LABEL[step.action] ?? step.action}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="text-ink/80">{step.detail}</span>
                  {step.summary && (
                    <span className="ml-2 text-ink/40">{step.summary}</span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Footer */}
      <footer className="space-y-1.5 border-t border-ink/15 pt-4 font-mono text-[11px] leading-relaxed text-ink/40">
        <p>{report.disclaimer}</p>
        <p>
          Investigated {report.scannedFiles.toLocaleString()} of{" "}
          {report.totalFilesInRepo.toLocaleString()} files
          {report.partialScan ? " (partial scan)" : ""}
          {" · "}
          {report.llmUsed ? "report written by an LLM" : "no AI model connected"}
          {" · "}generated {new Date(report.generatedAt).toLocaleString()}
        </p>
      </footer>
    </div>
  );
}

function labelForKind(kind: string): string {
  switch (kind) {
    case "mcp-server":
      return "MCP server";
    case "claude-skill":
      return "Claude skill or agent";
    case "cli":
      return "command-line tool";
    case "library":
      return "library or package";
    case "vscode-extension":
      return "VS Code extension";
    default:
      return "general project";
  }
}

const EVIDENCE_LABEL: Record<string, string> = {
  web_search: "SEARCH",
  fetch_url: "READ",
  github: "GITHUB",
};
