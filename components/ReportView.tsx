import type { Finding, Report, Severity, Verdict } from "@/lib/types";
import { Markdown } from "./markdown";

const VERDICT_META: Record<
  Verdict,
  { label: string; ring: string; badge: string; bar: string; text: string; icon: "check" | "warn" | "alert" | "unknown" }
> = {
  safe: {
    label: "Looks safe to use",
    ring: "ring-emerald-200 dark:ring-emerald-900/50",
    badge: "bg-emerald-50 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200",
    bar: "bg-emerald-500",
    text: "text-emerald-600 dark:text-emerald-400",
    icon: "check",
  },
  caution: {
    label: "Use with caution",
    ring: "ring-amber-200 dark:ring-amber-900/50",
    badge: "bg-amber-50 text-amber-800 dark:bg-amber-950 dark:text-amber-200",
    bar: "bg-amber-500",
    text: "text-amber-600 dark:text-amber-400",
    icon: "warn",
  },
  risky: {
    label: "High risk",
    ring: "ring-rose-200 dark:ring-rose-900/50",
    badge: "bg-rose-50 text-rose-800 dark:bg-rose-950 dark:text-rose-200",
    bar: "bg-rose-500",
    text: "text-rose-600 dark:text-rose-400",
    icon: "alert",
  },
  unknown: {
    label: "Can't tell",
    ring: "ring-zinc-200 dark:ring-zinc-700",
    badge: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
    bar: "bg-zinc-400",
    text: "text-zinc-500 dark:text-zinc-400",
    icon: "unknown",
  },
};

const SEVERITY_META: Record<Severity, { dot: string; label: string }> = {
  critical: { dot: "bg-rose-600", label: "Critical" },
  high: { dot: "bg-orange-500", label: "High" },
  medium: { dot: "bg-amber-500", label: "Medium" },
  low: { dot: "bg-sky-500", label: "Low" },
  info: { dot: "bg-zinc-400", label: "Note" },
};

function Icon({ name }: { name: "check" | "warn" | "alert" | "unknown" }) {
  const common = "h-5 w-5";
  if (name === "check")
    return (
      <svg className={common} viewBox="0 0 20 20" fill="currentColor" aria-hidden>
        <path
          fillRule="evenodd"
          d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.7-9.3a1 1 0 00-1.4-1.4L9 10.6 7.7 9.3a1 1 0 00-1.4 1.4l2 2a1 1 0 001.4 0l4-4z"
          clipRule="evenodd"
        />
      </svg>
    );
  if (name === "alert")
    return (
      <svg className={common} viewBox="0 0 20 20" fill="currentColor" aria-hidden>
        <path
          fillRule="evenodd"
          d="M8.3 2.7a2 2 0 013.4 0l6.1 10.5A2 2 0 0116.1 16H3.9a2 2 0 01-1.7-2.8L8.3 2.7zM10 7a1 1 0 011 1v3a1 1 0 11-2 0V8a1 1 0 011-1zm0 7.2a1.1 1.1 0 100-2.2 1.1 1.1 0 000 2.2z"
          clipRule="evenodd"
        />
      </svg>
    );
  if (name === "warn")
    return (
      <svg className={common} viewBox="0 0 20 20" fill="currentColor" aria-hidden>
        <path
          fillRule="evenodd"
          d="M10 18a8 8 0 100-16 8 8 0 000 16zM9 9a1 1 0 112 0v4a1 1 0 11-2 0V9zm1 7a1.1 1.1 0 100-2.2A1.1 1.1 0 0010 16z"
          clipRule="evenodd"
        />
      </svg>
    );
  return (
    <svg className={common} viewBox="0 0 20 20" fill="currentColor" aria-hidden>
      <path
        fillRule="evenodd"
        d="M10 18a8 8 0 100-16 8 8 0 000 16zM9 9a1 1 0 011-1h.01a1 1 0 010 2H10a1 1 0 01-1-1zm1 4.5a1 1 0 112 0 1 1 0 01-2 0z"
        clipRule="evenodd"
      />
    </svg>
  );
}

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-zinc-100 px-2.5 py-1 text-xs font-medium text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
      {children}
    </span>
  );
}

function relativeDays(iso: string): string {
  const days = Math.round((Date.now() - new Date(iso).getTime()) / 86_400_000);
  if (days < 1) return "today";
  if (days < 30) return `${days}d ago`;
  if (days < 365) return `${Math.round(days / 30)}mo ago`;
  return `${Math.round(days / 365)}y ago`;
}

function ScoreGauge({ score, verdict }: { score: number; verdict: Verdict }) {
  const meta = VERDICT_META[verdict];
  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative h-20 w-20">
        <svg viewBox="0 0 36 36" className="h-20 w-20 -rotate-90">
          <circle cx="18" cy="18" r="15.5" fill="none" className="stroke-zinc-200 dark:stroke-zinc-700" strokeWidth="3.5" />
          <circle
            cx="18"
            cy="18"
            r="15.5"
            fill="none"
            strokeWidth="3.5"
            strokeLinecap="round"
            className={meta.text}
            stroke="currentColor"
            strokeDasharray={`${(score / 100) * 97.4} 97.4`}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center text-xl font-semibold tabular-nums">
          {score}
        </div>
      </div>
      <span className="mt-1 text-[11px] uppercase tracking-wide text-zinc-400">safety</span>
    </div>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const sev = SEVERITY_META[finding.severity];
  return (
    <li className="rounded-xl border border-zinc-200 p-3.5 dark:border-zinc-800">
      <div className="flex items-start gap-2.5">
        <span className={`mt-1.5 h-2 w-2 flex-shrink-0 rounded-full ${sev.dot}`} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-wide text-zinc-400">
              {sev.label}
            </span>
            {finding.file && (
              <code className="truncate rounded bg-zinc-100 px-1.5 py-0.5 font-mono text-[11px] text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400">
                {finding.file}
              </code>
            )}
            {finding.locations && finding.locations > 1 ? (
              <span className="rounded bg-zinc-100 px-1.5 py-0.5 text-[11px] text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400">
                in {finding.locations} places
              </span>
            ) : null}
          </div>
          <p className="mt-0.5 font-medium text-zinc-900 dark:text-zinc-100">{finding.title}</p>
          <p className="mt-1 text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">{finding.detail}</p>
          {(finding.snippet || finding.evidence) && (
            <details className="mt-2 group">
              <summary className="cursor-pointer text-xs font-medium text-sky-700 hover:text-sky-800 dark:text-sky-400">
                Show technical detail
              </summary>
              <pre className="mt-1.5 overflow-x-auto rounded-md bg-zinc-50 p-2 font-mono text-[11px] text-zinc-600 dark:bg-zinc-900 dark:text-zinc-400">
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

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        <a
          href={r.url}
          target="_blank"
          rel="noopener noreferrer"
          className="font-mono text-sm font-medium text-sky-700 hover:underline dark:text-sky-400"
        >
          {r.fullName}
        </a>
        <div className="flex flex-wrap gap-1.5">
          <Chip>★ {r.stars.toLocaleString()}</Chip>
          {r.license && <Chip>{r.license}</Chip>}
          {r.primaryLanguage && <Chip>{r.primaryLanguage}</Chip>}
          <Chip>Updated {relativeDays(r.pushedAt)}</Chip>
          {r.archived && <Chip>Archived</Chip>}
        </div>
      </div>

      {/* Verdict */}
      <section className={`rounded-2xl bg-white p-5 ring-1 ${meta.ring} dark:bg-zinc-900`}>
        <div className="flex items-start gap-4">
          <ScoreGauge score={report.score} verdict={report.verdict} />
          <div className="min-w-0 flex-1">
            <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ${meta.badge}`}>
              <Icon name={meta.icon} />
              {meta.label}
            </span>
            <p className="mt-2 text-[15px] leading-relaxed text-zinc-800 dark:text-zinc-200">
              {report.headline}
            </p>
          </div>
        </div>
      </section>

      {/* What it is */}
      <section className="rounded-2xl border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-zinc-900">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-zinc-500">
          What this project is
        </h2>
        <div className="text-[15px] leading-relaxed text-zinc-700 dark:text-zinc-300">
          <Markdown source={report.summary} />
        </div>
      </section>

      {/* Concerns */}
      {report.findings.length > 0 && (
        <section className="rounded-2xl border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-zinc-900">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-500">
            Things worth checking ({report.findings.length})
          </h2>
          <ul className="space-y-2.5">
            {report.findings.map((f, i) => (
              <FindingRow key={`${f.id}-${i}`} finding={f} />
            ))}
          </ul>
        </section>
      )}

      {/* Known vulnerabilities (OSV.dev) */}
      {report.vulnerabilities.length > 0 && (
        <section className="rounded-2xl border border-rose-200 bg-rose-50/40 p-5 dark:border-rose-900/50 dark:bg-rose-950/20">
          <h2 className="mb-1 text-sm font-semibold uppercase tracking-wide text-rose-700 dark:text-rose-400">
            Known vulnerabilities in dependencies ({report.vulnerabilities.length})
          </h2>
          <p className="mb-3 text-xs text-rose-700/70 dark:text-rose-400/70">
            Verified against the OSV.dev vulnerability database — these are real, published issues, not guesses.
          </p>
          <ul className="space-y-2.5">
            {report.vulnerabilities.slice(0, 12).map((v) => {
              const sev = SEVERITY_META[v.severity];
              return (
                <li key={`${v.id}-${v.package}`} className="flex items-start gap-2.5 rounded-xl border border-rose-200/70 p-3 dark:border-rose-900/40">
                  <span className={`mt-1.5 h-2 w-2 flex-shrink-0 rounded-full ${sev.dot}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-zinc-800 dark:text-zinc-200">{v.id}</span>
                      <span className="text-[10px] font-semibold uppercase tracking-wide text-zinc-400">{sev.label}</span>
                      {v.fixedIn && <span className="rounded bg-emerald-100 px-1.5 py-0.5 text-[11px] text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300">fix in {v.fixedIn}</span>}
                    </div>
                    <p className="mt-0.5 text-sm text-zinc-700 dark:text-zinc-300">
                      In <code className="rounded bg-zinc-100 px-1 py-0.5 font-mono text-[11px] dark:bg-zinc-800">{v.package}@{v.version}</code>
                      {v.ecosystem !== "npm" && <span className="text-zinc-400"> ({v.ecosystem})</span>}
                    </p>
                    {v.summary && <p className="mt-1 text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">{v.summary}</p>}
                    {v.url && (
                      <a href={v.url} target="_blank" rel="noopener noreferrer" className="mt-1 inline-block text-xs font-medium text-sky-700 hover:underline dark:text-sky-400">
                        Advisory details ↗
                      </a>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {/* Good signs */}
      {report.goodSignals.length > 0 && (
        <section className="rounded-2xl border border-emerald-200 bg-emerald-50/40 p-5 dark:border-emerald-900/50 dark:bg-emerald-950/20">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-emerald-700 dark:text-emerald-400">
            Good signs
          </h2>
          <ul className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
            {report.goodSignals.map((g, i) => (
              <li key={`${g.id}-${i}`} className="flex items-start gap-2 text-sm text-zinc-700 dark:text-zinc-300">
                <svg className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-600 dark:text-emerald-400" viewBox="0 0 20 20" fill="currentColor" aria-hidden>
                  <path fillRule="evenodd" d="M16.7 5.3a1 1 0 010 1.4l-7.5 7.5a1 1 0 01-1.4 0L3.3 9.7a1 1 0 011.4-1.4l3.5 3.5 6.8-6.8a1 1 0 011.7 0z" clipRule="evenodd" />
                </svg>
                <span>{g.title}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Issues & maintenance signals */}
      {report.issues && report.issues.securityRelated.length > 0 && (
        <section className="rounded-2xl border border-amber-200 bg-amber-50/30 p-5 dark:border-amber-900/50 dark:bg-amber-950/10">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-amber-700 dark:text-amber-400">
            Security-related issues in the tracker
          </h2>
          <ul className="space-y-1.5">
            {report.issues.securityRelated.map((i) => (
              <li key={i.number} className="flex items-start gap-2 text-sm">
                <span className={`mt-1 h-1.5 w-1.5 flex-shrink-0 rounded-full ${i.state === "open" ? "bg-amber-500" : "bg-zinc-300 dark:bg-zinc-600"}`} />
                <a href={i.url} target="_blank" rel="noopener noreferrer" className="text-zinc-700 hover:text-sky-700 hover:underline dark:text-zinc-300 dark:hover:text-sky-400">
                  {i.title}
                  <span className="ml-1 text-xs text-zinc-400">#{i.number} · {i.state}</span>
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* How to use */}
      <section className="rounded-2xl border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-zinc-900">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-zinc-500">
          How to use it
        </h2>
        <div className="text-[15px] leading-relaxed text-zinc-700 dark:text-zinc-300">
          <Markdown source={report.howToUse} />
        </div>
      </section>

      {/* Integration */}
      {report.integration && (
        <section className="rounded-2xl border border-violet-200 bg-violet-50/40 p-5 dark:border-violet-900/50 dark:bg-violet-950/20">
          <h2 className="mb-1 text-sm font-semibold uppercase tracking-wide text-violet-700 dark:text-violet-400">
            Set it up in your AI app
          </h2>
          <p className="mb-2 text-xs text-violet-700/70 dark:text-violet-400/70">
            Detected as: {labelForKind(report.integration.kind)}
          </p>
          <div className="text-[15px] leading-relaxed text-zinc-700 dark:text-zinc-300">
            <Markdown source={report.integration.instructions} />
          </div>
        </section>
      )}

      {/* Footer */}
      <footer className="space-y-2 pt-1 text-xs text-zinc-400">
        <p>{report.disclaimer}</p>
        <p>
          Investigated {report.scannedFiles.toLocaleString()} of {report.totalFilesInRepo.toLocaleString()} files
          {report.partialScan ? " (partial scan)" : ""} ·{" "}
          {report.llmUsed && report.model
            ? `report written by ${report.model.provider} ${report.model.model}`
            : "rules-only report (no AI model connected)"}
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
      return "Claude skill/agent";
    case "cli":
      return "command-line tool";
    case "library":
      return "library/package";
    case "vscode-extension":
      return "VS Code extension";
    default:
      return "general project";
  }
}
