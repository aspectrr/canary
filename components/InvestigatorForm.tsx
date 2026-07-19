"use client";

import { useEffect, useRef, useState } from "react";

import { ReportView } from "./ReportView";
import type { Report } from "@/lib/types";
import type { StreamEvent } from "@/lib/progress";

const EXAMPLES = [
  { label: "vercel/next.js", url: "https://github.com/vercel/next.js" },
  { label: "anthropics/courses", url: "https://github.com/anthropics/courses" },
  { label: "modelcontextprotocol/servers", url: "https://github.com/modelcontextprotocol/servers" },
];

interface ActivityItem {
  label: string;
  done: boolean;
}

type Status = "idle" | "loading" | "done" | "error";

export function InvestigatorForm() {
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Live progress state
  const [pct, setPct] = useState(0);
  const [currentLabel, setCurrentLabel] = useState("");
  const [detail, setDetail] = useState<string | undefined>(undefined);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const seenStagesRef = useRef<Set<string>>(new Set());
  const resultsRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (status === "done" && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [status]);

  async function investigate(target: string) {
    const trimmed = target.trim();
    if (!trimmed) return;

    // Reset state for a fresh investigation.
    setStatus("loading");
    setError(null);
    setReport(null);
    setPct(0);
    setCurrentLabel("Starting…");
    setDetail(undefined);
    setActivity([]);
    seenStagesRef.current = new Set();

    try {
      const res = await fetch("/api/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: trimmed }),
      });

      // Non-streaming error (bad URL, etc.): the server returns plain JSON.
      if (!res.ok || !res.body) {
        let msg = "Something went wrong.";
        try {
          const data = await res.json();
          msg = data.error ?? msg;
        } catch {
          /* keep default */
        }
        setError(msg);
        setStatus("error");
        return;
      }

      // Read the SSE stream.
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        // SSE events are separated by blank lines.
        const frames = buffer.split("\n\n");
        buffer = frames.pop() ?? "";

        for (const frame of frames) {
          for (const line of frame.split("\n")) {
            if (!line.startsWith("data: ")) continue;
            let payload: StreamEvent;
            try {
              payload = JSON.parse(line.slice(6)) as StreamEvent;
            } catch {
              continue;
            }

            if (payload.type === "progress") {
              setPct(payload.pct);
              setCurrentLabel(payload.label);
              setDetail(payload.detail);
              // First time seeing this stage: mark previous ones done + append.
              if (!seenStagesRef.current.has(payload.stage)) {
                seenStagesRef.current.add(payload.stage);
                setActivity((prev) => [
                  ...prev.map((a) => ({ ...a, done: true })),
                  { label: payload.label, done: false },
                ]);
              }
            } else if (payload.type === "result") {
              setReport(payload.report);
              setStatus("done");
            } else if (payload.type === "error") {
              setError(payload.message);
              setStatus("error");
            }
          }
        }
      }
    } catch {
      setError("Couldn't reach the server. Make sure the app is running and try again.");
      setStatus("error");
    }
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    investigate(url);
  }

  return (
    <div className="w-full">
      <form onSubmit={onSubmit} className="flex w-full flex-col gap-3 sm:flex-row">
        <input
          type="text"
          inputMode="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="github.com/owner/repo"
          aria-label="GitHub repository URL"
          className="min-w-0 flex-1 border border-ink/25 bg-bone px-4 py-3 text-[15px] text-ink outline-none transition placeholder:text-ink/35 focus:border-ink"
          disabled={status === "loading"}
        />
        <button
          type="submit"
          disabled={status === "loading" || !url.trim()}
          className="border border-ink bg-ink px-7 py-3 text-[15px] font-semibold tracking-tight text-bone transition hover:bg-ink/85 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {status === "loading" ? "Investigating" : "Investigate"}
        </button>
      </form>

      <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
        <span className="text-ink/45">Try</span>
        {EXAMPLES.map((ex) => (
          <button
            key={ex.url}
            type="button"
            disabled={status === "loading"}
            onClick={() => {
              setUrl(ex.url);
              investigate(ex.url);
            }}
            className="border border-ink/20 px-3 py-1 text-xs font-medium text-ink/70 transition hover:border-ink hover:text-ink disabled:opacity-40"
          >
            {ex.label}
          </button>
        ))}
      </div>

      {status === "loading" && (
        <LoadingState pct={pct} label={currentLabel} detail={detail} activity={activity} repo={url} />
      )}

      {status === "error" && error && (
        <div className="mt-6 border-2 border-ink bg-bone p-4 text-sm font-medium text-ink">
          {error}
        </div>
      )}

      {status === "done" && report && (
        <div ref={resultsRef} className="mt-12 scroll-mt-6">
          <ReportView report={report} />
          <div className="mt-10">
            <button
              type="button"
              onClick={() => {
                setStatus("idle");
                setReport(null);
                setUrl("");
              }}
              className="border-b border-ink/40 pb-0.5 text-sm font-medium text-ink hover:border-ink"
            >
              Investigate another repo
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Loading state: live progress bar + activity feed driven by SSE events
// ---------------------------------------------------------------------------

function LoadingState({
  pct,
  label,
  detail,
  activity,
  repo,
}: {
  pct: number;
  label: string;
  detail?: string;
  activity: ActivityItem[];
  repo: string;
}) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const t0 = Date.now();
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 500);
    return () => clearInterval(id);
  }, []);

  const shortRepo = repo.replace(/^https?:\/\/github\.com\//i, "") || "Working";

  return (
    <div className="mt-12">
      {/* Progress bar */}
      <div className="mb-2 flex items-center justify-between text-xs uppercase tracking-[0.14em]">
        <span className="font-mono text-ink/55">{shortRepo}</span>
        <span className="font-mono tabular-nums text-ink/45">{elapsed}s</span>
      </div>
      <div className="h-2 w-full bg-stone">
        <div
          className="h-full bg-ink transition-all duration-500 ease-out"
          style={{ width: `${Math.max(2, pct)}%` }}
        />
      </div>

      {/* Current action */}
      <p className="mt-4 text-[15px] font-medium">{label}</p>
      {detail && <p className="mt-0.5 font-mono text-sm text-ink/50">{detail}</p>}

      {/* Activity feed */}
      <div className="mt-6 border border-ink/15 bg-stone/40 p-5">
        <ul className="space-y-2.5">
          {activity.map((item, i) => (
            <li key={i} className="flex items-center gap-3 text-sm">
              {item.done ? (
                <svg
                  className="h-3.5 w-3.5 flex-shrink-0"
                  viewBox="0 0 20 20"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2.5}
                  aria-hidden
                >
                  <path d="M4 10.5l4 4 8-9" strokeLinecap="square" strokeLinejoin="miter" />
                </svg>
              ) : (
                <span className="flex h-3.5 w-3.5 flex-shrink-0 items-center justify-center">
                  <span className="h-3 w-3 animate-spin border-2 border-ink/20 border-t-ink" />
                </span>
              )}
              <span className={item.done ? "text-ink/45 line-through" : "text-ink"}>
                {item.label.replace(/…$/, "")}
              </span>
            </li>
          ))}
        </ul>
      </div>

      <p className="mt-3 text-right font-mono text-xs tabular-nums text-ink/40">{pct}%</p>
    </div>
  );
}
