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

      // Non-streaming error (bad URL, etc.) — the server returns plain JSON.
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
              // First time seeing this stage → mark previous ones done + append.
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
      <form onSubmit={onSubmit} className="mx-auto flex w-full max-w-2xl flex-col gap-3">
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            type="text"
            inputMode="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Paste a GitHub URL, e.g. github.com/owner/repo"
            aria-label="GitHub repository URL"
            className="flex-1 rounded-xl border border-zinc-300 bg-white px-4 py-3 text-[15px] text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100"
            disabled={status === "loading"}
          />
          <button
            type="submit"
            disabled={status === "loading" || !url.trim()}
            className="rounded-xl bg-zinc-900 px-6 py-3 text-[15px] font-semibold text-white transition hover:bg-zinc-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-200"
          >
            {status === "loading" ? "Investigating…" : "Investigate"}
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-zinc-500 dark:text-zinc-400">Try:</span>
          {EXAMPLES.map((ex) => (
            <button
              key={ex.url}
              type="button"
              disabled={status === "loading"}
              onClick={() => {
                setUrl(ex.url);
                investigate(ex.url);
              }}
              className="rounded-full border border-zinc-300 px-3 py-1 text-xs font-medium text-zinc-600 transition hover:border-sky-400 hover:text-sky-700 disabled:opacity-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:text-sky-400"
            >
              {ex.label}
            </button>
          ))}
        </div>
      </form>

      {status === "loading" && (
        <LoadingState
          pct={pct}
          label={currentLabel}
          detail={detail}
          activity={activity}
          repo={url}
        />
      )}

      {status === "error" && error && (
        <div className="mx-auto mt-6 max-w-2xl rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800 dark:border-rose-900/50 dark:bg-rose-950/30 dark:text-rose-200">
          {error}
        </div>
      )}

      {status === "done" && report && (
        <div ref={resultsRef} className="mx-auto mt-8 max-w-2xl scroll-mt-6">
          <ReportView report={report} />
          <div className="mt-6 text-center">
            <button
              type="button"
              onClick={() => {
                setStatus("idle");
                setReport(null);
                setUrl("");
              }}
              className="text-sm font-medium text-sky-700 hover:underline dark:text-sky-400"
            >
              ← Investigate another repo
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Loading state — live progress bar + activity feed driven by SSE events
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

  return (
    <div className="mx-auto mt-10 max-w-2xl">
      {/* Progress bar */}
      <div className="mb-1 flex items-center justify-between text-sm">
        <span className="font-mono text-zinc-500 dark:text-zinc-400">
          {repo.replace(/^https?:\/\/github\.com\//, "") || "Working…"}
        </span>
        <span className="font-mono text-zinc-400">{pct}%</span>
      </div>
      <div className="h-2.5 w-full overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800">
        <div
          className="h-full rounded-full bg-gradient-to-r from-sky-500 to-sky-400 transition-all duration-500 ease-out"
          style={{ width: `${Math.max(2, pct)}%` }}
        />
      </div>

      {/* Current action */}
      <p className="mt-4 text-[15px] font-medium text-zinc-800 dark:text-zinc-200">{label}</p>
      {detail && <p className="mt-0.5 text-sm text-zinc-500 dark:text-zinc-400">{detail}</p>}

      {/* Activity feed */}
      <div className="mt-5 rounded-xl border border-zinc-200 bg-zinc-50/80 p-4 dark:border-zinc-800 dark:bg-zinc-900/50">
        <ul className="space-y-2">
          {activity.map((item, i) => (
            <li key={i} className="flex items-center gap-2.5 text-sm">
              {item.done ? (
                <svg
                  className="h-4 w-4 flex-shrink-0 text-emerald-500"
                  viewBox="0 0 20 20"
                  fill="currentColor"
                >
                  <path
                    fillRule="evenodd"
                    d="M16.7 5.3a1 1 0 0 1 0 1.4l-7.5 7.5a1 1 0 0 1-1.4 0l-3.5-3.5a1 1 0 1 1 1.4-1.4l2.8 2.8 6.8-6.8a1 1 0 0 1 1.4 0z"
                    clipRule="evenodd"
                  />
                </svg>
              ) : (
                <span className="flex h-4 w-4 flex-shrink-0 items-center justify-center">
                  <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-sky-200 border-t-sky-500 dark:border-zinc-700 dark:border-t-sky-400" />
                </span>
              )}
              <span
                className={
                  item.done
                    ? "text-zinc-500 line-through decoration-zinc-300 dark:text-zinc-500 dark:decoration-zinc-700"
                    : "text-zinc-900 dark:text-zinc-100"
                }
              >
                {item.label.replace(/…$/, "")}
              </span>
            </li>
          ))}
        </ul>
      </div>

      <p className="mt-3 text-center text-xs text-zinc-400">{elapsed}s elapsed</p>
    </div>
  );
}
