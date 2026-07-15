"use client";

import { useEffect, useRef, useState } from "react";

import { ReportView } from "./ReportView";
import type { ApiError, Report } from "@/lib/types";

const EXAMPLES = [
  { label: "vercel/next.js", url: "https://github.com/vercel/next.js" },
  { label: "anthropics/courses", url: "https://github.com/anthropics/courses" },
  { label: "modelcontextprotocol/servers", url: "https://github.com/modelcontextprotocol/servers" },
];

const LOADING_STEPS = [
  "Fetching the repository…",
  "Reading the code and README…",
  "Checking install scripts…",
  "Hunting for hidden or obfuscated code…",
  "Looking for secrets and sketchy endpoints…",
  "Checking dependencies for known vulnerabilities…",
  "Reviewing recent issue reports…",
  "Writing your plain-English report…",
];

type Status = "idle" | "loading" | "done" | "error";

export function InvestigatorForm() {
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState(0);
  const resultsRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (status !== "loading") return;
    setStep(0);
    const id = setInterval(() => setStep((s) => (s + 1) % LOADING_STEPS.length), 2400);
    return () => clearInterval(id);
  }, [status]);

  useEffect(() => {
    if (status === "done" && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [status]);

  async function investigate(target: string) {
    const trimmed = target.trim();
    if (!trimmed) return;
    setStatus("loading");
    setError(null);
    setReport(null);
    try {
      const res = await fetch("/api/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: trimmed }),
      });
      const data = (await res.json()) as Report | ApiError;
      if (!res.ok) {
        const msg = (data as ApiError).error ?? "Something went wrong.";
        setError(msg);
        setStatus("error");
        return;
      }
      setReport(data as Report);
      setStatus("done");
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

      {status === "loading" && <LoadingState step={step} repo={url} />}

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

function LoadingState({ step, repo }: { step: number; repo: string }) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const t0 = Date.now();
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 500);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="mx-auto mt-10 max-w-2xl text-center">
      <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-2 border-zinc-300 border-t-sky-600 dark:border-zinc-700 dark:border-t-sky-400" />
      <p className="font-mono text-sm text-zinc-500 dark:text-zinc-400">{repo || "Working…"}</p>
      <p className="mt-1 text-[15px] text-zinc-700 transition-all dark:text-zinc-300">
        {LOADING_STEPS[step]}
      </p>
      <p className="mt-3 text-xs text-zinc-400">
        {elapsed < 3
          ? "This usually takes 5–20 seconds."
          : elapsed < 25
            ? `${elapsed}s… still working — scanning dozens of files.`
            : `${elapsed}s… the AI is writing your report now. This can take up to a minute.`}
      </p>
    </div>
  );
}
