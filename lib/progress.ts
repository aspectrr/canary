import type { Report } from "./types";

/**
 * Progress callback threaded through the investigation pipeline. Called at each
 * real stage so the UI can show a live progress bar instead of a fake spinner.
 *
 * @param pct    0–100 completion estimate
 * @param stage  machine-readable stage id (see STAGE_ORDER)
 * @param label  plain-English description of what's happening right now
 * @param detail optional extra context (e.g. "23 of 144 files")
 */
export type ProgressFn = (
  pct: number,
  stage: string,
  label: string,
  detail?: string,
) => void;

/** Ordered stages — used by the UI to show checkmarks for completed steps. */
export const STAGE_ORDER = [
  "resolve",
  "fetch-meta",
  "file-tree",
  "fetch-files",
  "scan",
  "evidence",
  "evidence-vuln",
  "evidence-issues",
  "evidence-discussions",
  "evidence-web",
  "grade",
  "report",
  "complete",
] as const;

// ---------------------------------------------------------------------------
// SSE event types (server → client stream)
// ---------------------------------------------------------------------------

export interface StreamProgress {
  type: "progress";
  pct: number;
  stage: string;
  label: string;
  detail?: string;
}

export interface StreamResult {
  type: "result";
  report: Report;
}

export interface StreamError {
  type: "error";
  message: string;
  status: number;
}

export type StreamEvent = StreamProgress | StreamResult | StreamError;
