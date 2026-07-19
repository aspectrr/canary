/**
 * Minimal OpenRouter client (OpenAI-compatible). Uses fetch — no SDK needed.
 *
 * Docs: https://openrouter.ai/docs/api-reference/overview
 *
 * Env:
 *   OPENROUTER_API_KEY        (required for AI reports)
 *   OPENROUTER_MODEL          default "anthropic/claude-sonnet-4.5"
 *   OPENROUTER_FALLBACK_MODEL default "google/gemini-2.5-flash" (used if the
 *                             primary model fails every retry)
 *   OPENROUTER_BASE_URL       default "https://openrouter.ai/api/v1"
 *   OPENROUTER_TIMEOUT_MS     stall-detection window, default 120000
 *   OPENROUTER_REFERER        optional HTTP-Referer for app attribution
 *   APP_TITLE                 optional X-Title for app attribution
 */

const DEFAULT_BASE = "https://openrouter.ai/api/v1";
const DEFAULT_MODEL = "anthropic/claude-sonnet-4.5";

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface JsonSchemaMode {
  type: "json_schema";
  json_schema: { name: string; strict?: boolean; schema: object };
}
export interface JsonObjectMode {
  type: "json_object";
}
export type ResponseFormat = JsonSchemaMode | JsonObjectMode;

export interface CompletionOptions {
  messages: ChatMessage[];
  /** When set, requests structured output. */
  responseFormat?: ResponseFormat;
  maxTokens?: number;
  temperature?: number;
  /** Override the active model for this call (used by the model cascade). */
  model?: string;
  /** Called as the stream produces tokens, with the running character count —
   * lets the caller drive a progress bar during generation. */
  onToken?: (totalChars: number) => void;
}

export function isConfigured(): boolean {
  return Boolean(process.env.OPENROUTER_API_KEY);
}

export function activeModel(): string {
  return process.env.OPENROUTER_MODEL ?? DEFAULT_MODEL;
}

function headers(): Record<string, string> {
  const h: Record<string, string> = {
    "content-type": "application/json",
  };
  const key = process.env.OPENROUTER_API_KEY;
  if (key) h.authorization = `Bearer ${key}`;
  const referer = process.env.OPENROUTER_REFERER;
  if (referer) h["HTTP-Referer"] = referer;
  const title = process.env.APP_TITLE;
  if (title) h["X-Title"] = title;
  return h;
}

/**
 * A failure from an OpenRouter call, classified so the retry loop and the
 * model cascade can decide what to do. Retryable: rate limits (429), server
 * errors (5xx), timeouts/stalls, network blips. Non-retryable: auth (401),
 * bad request (400), model not found (404) — retrying won't help.
 */
export class OrError extends Error {
  retryable: boolean;
  status?: number;
  constructor(message: string, retryable: boolean, status?: number) {
    super(message);
    this.name = "OrError";
    this.retryable = retryable;
    this.status = status;
  }
}

const RETRYABLE_STATUS = new Set([408, 409, 425, 429, 500, 502, 503, 504]);
const MAX_ATTEMPTS = 3;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function backoffMs(attempt: number, rateLimited: boolean): number {
  const base = [1500, 4000, 8000][attempt] ?? 8000;
  return (rateLimited ? base * 2 : base) + Math.floor(Math.random() * 500);
}

/** One streaming attempt. Throws OrError on any failure; returns text on success. */
async function completeOnce(opts: CompletionOptions, stallMs: number): Promise<string> {
  const base = process.env.OPENROUTER_BASE_URL ?? DEFAULT_BASE;
  const body: Record<string, unknown> = {
    model: opts.model ?? activeModel(),
    messages: opts.messages,
    max_tokens: opts.maxTokens ?? 2048,
    temperature: opts.temperature ?? 0.2,
    stream: true,
  };
  if (opts.responseFormat) body.response_format = opts.responseFormat;

  const controller = new AbortController();
  let abortedByStall = false;
  const arm = (): void => {
    abortedByStall = true;
    controller.abort();
  };
  let timer: ReturnType<typeof setTimeout> = setTimeout(arm, stallMs);
  const resetTimer = (): void => {
    clearTimeout(timer);
    timer = setTimeout(arm, stallMs);
  };

  try {
    const res = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) {
      let detail = "";
      try {
        detail = (await res.text()).slice(0, 200);
      } catch {
        /* ignore */
      }
      throw new OrError(
        `OpenRouter ${res.status}: ${detail || res.statusText}`,
        RETRYABLE_STATUS.has(res.status),
        res.status,
      );
    }
    if (!res.body) throw new OrError("OpenRouter: empty response body", true);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let fullContent = "";
    let buffer = "";

    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      resetTimer();

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("data:")) continue;
        const payload = trimmed.slice(5).trim();
        if (payload === "[DONE]" || payload === "") continue;
        try {
          const chunk = JSON.parse(payload) as {
            choices?: { delta?: { content?: string | null } }[];
            error?: { message?: string };
          };
          if (chunk.error) {
            throw new OrError(`OpenRouter stream error: ${chunk.error.message ?? "unknown"}`, true);
          }
          const delta = chunk.choices?.[0]?.delta?.content;
          if (typeof delta === "string") {
            fullContent += delta;
            opts.onToken?.(fullContent.length);
          }
        } catch (e) {
          if (e instanceof OrError) throw e;
          /* ignore partial/malformed SSE lines */
        }
      }
    }

    if (!fullContent) throw new OrError("OpenRouter: empty completion", true);
    return fullContent;
  } catch (err) {
    if (err instanceof OrError) throw err;
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new OrError(
        abortedByStall ? "OpenRouter: generation stalled (no tokens for the timeout window)" : "OpenRouter: aborted",
        true,
      );
    }
    throw new OrError(`OpenRouter: network error — ${err instanceof Error ? err.message : "unknown"}`, true);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Streaming completion with automatic retries on transient failures (rate
 * limits, server errors, stalls, network blips). Returns null only if every
 * attempt fails or the error is non-retryable (auth / bad request).
 *
 * The timeout is a STALL detector (abort if no data arrives for `stallMs`),
 * not a hard total cap — slow models that keep producing tokens won't be cut
 * off mid-generation.
 */
export async function complete(
  opts: CompletionOptions,
  stallMs = Number(process.env.OPENROUTER_TIMEOUT_MS) || 120_000,
): Promise<string | null> {
  let lastErr: OrError | null = null;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    try {
      return await completeOnce(opts, stallMs);
    } catch (err) {
      if (!(err instanceof OrError)) return null;
      lastErr = err;
      // Auth / bad request — retrying won't help.
      if (!err.retryable) return null;
      if (attempt === MAX_ATTEMPTS - 1) break;
      await sleep(backoffMs(attempt, err.status === 429));
    }
  }
  console.error(`[canary] OpenRouter failed after ${MAX_ATTEMPTS} attempts: ${lastErr?.message}`);
  return null;
}

/**
 * Single call in json_object mode (universally supported by every model on
 * OpenRouter). We validate the structure ourselves, so json_schema enforcement
 * is redundant — and trying json_schema first then falling back doubles latency,
 * which breaks slow models (e.g. Kimi k2.5 needs ~56s for a full report).
 */
export async function completeJson(
  messages: ChatMessage[],
  _schema: { name: string; schema: object },
  maxTokens?: number,
  onToken?: (totalChars: number) => void,
  model?: string,
): Promise<string | null> {
  return complete({
    messages,
    responseFormat: { type: "json_object" },
    maxTokens,
    onToken,
    model,
  });
}

// ---------------------------------------------------------------------------
// Tool-calling (agentic) path — non-streaming.
// ---------------------------------------------------------------------------

export interface ToolCall {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

/** An assistant turn that may carry content, tool calls, or both. */
export interface AssistantMessage {
  role: "assistant";
  content: string | null;
  tool_calls?: ToolCall[];
}

/** A tool-result message appended after executing a tool call. */
export interface ToolMessage {
  role: "tool";
  tool_call_id: string;
  content: string;
}

export type AgentMessage = ChatMessage | AssistantMessage | ToolMessage;

export interface ChatTurnOptions {
  /** OpenAI-style tool definitions. Omit to disable tool use. */
  tools?: unknown[];
  model?: string;
  maxTokens?: number;
  temperature?: number;
}

interface RawChoice {
  message?: {
    content?: string | null;
    tool_calls?: ToolCall[];
  } | null;
}

/** One non-streaming attempt. Throws OrError on failure. */
async function chatOnce(
  messages: AgentMessage[],
  opts: ChatTurnOptions,
  timeoutMs: number,
): Promise<AssistantMessage> {
  const base = process.env.OPENROUTER_BASE_URL ?? DEFAULT_BASE;
  const body: Record<string, unknown> = {
    model: opts.model ?? activeModel(),
    messages,
    max_tokens: opts.maxTokens ?? 2048,
    temperature: opts.temperature ?? 0.3,
    stream: false,
  };
  if (opts.tools) {
    body.tools = opts.tools;
    body.tool_choice = "auto";
  }

  let res: Response;
  try {
    res = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    throw new OrError(
      `OpenRouter: network error — ${err instanceof Error ? err.message : "unknown"}`,
      true,
    );
  }

  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.text()).slice(0, 200);
    } catch {
      /* ignore */
    }
    throw new OrError(
      `OpenRouter ${res.status}: ${detail || res.statusText}`,
      RETRYABLE_STATUS.has(res.status),
      res.status,
    );
  }

  const data = (await res.json()) as { choices?: RawChoice[]; error?: { message?: string } };
  if (data.error) {
    throw new OrError(`OpenRouter error: ${data.error.message ?? "unknown"}`, true);
  }
  const msg = data.choices?.[0]?.message;
  if (!msg) throw new OrError("OpenRouter: empty completion", true);
  return {
    role: "assistant",
    content: msg.content ?? null,
    tool_calls: msg.tool_calls,
  };
}

/**
 * Non-streaming chat completion with tool-calling support, for the agent loop.
 * Retries transient failures. Throws OrError if a non-retryable error occurs
 * or every retry is exhausted (caller cascades to a backup model).
 */
export async function chatComplete(
  messages: AgentMessage[],
  opts: ChatTurnOptions,
  timeoutMs = 120_000,
): Promise<AssistantMessage> {
  let lastErr: OrError | null = null;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    try {
      return await chatOnce(messages, opts, timeoutMs);
    } catch (err) {
      if (!(err instanceof OrError)) throw err;
      lastErr = err;
      if (!err.retryable) throw err;
      if (attempt === MAX_ATTEMPTS - 1) break;
      await sleep(backoffMs(attempt, err.status === 429));
    }
  }
  throw lastErr ?? new OrError("OpenRouter: failed after retries", false);
}
