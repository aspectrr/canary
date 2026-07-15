/**
 * Minimal OpenRouter client (OpenAI-compatible). Uses fetch — no SDK needed.
 *
 * Docs: https://openrouter.ai/docs/api-reference/overview
 *
 * Env:
 *   OPENROUTER_API_KEY  (required for AI reports; without it the app uses
 *                        deterministic rules-only reports)
 *   OPENROUTER_MODEL    default "anthropic/claude-sonnet-4.5"
 *   OPENROUTER_BASE_URL default "https://openrouter.ai/api/v1"
 *   OPENROUTER_REFERER  optional HTTP-Referer for app attribution
 *   APP_TITLE           optional X-Title for app attribution
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
 * Request a chat completion via streaming and return the accumulated text.
 *
 * Uses stream:true so the connection stays alive as long as the model is
 * actively producing tokens. The timeout is a STALL detector (abort if no
 * data arrives for `stallMs`), not a hard total cap — so slow models like
 * Kimi k2.5 (which varies from 56s to 120s+) won't get cut off mid-generation.
 *
 * Returns null on any failure (caller falls back to deterministic report).
 */
export async function complete(
  opts: CompletionOptions,
  stallMs = Number(process.env.OPENROUTER_TIMEOUT_MS) || 120_000,
): Promise<string | null> {
  const base = process.env.OPENROUTER_BASE_URL ?? DEFAULT_BASE;
  const body: Record<string, unknown> = {
    model: activeModel(),
    messages: opts.messages,
    max_tokens: opts.maxTokens ?? 2048,
    temperature: opts.temperature ?? 0.2,
    stream: true,
  };
  if (opts.responseFormat) body.response_format = opts.responseFormat;

  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> = setTimeout(() => controller.abort(), stallMs);
  const resetTimer = (): void => {
    clearTimeout(timer);
    timer = setTimeout(() => controller.abort(), stallMs);
  };

  try {
    const res = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) return null;
    if (!res.body) return null;

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
          if (chunk.error) return null;
          const delta = chunk.choices?.[0]?.delta?.content;
          if (typeof delta === "string") {
            fullContent += delta;
            opts.onToken?.(fullContent.length);
          }
        } catch {
          /* ignore partial/malformed SSE lines */
        }
      }
    }

    return fullContent || null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
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
): Promise<string | null> {
  return complete({
    messages,
    responseFormat: { type: "json_object" },
    maxTokens,
    onToken,
  });
}
