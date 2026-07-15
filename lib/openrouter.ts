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

interface ChatCompletionResponse {
  choices?: { message?: { content?: string | null } }[];
  error?: { message?: string };
}

/**
 * Request a chat completion and return the assistant text. Returns null on any
 * failure (caller decides whether to retry or fall back).
 */
export async function complete(
  opts: CompletionOptions,
  timeoutMs = 45_000,
): Promise<string | null> {
  const base = process.env.OPENROUTER_BASE_URL ?? DEFAULT_BASE;
  const body: Record<string, unknown> = {
    model: activeModel(),
    messages: opts.messages,
    max_tokens: opts.maxTokens ?? 2048,
    temperature: opts.temperature ?? 0.2,
  };
  if (opts.responseFormat) body.response_format = opts.responseFormat;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) return null;
    const data = (await res.json()) as ChatCompletionResponse;
    if (data.error) return null;
    const content = data.choices?.[0]?.message?.content ?? null;
    return typeof content === "string" ? content : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Try a structured (json_schema) call first; if it fails or yields nothing
 * usable, retry with plain json_object mode (broader model support). Returns
 * the assistant text, or null if both fail.
 */
export async function completeJson(
  messages: ChatMessage[],
  schema: { name: string; schema: object },
  maxTokens?: number,
): Promise<string | null> {
  const strict = await complete({
    messages,
    responseFormat: { type: "json_schema", json_schema: { name: schema.name, strict: false, schema: schema.schema } },
    maxTokens,
  });
  if (strict && strict.trim()) return strict;

  // Broader fallback — schema is described in the prompt instead.
  return complete({
    messages,
    responseFormat: { type: "json_object" },
    maxTokens,
  });
}
