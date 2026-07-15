import { GitHubError } from "@/lib/github";
import { investigate, UserInputError } from "@/lib/investigate";
import type { ApiError } from "@/lib/types";

// Allow generous time for scan + AI synthesis. Slower models (e.g. Kimi k2.5)
// can take 60-75s for the model call alone; GitHub/OSV/issues intake adds more.
// Set higher than the model timeout (OPENROUTER_TIMEOUT_MS, default 120s).
export const maxDuration = 180;
// Always run at request time — never cached.
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  let body: { url?: unknown };
  try {
    body = (await request.json()) as { url?: unknown };
  } catch {
    return jsonError("Send a JSON body like { \"url\": \"https://github.com/owner/repo\" }.", 400);
  }

  const url = typeof body.url === "string" ? body.url.trim() : "";
  if (!url) {
    return jsonError("Please provide a GitHub repository URL.", 400);
  }

  try {
    const report = await investigate(url);
    return Response.json(report);
  } catch (err) {
    if (err instanceof GitHubError) {
      const status =
        err.kind === "not-found" ? 404 : err.kind === "rate-limit" ? 429 : 502;
      return jsonError(err.message, status, err.kind);
    }
    if (err instanceof UserInputError) {
      return jsonError(err.message, 400);
    }
    const message = err instanceof Error ? err.message : "Investigation failed unexpectedly.";
    return jsonError(message, 500);
  }
}

function jsonError(error: string, status: number, detail?: string): Response {
  const body: ApiError = { error, detail };
  return Response.json(body, { status });
}
