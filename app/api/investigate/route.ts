import { GitHubError } from "@/lib/github";
import { investigate, UserInputError } from "@/lib/investigate";
import type { StreamEvent } from "@/lib/progress";

// Allow generous time for scan + AI synthesis. Slower models (e.g. Kimi k2.5)
// can take 60-75s for the model call alone; GitHub/OSV/issues intake adds more.
// Set higher than the model timeout (OPENROUTER_TIMEOUT_MS, default 120s).
export const maxDuration = 180;
// Always run at request time — never cached.
export const dynamic = "force-dynamic";

const encoder = new TextEncoder();

/** Format a single SSE data frame. */
function sseFrame(event: StreamEvent): Uint8Array {
  return encoder.encode(`data: ${JSON.stringify(event)}\n\n`);
}

export async function POST(request: Request): Promise<Response> {
  let body: { url?: unknown };
  try {
    body = (await request.json()) as { url?: unknown };
  } catch {
    return Response.json(
      { error: 'Send a JSON body like { "url": "https://github.com/owner/repo" }.' },
      { status: 400 },
    );
  }

  const url = typeof body.url === "string" ? body.url.trim() : "";
  if (!url) {
    return Response.json({ error: "Please provide a GitHub repository URL." }, { status: 400 });
  }

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (event: StreamEvent): void => {
        controller.enqueue(sseFrame(event));
      };

      try {
        const report = await investigate(url, (pct, stage, label, detail) => {
          send({ type: "progress", pct, stage, label, detail });
        });
        send({ type: "result", report });
      } catch (err) {
        let status = 500;
        let message = "Investigation failed unexpectedly.";

        if (err instanceof GitHubError) {
          status = err.kind === "not-found" ? 404 : err.kind === "rate-limit" ? 429 : 502;
          message = err.message;
        } else if (err instanceof UserInputError) {
          status = 400;
          message = err.message;
        } else if (err instanceof Error) {
          message = err.message;
        }

        send({ type: "error", message, status });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
