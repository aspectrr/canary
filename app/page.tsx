import { InvestigatorForm } from "@/components/InvestigatorForm";

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center px-4 py-16 sm:py-24">
      <div className="w-full max-w-3xl text-center">
        <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-zinc-200 bg-white px-3 py-1 text-xs font-medium text-zinc-600 shadow-sm dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
          Plain-English safety reports for open-source code
        </div>

        <h1 className="text-balance text-4xl font-semibold tracking-tight text-zinc-900 sm:text-5xl dark:text-zinc-50">
          Is this open-source project safe to use?
        </h1>

        <p className="mx-auto mt-4 max-w-xl text-pretty text-[17px] leading-relaxed text-zinc-600 dark:text-zinc-400">
          Paste a GitHub link. Aspectrr reads the code, checks for malware red
          flags, and tells you in plain English whether you can trust it — plus
          how to actually use it.
        </p>
      </div>

      <div className="mt-10 w-full">
        <InvestigatorForm />
      </div>

      <div className="mt-20 grid w-full max-w-3xl gap-4 sm:grid-cols-3">
        {[
          {
            title: "Reads the code",
            body: "Scans install scripts, dependencies, and source files for the patterns malicious packages use.",
          },
          {
            title: "No jargon",
            body: "Findings are explained like you've never read code before — not a wall of CVE numbers.",
          },
          {
            title: "Next steps",
            body: "Get install instructions and, when relevant, how to wire it into Claude, Codex, or Cursor.",
          },
        ].map((f) => (
          <div
            key={f.title}
            className="rounded-2xl border border-zinc-200 bg-white p-5 text-left dark:border-zinc-800 dark:bg-zinc-900"
          >
            <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{f.title}</h3>
            <p className="mt-1.5 text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">{f.body}</p>
          </div>
        ))}
      </div>
    </main>
  );
}
