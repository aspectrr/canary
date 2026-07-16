import { InvestigatorForm } from "@/components/InvestigatorForm";

/** Canary wordmark glyph: a perched songbird in ink. Transparent background. */
function CanaryMark({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 64 64" fill="currentColor" aria-hidden>
      <path d="M9 13 L23 31 L15 40 Z" />
      <circle cx="34" cy="39" r="14" />
      <circle cx="46" cy="25" r="9" />
      <path d="M53 23 L61 26 L53 29 Z" />
      <circle cx="48" cy="23" r="2.2" fill="#efedea" />
    </svg>
  );
}

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col px-5 py-10 sm:px-8 sm:py-14">
      <div className="mx-auto w-full max-w-3xl">
        {/* Wordmark row */}
        <header className="flex items-center justify-between">
          <span className="flex items-center gap-2 text-sm font-semibold uppercase tracking-[0.22em]">
            <CanaryMark className="h-5 w-5" />
            Canary
          </span>
          <span className="text-xs uppercase tracking-[0.18em] text-ink/45">
            Open-source safety
          </span>
        </header>

        {/* Hero */}
        <div className="mt-20 sm:mt-28">
          <h1 className="text-balance text-[2.6rem] font-semibold leading-[1.04] tracking-tight sm:text-6xl">
            Is this open-source project safe to use?
          </h1>

          <p className="mt-5 max-w-xl text-pretty text-lg leading-relaxed text-ink/70">
            Paste a GitHub link. We read the code, spot the red flags, and tell
            you in plain English whether you can trust it.
          </p>
        </div>

        {/* Form */}
        <div className="mt-10">
          <InvestigatorForm />
        </div>

        {/* Features — flat columns split by hairlines, not cards */}
        <div className="mt-24 grid gap-px overflow-hidden border-y border-ink/15 bg-ink/15 sm:grid-cols-3">
          {FEATURES.map((f) => (
            <div key={f.title} className="bg-bone p-6">
              <h3 className="text-sm font-semibold uppercase tracking-[0.14em]">{f.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-ink/65">{f.body}</p>
            </div>
          ))}
        </div>

        <footer className="mt-20 text-xs leading-relaxed text-ink/40">
          <p>
            Automated checks, not a guarantee. A clever attacker can hide. Treat
            every verdict as a starting point.
          </p>
        </footer>
      </div>
    </main>
  );
}

const FEATURES = [
  {
    title: "Reads the code",
    body: "Install scripts, dependencies, source files. We look for the patterns malicious packages tend to share.",
  },
  {
    title: "No jargon",
    body: "Plain English, not a wall of CVE numbers. You shouldn't need to be a developer to follow it.",
  },
  {
    title: "Next steps",
    body: "Install instructions, and when it matters, how to wire it into Claude, Codex, or Cursor.",
  },
];
