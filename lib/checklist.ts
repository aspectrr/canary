/**
 * The "common cybersecurity no-nos" framework. Passed to the model so it
 * reasons against an explicit checklist, and surfaces the ones that matter.
 *
 * Mirrors the categories the deterministic scanners look for, expressed in
 * plain English so the model can cite them in a non-technical report.
 */
export interface ChecklistItem {
  id: string;
  title: string;
  /** Why it matters, in plain English. */
  why: string;
}

export const SECURITY_CHECKLIST: ChecklistItem[] = [
  {
    id: "install-hooks",
    title: "Code that runs automatically when you install it",
    why: "The #1 supply-chain attack vector. Legitimate packages rarely need to do anything at install time. Watch for npm postinstall/preinstall/prepare scripts, Python setup.py execution, and any `curl … | sh` patterns.",
  },
  {
    id: "network-exfil",
    title: "Code that sends data to the internet from an install hook or startup",
    why: "Phoning home with your data (environment variables, tokens, files) is the goal of most malware. Discord/Telegram webhooks, raw IP addresses, and paste sites are classic exfiltration channels.",
  },
  {
    id: "credential-access",
    title: "Reading your secrets and keys",
    why: "Touching SSH keys, AWS/Google/Stripe tokens, browser cookies, password databases, or dumping all of process.env are hallmarks of credential theft.",
  },
  {
    id: "obfuscation",
    title: "Hidden or obfuscated code",
    why: "eval(), new Function, the `vm` module, large base64/hex blobs, and minified blobs can hide what code actually does. Legitimate libraries occasionally use these, but they deserve scrutiny.",
  },
  {
    id: "exec",
    title: "Running external programs (shells, commands)",
    why: "child_process / subprocess calls can download and run anything. Normal for CLI tools; unusual and risky in a library.",
  },
  {
    id: "dependency-trust",
    title: "Dependencies from non-standard sources",
    why: "Packages pulled from a Git URL, HTTP URL, or local path bypass the registry's review and can be silently swapped. Also watch for typo-squatted package or repo names.",
  },
  {
    id: "known-vulns",
    title: "Known vulnerabilities in dependencies",
    why: "A dependency with a public CVE/advisory can be exploited. Check whether fixes are available and whether the project pins a safe version.",
  },
  {
    id: "maintenance",
    title: "Project health and maintenance",
    why: "Abandoned, archived, or brand-new projects from throwaway accounts carry more risk: vulnerabilities go unpatched and there's little community scrutiny.",
  },
  {
    id: "license-provenance",
    title: "License and provenance",
    why: "No license = no legal permission to use. Missing README, no tests, and no CI are weak signs of a thrown-together or copy-paste project.",
  },
  {
    id: "open-issues",
    title: "Security-related issues in the tracker",
    why: "Unresolved issues mentioning vulnerabilities, backdoors, or data leaks are direct warnings from the community.",
  },
];

export function checklistForPrompt(): unknown[] {
  return SECURITY_CHECKLIST.map((c) => ({ id: c.id, check: c.title, why: c.why }));
}
