import type { Finding, RepoFile, Severity } from "../types";
import { isSourceFile, lineNumber, shannonEntropy, snippetAround } from "./util";

/**
 * Looks for code that hides what it does: eval/Function execution, packed
 * blobs, dynamic imports, and reads of the machine's most sensitive files.
 * These don't prove malice, but obfuscation in a package you're about to trust
 * is the pattern that deserves the most scrutiny.
 */

interface Rule {
  id: string;
  re: RegExp;
  severity: Severity;
  title: string;
  detail: string;
}

const RULES: Rule[] = [
  {
    id: "eval",
    re: /\beval\s*\(/,
    severity: "medium",
    title: "Uses `eval()`",
    detail:
      "`eval()` runs a string as code, which means the real behavior can be hidden until the moment it runs. It's occasionally legitimate but is a favorite tool for hiding what a script actually does.",
  },
  {
    id: "new-function",
    re: /\bnew\s+Function\s*\(/,
    severity: "medium",
    title: "Builds code from a string (`new Function`)",
    detail:
      "`new Function(...)` creates code from a string at runtime, similar to eval. It's used to run hidden or assembled code and is worth inspecting closely.",
  },
  {
    id: "vm",
    re: /\bvm\.(runInNewContext|runInThisContext|Script|compileFunction)\b/,
    severity: "medium",
    title: "Uses Node's `vm` to run code",
    detail:
      "The `vm` module executes code in a sandbox. Legit uses exist, but it's also how hidden payloads get run while bypassing normal inspection.",
  },
  {
    id: "child-process",
    re: /\b(?:child_process|node:child_process)\b|require\(\s*['"]child_process['"]/,
    severity: "low",
    title: "Runs external programs (`child_process`)",
    detail:
      "This code can launch other programs on your computer (via exec/spawn). That's normal for command-line tools, but in a library it's unusual and worth checking — combined with network access it can download and run anything.",
  },
  {
    id: "string-exec",
    re: /\b(?:setTimeout|setInterval|setImmediate)\s*\(\s*['"`]/,
    severity: "medium",
    title: "Runs code from a string via timer",
    detail:
      "A string is passed to setTimeout/setInterval instead of a function, which runs it as code. It's an indirect way to execute something and is often used to dodge simple checks.",
  },
  {
    id: "dynamic-require",
    re: /\brequire\s*\(\s*[^'")\s]/,
    severity: "low",
    title: "Loads modules from a computed name",
    detail:
      "A `require()` call uses a variable instead of a fixed name, so the module it loads isn't obvious from reading the code. Sometimes innocent, sometimes used to load hidden code.",
  },
  {
    id: "ssh-keys",
    re: /(?:~\/\.ssh|\/\.ssh\/|\/\.ssh|id_rsa|id_ed25519|id_ecdsa)/,
    severity: "high",
    title: "References your SSH keys",
    detail:
      "The code touches SSH key paths (`~/.ssh`, `id_rsa`, etc.). SSH keys are how you authenticate to servers and services like GitHub. Legitimate apps rarely need to read them — this is a common step in credential theft.",
  },
  {
    id: "aws-creds",
    re: /\/\.aws\/credentials|AWS_SECRET_ACCESS_KEY|credentials\.aws|\.aws\/config/,
    severity: "high",
    title: "References AWS credentials",
    detail:
      "The code references AWS credential files or secret keys. Reading these can give full access to someone's cloud account. Rarely needed by ordinary apps.",
  },
  {
    id: "sensitive-files",
    re: /\/etc\/passwd|cookies\.sqlite|Login Data|keychain|Windows\s*Vault|chrome.*(?:Login|Cookie)|firefox.*logins/i,
    severity: "medium",
    title: "References sensitive system files",
    detail:
      "The code reads files like password databases, browser cookies, or keychains. These hold logins and secrets. Ordinary apps almost never touch them — though some tools (password managers, security software) do, so consider what this project is supposed to do.",
  },
  {
    id: "env-harvest",
    re: /JSON\.stringify\s*\(\s*process\.env\b|\{\s*\.\.\.\s*process\.env\b|Buffer\.from\s*\(\s*JSON\.stringify\s*\(\s*process\.env/,
    severity: "medium",
    title: "Reads the entire set of environment variables",
    detail:
      "The code serializes the whole `process.env` object (where API keys, tokens, and secrets live). Normal apps read individual variables; dumping all of them is suspicious — it's the first step in hoovering up credentials. It becomes a real danger if that data is then sent somewhere, so check whether this code also makes network calls.",
  },
];

export function scanObfuscation(files: RepoFile[]): Finding[] {
  const out: Finding[] = [];

  for (const file of files) {
    if (!isSourceFile(file.path)) continue;
    const c = file.content;
    if (!c) continue;

    const applied = new Set<string>();

    for (const rule of RULES) {
      if (applied.has(rule.id)) continue;
      rule.re.lastIndex = 0;
      const m = rule.re.exec(c);
      if (m) {
        applied.add(rule.id);
        out.push({
          id: `obf.${rule.id}`,
          category: "obfuscation",
          severity: rule.severity,
          title: rule.title,
          detail: rule.detail,
          file: file.path,
          line: lineNumber(c, m.index),
          evidence: m[0],
          snippet: snippetAround(c, m.index, 100),
        });
      }
    }

    // Long base64 / hex blobs.
    const b64 = c.match(/[A-Za-z0-9+/]{90,}={0,2}/g);
    if (b64 && b64.length >= 2) {
      const dense = b64.filter((b) => shannonEntropy(b) > 4.5);
      if (dense.length && !applied.has("packed-blob")) {
        applied.add("packed-blob");
        out.push({
          id: "obf.packed-blob",
          category: "obfuscation",
          severity: "medium",
          title: `${dense.length} large encoded blob${dense.length === 1 ? "" : "s"}`,
          detail:
            "The code contains large base64-encoded blobs. These can hide anything — images and fonts are usually fine, but a large blob can also be a hidden payload decoded and run later. Worth a second look if it's not obviously an asset.",
          file: file.path,
          evidence: `${dense[0].slice(0, 40)}…`,
          snippet: snippetAround(c, c.indexOf(dense[0]), 100),
        });
      }
    }

    const hex = c.match(/(?:\\x[0-9a-fA-F]{2}){8,}/g);
    if (hex && !applied.has("hex-string")) {
      applied.add("hex-string");
      out.push({
        id: "obf.hex-string",
        category: "obfuscation",
        severity: "medium",
        title: "Long hex-escaped string",
        detail:
          "A long string built from `\\x..` hex escapes hides its actual contents from casual reading. Legitimate code rarely needs this; it's a common way to disguise a payload.",
        file: file.path,
        evidence: `${hex[0].slice(0, 40)}…`,
        snippet: snippetAround(c, c.indexOf(hex[0]), 100),
      });
    }

    // Heavily minified single-line code (likely packed).
    const longestLine = c.split("\n").reduce((max, l) => Math.max(max, l.length), 0);
    if (longestLine > 5000 && !applied.has("minified")) {
      applied.add("minified");
      out.push({
        id: "obf.minified",
        category: "obfuscation",
        severity: "info",
        title: "Heavily minified code",
        detail:
          "Parts of this code are minified into very long lines. Minification is normal for shipped web bundles, but in a small source file it can also be a sign of packed/obfuscated code that's hard to audit.",
        file: file.path,
      });
    }
  }

  return out;
}
