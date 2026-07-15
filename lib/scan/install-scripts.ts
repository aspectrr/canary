import type { Finding, RepoFile, Severity } from "../types";
import { SUSPICIOUS_COMMANDS } from "./patterns";
import { lineNumber, snippetAround } from "./util";

/**
 * The single biggest supply-chain vector in open source: scripts that run
 * *automatically* when someone installs a package. This scanner finds them,
 * reads what they do, and escalates severity based on the commands inside.
 */

const AUTO_RUN = ["preinstall", "install", "postinstall", "prepare"];
const OTHER_LIFECYCLE = [
  "prepublish",
  "prepublishOnly",
  "prepack",
  "postpack",
  "preuninstall",
  "postuninstall",
  "prebuild",
  "postbuild",
];

function commandRisk(cmd: string): { level: Severity; hits: string[] } {
  const lower = cmd.toLowerCase();
  const hits = SUSPICIOUS_COMMANDS.filter((c) => lower.includes(c.toLowerCase()));
  if (!hits.length) return { level: "low", hits };
  // The nastier the capability, the higher the floor.
  const nasty = ["-encodedcommand", "downloadstring", "invoke-expression", "/dev/tcp", "iex", "base64"];
  const pipesToShell = /\|\s*(?:sh|bash|zsh|python\d?|perl|ruby|node)\b/.test(lower);
  if (hits.some((h) => nasty.includes(h.toLowerCase())) || pipesToShell) {
    return { level: "critical", hits };
  }
  const exec = ["curl", "wget", "powershell", "pwsh", "node -e", "python -c", "python3 -c", "ruby -e", "perl -e", "php -r", "nc ", "netcat", "ncat"];
  if (hits.some((h) => exec.includes(h.toLowerCase()))) return { level: "high", hits };
  return { level: "medium", hits };
}

function safeJson(text: string): Record<string, unknown> | null {
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function scanPackageJson(file: RepoFile): Finding[] {
  const pkg = safeJson(file.content);
  if (!pkg || typeof pkg !== "object") return [];
  const scripts = pkg.scripts;
  if (!scripts || typeof scripts !== "object") return [];

  const out: Finding[] = [];
  for (const [name, value] of Object.entries(scripts)) {
    if (typeof value !== "string") continue;
    const isAuto = AUTO_RUN.includes(name);
    const isOther = OTHER_LIFECYCLE.includes(name);
    if (!isAuto && !isOther) continue;

    const risk = commandRisk(value);
    let severity: Severity = isAuto ? "medium" : "info";
    if (risk.level === "critical") severity = "critical";
    else if (risk.level === "high") severity = isAuto ? "high" : "medium";
    else if (risk.level === "medium") severity = isAuto ? "high" : "low";
    else if (risk.level === "low") severity = isAuto ? "medium" : "info";

    out.push({
      id: `pkg.script.${name}`,
      category: "install-script",
      severity,
      title: isAuto
        ? `Automatic install script: \`${name}\``
        : `Lifecycle script: \`${name}\``,
      detail: isAuto
        ? `This package runs a script called "${name}" automatically when someone installs it. That's the most common way malicious packages strike — most legitimate packages don't need to run anything at install time. ${
            risk.hits.length
              ? `This one uses ${risk.hits.map((h) => `\`${h.trim()}\``).join(", ")}, which is a particular red flag.`
              : "The command looks ordinary, but you should still check what it does before trusting it."
          }`
        : `The "${name}" script runs at specific lifecycle moments (e.g. publish or build). It doesn't run on a plain install, but it's worth knowing about.`,
      file: file.path,
      evidence: value,
      snippet: value.length > 120 ? `${value.slice(0, 120)}…` : value,
    });
  }
  return out;
}

function scanNpmrc(file: RepoFile): Finding[] {
  const out: Finding[] = [];
  for (const line of file.content.split("\n")) {
    const m = line.match(/^\s*registry\s*=\s*(https?:\/\/\S+)/i);
    if (m && !/registry\.npmjs\.org/i.test(m[1])) {
      out.push({
        id: "npmrc.registry-override",
        category: "install-script",
        severity: "high",
        title: "Custom package registry configured",
        detail: `An \`.npmrc\` file tells npm to download packages from ${m[1]} instead of the official npm registry. A custom registry can serve tampered packages. Only trust this if you recognize and control that registry.`,
        file: file.path,
        evidence: line.trim(),
        snippet: line.trim(),
      });
    }
    if (/^\s*node-linker\s*=/i.test(line) && /pnp/i.test(line)) {
      // benign, ignore
    }
  }
  return out;
}

function scanSetupPy(file: RepoFile): Finding[] {
  const c = file.content;
  const out: Finding[] = [];
  const dangerous = [
    { re: /\bexec\s*\(/g, label: "exec()", why: "runs arbitrary Python code" },
    { re: /\beval\s*\(/g, label: "eval()", why: "runs arbitrary Python code" },
    {
      re: /os\.system\s*\(/g,
      label: "os.system()",
      why: "runs a shell command",
    },
    {
      re: /subprocess\.(call|run|Popen|check_output|check_call)\s*\(/g,
      label: "subprocess",
      why: "spawns external programs",
    },
    {
      re: /(urlopen|requests\.(get|post)|urllib.+open)/g,
      label: "network call",
      why: "contacts the network during install",
    },
  ];
  for (const { re, label, why } of dangerous) {
    re.lastIndex = 0;
    const m = re.exec(c);
    if (m) {
      out.push({
        id: `setuppy.${label}`,
        category: "install-script",
        severity: "high",
        title: `setup.py uses ${label}`,
        detail: `The Python install file uses ${label}, which ${why} while the package is being set up. Legitimate setup.py files rarely need to do this — it's a known way malicious Python packages hide bad behavior.`,
        file: file.path,
        line: lineNumber(c, m.index),
        evidence: label,
        snippet: snippetAround(c, m.index),
      });
    }
  }
  return out;
}

function scanMakefile(file: RepoFile): Finding[] {
  const out: Finding[] = [];
  const lower = file.content.toLowerCase();
  for (const bad of ["curl", "wget", "nc ", "bash -c", "sh -c"]) {
    const idx = lower.indexOf(bad);
    if (idx >= 0 && /(install|setup|build|all):/.test(file.content)) {
      out.push({
        id: `makefile.${bad.trim()}`,
        category: "install-script",
        severity: "medium",
        title: `Makefile target uses \`${bad.trim()}\``,
        detail: `A Makefile target (often \`make install\` or \`make setup\`) runs \`${bad.trim()}\`. Make targets can run when you follow setup instructions. Check where it downloads from before running it.`,
        file: file.path,
        evidence: bad.trim(),
        snippet: snippetAround(file.content, idx),
      });
      break;
    }
  }
  return out;
}

function scanDockerfile(file: RepoFile): Finding[]{
  const out: Finding[] = [];
  const lines = file.content.split("\n");
  lines.forEach((line, i) => {
    const lower = line.toLowerCase();
    const isRun = /^\s*run\s+/i.test(line);
    if (!isRun) return;
    const pipesToShell = /\|\s*(sh|bash|python|perl)/i.test(lower);
    const fetches = /\b(curl|wget)\b/.test(lower);
    if (fetches) {
      out.push({
        id: `dockerfile.fetch.${i}`,
        category: "install-script",
        severity: pipesToShell ? "high" : "low",
        title: pipesToShell
          ? "Dockerfile downloads and runs code"
          : "Dockerfile downloads a file",
        detail: pipesToShell
          ? "A RUN line downloads something from the internet and immediately pipes it into a shell (`curl … | sh`). This blindly runs whatever the server sends back. Only build this image if you trust the source URL."
          : "A RUN line uses curl/wget to download a file during the image build. Confirm the URL is one you trust before building.",
        file: file.path,
        line: i + 1,
        evidence: line.trim(),
        snippet: line.trim(),
      });
    }
  });
  return out;
}

export function scanInstallScripts(files: RepoFile[]): Finding[] {
  const out: Finding[] = [];
  for (const f of files) {
    const path = f.path;
    if (path.endsWith("package.json") && !/node_modules/.test(path)) {
      out.push(...scanPackageJson(f));
    } else if (basenameIs(path, ".npmrc")) {
      out.push(...scanNpmrc(f));
    } else if (path.endsWith("setup.py")) {
      out.push(...scanSetupPy(f));
    } else if (path === "Makefile" || path.endsWith("/Makefile")) {
      out.push(...scanMakefile(f));
    } else if (basenameIs(path, "Dockerfile") || /Dockerfile\.\w+$/.test(path)) {
      out.push(...scanDockerfile(f));
    }
  }
  return out;
}

function basenameIs(path: string, name: string): boolean {
  return path.split("/").pop() === name;
}
