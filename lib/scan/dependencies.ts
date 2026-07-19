import type { Ecosystem, Finding, PackageRef, RepoFile } from "../types";

interface Dep {
  name: string;
  ecosystem: Ecosystem;
  /** Raw spec/constraint, e.g. "^1.2.3", ">=4.0", "v1.2.3". */
  spec?: string;
  /** Cleaned version string for vuln lookup, e.g. "1.2.3", or "" if none. */
  version?: string;
  source?: "registry" | "git" | "file" | "http" | "local";
  /** True if this is a runtime/shipped dependency (not dev/peer-only). */
  runtime?: boolean;
}

/** Extract the first version-like substring (e.g. "^1.2.3" -> "1.2.3"). */
function extractVersion(spec: string): string {
  const m = spec.match(/\d+(?:\.\d+){0,2}/);
  return m ? m[0] : "";
}

function pkgJsonDeps(content: string): Dep[] {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content);
  } catch {
    return [];
  }
  const out: Dep[] = [];
  // Only `dependencies` and `optionalDependencies` ship to end users;
  // dev/peer deps are excluded from vuln lookups (see collectPackages).
  const sections: Array<{ name: string; runtime: boolean }> = [
    { name: "dependencies", runtime: true },
    { name: "optionalDependencies", runtime: true },
    { name: "peerDependencies", runtime: false },
    { name: "devDependencies", runtime: false },
    { name: "bundledDependencies", runtime: true },
  ];
  for (const { name: section, runtime } of sections) {
    const deps = pkg[section];
    if (Array.isArray(deps)) {
      for (const name of deps) if (typeof name === "string") out.push({ name, ecosystem: "npm", runtime });
    } else if (deps && typeof deps === "object") {
      for (const [name, spec] of Object.entries(deps)) {
        if (typeof spec !== "string") {
          out.push({ name, ecosystem: "npm", runtime });
          continue;
        }
        let source: Dep["source"] = "registry";
        if (/^git(\+(ssh|https))?:\/\//i.test(spec) || /^github:/i.test(spec)) source = "git";
        else if (/^file:/i.test(spec)) source = "file";
        else if (/^https?:/i.test(spec) && !/^https:\/\/registry\.npmjs\.org/i.test(spec)) source = "http";
        else if (/^\.\.?\/|^\//.test(spec)) source = "local";
        out.push({ name, ecosystem: "npm", spec, version: extractVersion(spec), source, runtime });
      }
    }
  }
  return out;
}

function requirementsDeps(content: string): Dep[] {
  const out: Dep[] = [];
  for (const raw of content.split("\n")) {
    const line = raw.split("#")[0].trim();
    if (!line) continue;
    if (/^(?:-r|--|git\+|https?:)/i.test(line)) continue;
    // Skip dev/test requirement files' extras by name conventions handled
    // at the file level; here just parse.
    const m = line.match(/^([A-Za-z0-9_.-]+)/);
    if (m) {
      const version = extractVersion(line.slice(m[0].length));
      out.push({ name: m[1].toLowerCase().replace(/_/g, "-"), ecosystem: "PyPI", version, runtime: true });
    }
  }
  return out;
}

function goModDeps(content: string): Dep[] {
  const out: Dep[] = [];
  const push = (line: string): void => {
    const m = line.match(/^\s*(?:require\s+)?([^\s]+)\s+v([\w.-]+)/);
    if (m && m[1] !== "module") {
      out.push({ name: m[1], ecosystem: "Go", spec: `v${m[2]}`, version: extractVersion(m[2]), runtime: true });
    }
  };
  for (const line of content.split("\n")) if (/^\s*require\s+\S/.test(line) || /^\s*\S+\s+v/.test(line)) push(line);
  const block = content.match(/require\s*\(([\s\S]*?)\)/);
  if (block) for (const line of block[1].split("\n")) push(line);
  return out;
}

function cargoDeps(content: string): Dep[] {
  const out: Dep[] = [];
  for (const block of content.matchAll(/\[dependencies\]([\s\S]*?)(?=\[|$)/g)) {
    for (const line of block[1].split("\n")) {
      const m = line.match(/^\s*([A-Za-z0-9_-]+)\s*=\s*["']?([^"'\s]+)/);
      if (m) out.push({ name: m[1].toLowerCase(), ecosystem: "crates.io", spec: m[2], version: extractVersion(m[2]), runtime: true });
    }
  }
  for (const block of content.matchAll(/\[dev-dependencies\]([\s\S]*?)(?=\[|$)/g)) {
    for (const line of block[1].split("\n")) {
      const m = line.match(/^\s*([A-Za-z0-9_-]+)\s*=\s*["']?([^"'\s]+)/);
      if (m) out.push({ name: m[1].toLowerCase(), ecosystem: "crates.io", spec: m[2], version: extractVersion(m[2]), runtime: false });
    }
  }
  return out;
}

function gemfileDeps(content: string): Dep[] {
  const out: Dep[] = [];
  const re = /gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content))) {
    out.push({
      name: m[1].toLowerCase(),
      ecosystem: "RubyGems",
      spec: m[2],
      version: m[2] ? extractVersion(m[2]) : "",
      runtime: true,
    });
  }
  return out;
}

function composerDeps(content: string): Dep[] {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content);
  } catch {
    return [];
  }
  const out: Dep[] = [];
  const req = pkg.require;
  if (req && typeof req === "object") {
    for (const [name, spec] of Object.entries(req as Record<string, unknown>)) {
      if (name === "php") continue;
      const s = typeof spec === "string" ? spec : "";
      out.push({ name: name.toLowerCase(), ecosystem: "Packagist", spec: s, version: extractVersion(s), runtime: true });
    }
  }
  return out;
}

/** Directories that hold comparison/test/demo harnesses — manifests here pin
 * tools for testing, not what end users install. e.g. esbuild's
 * `require/webpack5/package.json`. Safe to exclude: no real shipping package
 * declares its runtime deps inside `require/`, `compat/`, or `demo/`. */
const HARNESS_DIRS = new Set([
  "require",
  "compat",
  "compat-table",
  "demo",
  "demos",
  "playground",
  "sandboxes",
  "sandbox",
  "repro",
  "repros",
]);

function inHarnessDir(path: string): boolean {
  return path.split("/").some((seg) => HARNESS_DIRS.has(seg));
}

function depsForFile(file: RepoFile): Dep[] {
  if (inHarnessDir(file.path)) return [];
  const p = file.path;
  if (p.endsWith("package.json") && !/node_modules/.test(p)) return pkgJsonDeps(file.content);
  if (p.endsWith("requirements.txt") || /requirements-[\w-]+\.txt$/.test(p)) return requirementsDeps(file.content);
  if (p.endsWith("go.mod")) return goModDeps(file.content);
  if (p.endsWith("Cargo.toml")) return cargoDeps(file.content);
  if (p.endsWith("Gemfile")) return gemfileDeps(file.content);
  if (p.endsWith("composer.json")) return composerDeps(file.content);
  return [];
}

/** All declared dependencies across manifests (for counting + source checks). */
export function collectAllDeps(files: RepoFile[]): Dep[] {
  const out: Dep[] = [];
  for (const file of files) for (const d of depsForFile(file)) out.push(d);
  return out;
}

/** Distinct RUNTIME packages with a concrete version, for OSV.dev lookup. */
export function collectPackages(files: RepoFile[]): PackageRef[] {
  const seen = new Set<string>();
  const out: PackageRef[] = [];
  for (const d of collectAllDeps(files)) {
    if (d.runtime === false) continue; // skip dev/peer-only deps
    if (!d.version) continue;
    const key = `${d.ecosystem}:${d.name.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ name: d.name, ecosystem: d.ecosystem, version: d.version });
  }
  return out;
}

export function scanDependencies(files: RepoFile[]): Finding[] {
  const out: Finding[] = [];
  const allDeps = collectAllDeps(files);
  const totalDeps = allDeps.length;

  for (const dep of allDeps) {
    if (dep.source && dep.source !== "registry") {
      const label = {
        git: "a Git repository",
        file: "a local path",
        http: "a direct HTTP URL",
        local: "a local path",
      }[dep.source]!;
      out.push({
        id: `dep.source.${dep.source}.${dep.name}`,
        category: "dependency",
        severity: dep.source === "http" ? "high" : "low",
        title: `Dependency \`${dep.name}\` comes from ${label}`,
        detail:
          dep.source === "http" || dep.source === "git"
            ? `Instead of the standard package registry, \`${dep.name}\` is pulled from ${label}${
                dep.spec ? ` (${dep.spec})` : ""
              }. Packages fetched this way bypass normal review and can be swapped for malicious versions. Check that you trust the exact source.`
            : `\`${dep.name}\` is pulled from ${label} rather than a registry. That's not necessarily dangerous, but it means the dependency isn't independently published and reviewed.`,
        evidence: dep.spec,
      });
    }
  }

  if (totalDeps >= 120) {
    out.push({
      id: "dep.count",
      category: "dependency",
      severity: "info",
      title: `Large dependency tree (${totalDeps} declared)`,
      detail: `This project declares ${totalDeps}+ dependencies. Each one is another place a vulnerability or malicious update could sneak in. It's not a problem on its own, just a larger "blast radius" to be aware of.`,
    });
  }

  return out;
}
