import type { Finding, RepoMeta } from "../types";
import { closestPopular } from "./util";

/** Repo-level facts derived from the file tree in the orchestrator. */
export interface RepoFlags {
  hasReadme: boolean;
  hasSecurityMd: boolean;
  hasContributing: boolean;
  hasLicenseFile: boolean;
  hasCI: boolean;
  hasTests: boolean;
  hasLockfile: boolean;
}

function daysSince(iso: string): number {
  const ms = Date.now() - new Date(iso).getTime();
  return Math.max(0, Math.round(ms / 86_400_000));
}

export function scanSignals(
  meta: RepoMeta,
  flags: RepoFlags,
  treeSize: number,
): Finding[] {
  const out: Finding[] = [];
  const ageDays = daysSince(meta.createdAt);
  const sincePush = daysSince(meta.pushedAt);
  const ownerAge = meta.ownerCreatedAt ? daysSince(meta.ownerCreatedAt) : null;

  const good = (id: string, title: string, detail: string): void => {
    out.push({ id: `signal.good.${id}`, category: "signal", severity: "info", title, detail });
  };
  const concern = (
    id: string,
    severity: Finding["severity"],
    title: string,
    detail: string,
  ): void => {
    out.push({ id: `signal.concern.${id}`, category: "signal", severity, title, detail });
  };

  // ---- Good signals -------------------------------------------------------
  if (meta.license || flags.hasLicenseFile) {
    good(
      "license",
      "Has a license",
      "The project declares a license, which means the author has stated the legal terms for using it. This is a basic sign of a real, intentional project.",
    );
  }
  if (meta.description) {
    good(
      "description",
      "Has a clear description",
      "The repository has a description, so it's clear what the project is meant to do. Anonymous or vague projects are a mild risk factor.",
    );
  }
  if (sincePush < 180) {
    good(
      "maintained",
      "Recently updated",
      `The project was updated about ${sincePush} day${sincePush === 1 ? "" : "s"} ago, so someone is still maintaining it. Abandoned projects can be riskier because vulnerabilities go unpatched.`,
    );
  }
  if (meta.stars >= 1000) {
    good(
      "popular",
      `Well-used (${meta.stars.toLocaleString()} stars)`,
      "Thousands of people have starred this project. High adoption means many eyes have been on the code, which generally lowers the chance of anything nasty hiding in it.",
    );
  } else if (meta.stars >= 100) {
    good(
      "popular",
      `Reasonably used (${meta.stars.toLocaleString()} stars)`,
      "A few hundred people have starred this project, suggesting real adoption beyond just the author.",
    );
  }
  if (flags.hasSecurityMd) {
    good(
      "security-policy",
      "Has a security policy (SECURITY.md)",
      "The project publishes a way to report security issues responsibly. That's a sign the maintainers take safety seriously.",
    );
  }
  if (flags.hasCI) {
    good(
      "ci",
      "Has automated tests/CI",
      "The project uses continuous integration (GitHub Actions or similar), which runs checks automatically. Common in well-run projects.",
    );
  }
  if (flags.hasTests) {
    good(
      "tests",
      "Includes tests",
      "There's a tests directory, which usually means the code is checked for correctness rather than thrown together.",
    );
  }
  if (ownerAge !== null && ownerAge > 365) {
    good(
      "owner-age",
      "Established maintainer account",
      `The account that owns this repo is over a year old. Brand-new accounts are a common hallmark of throwaway malware campaigns.`,
    );
  }
  if (meta.ownerType === "Organization") {
    good(
      "org-owner",
      "Owned by an organization",
      "The repo belongs to an organization rather than a personal account. Organizations are more accountable (and harder to throw away).",
    );
  }
  if (flags.hasLockfile) {
    good(
      "lockfile",
      "Pins its dependencies",
      "The project has a lockfile, which freezes exact dependency versions. That prevents a dependency from silently swapping in a bad update later.",
    );
  }

  // ---- Concerns -----------------------------------------------------------
  if (meta.disabled) {
    concern("disabled", "high", "Repository is disabled", "GitHub has marked this repository as disabled. Treat any copy with extreme caution.");
  }
  if (meta.archived) {
    concern("archived", "low", "Archived (no longer maintained)", "The author has archived this project, so it receives no updates or security fixes. It may still be usable, but you're on your own for issues.");
  }
  if (!meta.license && !flags.hasLicenseFile) {
    concern("no-license", "low", "No license", "Without a license, technically no one has permission to use the code. It's not a safety issue, but it's a yellow flag for a project meant to be shared.");
  }
  if (!flags.hasReadme) {
    concern("no-readme", "low", "No README", "There's no README explaining what the project does or how to use it. That makes the code harder to trust and harder to use safely.");
  }
  if (sincePush > 730) {
    concern("stale", "low", "Appears abandoned", `Last updated about ${Math.round(sincePush / 365)} year${Math.round(sincePush / 365) === 1 ? "" : "s"} ago. Unmaintained software can carry unpatched vulnerabilities.`);
  } else if (sincePush > 365) {
    concern("stale", "low", "Hasn't been updated in over a year", "The project hasn't seen activity in over a year, so bugs and security issues may go unaddressed.");
  }
  if (ageDays < 30 && meta.stars < 10) {
    concern("very-new", "medium", "Very new with little adoption", `This repository was created about ${ageDays} day${ageDays === 1 ? "" : "s"} ago and has almost no stars. It could be entirely legitimate, but brand-new projects have the least scrutiny and the highest historical risk.`,
    );
  }
  if (ownerAge !== null && ownerAge < 60) {
    concern("new-owner", "medium", "Maintainer account is very new", `The account that owns this repo is only about ${ownerAge} day${ownerAge === 1 ? "" : "s"} old. Attackers often create fresh accounts to publish malware and abandon them.`);
  }
  if (!meta.description) {
    concern("no-description", "low", "No description", "The repo has no description, which is slightly more common in throwaway or copy-paste projects.");
  }
  if (meta.isFork) {
    concern("fork", "info", "This is a fork", "The repo is a fork (a copy) of another project. If you plan to rely on it, check the original it's based on — forks can silently differ from upstream.");
  }
  if (treeSize === 0) {
    concern("empty", "medium", "Repository appears empty", "No files were found to scan, so there's nothing to evaluate. The repo may be empty or the default branch may have no content.");
  }

  // Repo-name typo-squat: a no-name repo mimicking a popular package.
  if (meta.stars < 50) {
    const close = closestPopular(meta.name.toLowerCase(), 1);
    if (close && close.name.toLowerCase() !== meta.name.toLowerCase()) {
      concern(
        "name-typosquat",
        "high",
        `Name mimics popular package \`${close.name}\``,
        `The repository name "${meta.name}" is nearly identical to the well-known package "${close.name}". Combined with low adoption, this is the classic shape of a typo-squatting trap. Double-check you have the real one.`,
      );
    }
  }

  return out;
}
