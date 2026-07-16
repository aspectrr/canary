import type { DiscussionRef, IssueRef, RepoDiscussions, RepoIssues } from "./types";
import type { DiscussionRaw, IssueRaw } from "./github";

/** Keywords/labels that mark an issue as security-relevant. */
const SEC_LABELS = [
  "security",
  "vulnerability",
  "vuln",
  "cve",
  "malware",
  "backdoor",
  "exploit",
  "rce",
  "xss",
  "csrf",
  "ssrf",
  "injection",
  "supply chain",
  "supply-chain",
  "crypto",
  "cryptographic",
  "data leak",
  "breach",
  "auth",
  "authentication",
  "authorization",
  "privilege",
];

const SEC_KEYWORDS = [
  "security",
  "vulnerab",
  "cve-",
  "malware",
  "backdoor",
  "remote code",
  " rce ",
  "xss",
  "csrf",
  "ssrf",
  "injection",
  "supply chain",
  "supply-chain",
  "token leak",
  "secret leak",
  "credential",
  "data exfil",
  "privilege escalat",
  "sandbox escape",
  "cryptographic",
  "weakness",
  "exploit",
];

function isSecurityRelated(title: string, labels: string[]): boolean {
  const t = ` ${title.toLowerCase()} `;
  if (labels.some((l) => SEC_LABELS.includes(l.toLowerCase()))) return true;
  return SEC_KEYWORDS.some((k) => t.includes(k));
}

export function summarizeIssues(raw: IssueRaw[]): RepoIssues {
  const refs: IssueRef[] = raw.map((i) => {
    const labels = (i.labels ?? []).map((l) => l.name).filter(Boolean);
    return {
      number: i.number,
      title: i.title,
      state: i.state,
      url: i.html_url,
      labels,
      securityRelated: isSecurityRelated(i.title, labels),
    };
  });

  return {
    total: refs.length,
    open: refs.filter((r) => r.state === "open").length,
    securityRelated: refs.filter((r) => r.securityRelated).slice(0, 8),
    recent: refs.slice(0, 8),
  };
}

/** Classify discussions the same way as issues. Discussions carry no labels
 * in the minimal GraphQL query we run, so classification is title-only. */
export function summarizeDiscussions(
  raw: { total: number; nodes: DiscussionRaw[] } | null,
): RepoDiscussions | null {
  if (!raw) return null;
  const refs: DiscussionRef[] = raw.nodes.map((d) => ({
    number: d.number,
    title: d.title,
    url: d.url,
    securityRelated: isSecurityRelated(d.title, []),
  }));
  return {
    total: raw.total,
    securityRelated: refs.filter((r) => r.securityRelated).slice(0, 8),
    recent: refs.slice(0, 8),
  };
}
