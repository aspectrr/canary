import type { Finding, RepoFile } from "../types";
import { SUSPICIOUS_HOSTS, SUSPICIOUS_TLDS } from "./patterns";
import { lineNumber, snippetAround } from "./util";

/**
 * Finds where the code reaches out to (and what secrets it touches):
 * raw IPs, abuse-prone domains/TLDs, exfiltration endpoints (Discord/Telegram
 * webhooks), and embedded credentials/keys. Network calls to odd places, next
 * to credential reads, are the most concrete malware signal we can catch.
 */

interface SecretRule {
  id: string;
  re: RegExp;
  severity: Finding["severity"];
  title: string;
  detail: string;
}

const SECRET_RULES: SecretRule[] = [
  {
    id: "private-key",
    re: /-----BEGIN (?:[A-Z ]*)?PRIVATE KEY-----/,
    severity: "high",
    title: "Embedded private key",
    detail:
      "A private key (SSH, TLS, or similar) is sitting in the code. It may be a committed test key, or it may be a real secret. If real, anyone with the code can use it. Either way it shouldn't be here.",
  },
  {
    id: "aws-key",
    re: /\bAKIA[0-9A-Z]{16}\b/,
    severity: "high",
    title: "Looks like an AWS access key",
    detail:
      "A string matching AWS access-key format is in the code. If it's a live key, it grants access to an AWS account. Never commit these.",
  },
  {
    id: "github-token",
    re: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/,
    severity: "high",
    title: "Looks like a GitHub token",
    detail:
      "A GitHub personal access token pattern is in the code. A live token here could let anyone read private repos or push changes. Should be removed and revoked.",
  },
  {
    id: "stripe-key",
    re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/,
    severity: "high",
    title: "Looks like a live Stripe key",
    detail:
      "A live Stripe secret key pattern appears in the code. This can move real money. Must not be committed.",
  },
  {
    id: "google-key",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/,
    severity: "medium",
    title: "Looks like a Google API key",
    detail:
      "A Google API key pattern is in the code. Keys are often meant to be public, but check it's a restricted key and not one meant to stay private.",
  },
  {
    id: "slack-token",
    re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
    severity: "medium",
    title: "Looks like a Slack token",
    detail:
      "A Slack token pattern is in the code. If live, it can read or post in a Slack workspace.",
  },
  {
    id: "btc-wallet",
    re: /\bbc1[a-z0-9]{39,59}\b/i,
    severity: "medium",
    title: "Bitcoin wallet address",
    detail:
      "A Bitcoin (bech32) address appears in the code. Wallet addresses in non-crypto software can be a sign of a crypto-mining or wallet-clipping payload.",
  },
];

const EXFIL_RE = [
  {
    id: "discord-webhook",
    re: /discord(?:app)?\.com\/api\/webhooks\/\d{15,}\/[\w-]+/i,
    severity: "high" as const,
    title: "Posts to a Discord webhook",
    detail:
      "The code sends data to a Discord webhook. This is one of the most common ways malware quietly phones home with stolen data — webhooks are free, anonymous, and look like normal Discord traffic.",
  },
  {
    id: "telegram-bot",
    re: /api\.telegram\.org\/bot\d{5,}:[A-Za-z0-9_-]{30,}\//i,
    severity: "high" as const,
    title: "Talks to a Telegram bot",
    detail:
      "The code calls the Telegram bot API with a bot token. Like Discord webhooks, this is a favorite channel for malware to exfiltrate data anonymously.",
  },
];

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

function isRawIp(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^[0-9a-f:]+$/i.test(host);
}

/** Private/reserved IPs are local bind/test addresses, not exfil targets. */
function isPrivateIp(host: string): boolean {
  if (
    host === "0.0.0.0" ||
    host === "::" ||
    host === "::1" ||
    host.startsWith("127.") ||
    host.startsWith("10.") ||
    host.startsWith("192.168.") ||
    host.startsWith("169.254.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    /^fe[89ab]/i.test(host) ||
    /^f[cd]/i.test(host)
  ) {
    return true;
  }
  return false;
}

export function scanSecretsAndEndpoints(files: RepoFile[]): Finding[] {
  const out: Finding[] = [];
  const seenHost = new Set<string>();
  const seenSecret = new Set<string>();

  for (const file of files) {
    const c = file.content;
    if (!c) continue;

    // Secrets / keys.
    for (const rule of SECRET_RULES) {
      rule.re.lastIndex = 0;
      const m = rule.re.exec(c);
      if (m && !seenSecret.has(rule.id)) {
        seenSecret.add(rule.id);
        out.push({
          id: `secret.${rule.id}`,
          category: "secret-endpoint",
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

    // Exfiltration endpoints.
    for (const rule of EXFIL_RE) {
      rule.re.lastIndex = 0;
      const m = rule.re.exec(c);
      if (m) {
        out.push({
          id: `exfil.${rule.id}`,
          category: "network",
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

    // URLs — only surface the suspicious hosts to keep signal high.
    const urlRe = /https?:\/\/[^\s"'`)>\\\]]+/gi;
    let m: RegExpExecArray | null;
    while ((m = urlRe.exec(c)) !== null) {
      const raw = m[0].replace(/[.,;]+$/, "");
      const host = hostOf(raw);
      if (!host || seenHost.has(host)) continue;
      seenHost.add(host);

      let severity: Finding["severity"] | null = null;
      let title = "";
      let detail = "";

      if (isRawIp(host)) {
        if (isPrivateIp(host)) continue;
        severity = "high";
        title = `Contacts a raw IP address (\`${host}\`)`;
        detail =
          "The code talks to a server by its IP address rather than a domain name. Legitimate services almost always use domain names; a raw IP (especially with no HTTPS) is a classic malware shortcut because it's hard to trace and easy to rotate.";
      } else if (SUSPICIOUS_HOSTS.some((s) => host === s || host.endsWith(`.${s}`))) {
        severity = "high";
        const matched = SUSPICIOUS_HOSTS.find((s) => host === s || host.endsWith(`.${s}`))!;
        title = `Contacts \`${host}\``;
        detail =
          matched.includes("discord") || matched.includes("telegram")
            ? `The code reaches ${host}. Messaging/exfil and paste services are common places malware sends stolen data.`
            : `The code reaches ${host}, a host commonly used to host payloads or collect exfiltrated data. Not always malicious, but worth understanding why it's contacted.`;
      } else {
        const tld = SUSPICIOUS_TLDS.find((t) => host.endsWith(t));
        if (tld) {
          severity = "medium";
          title = `Contacts \`${host}\``;
          detail = `The code talks to ${host}, which uses a TLD (${tld}) that sees disproportionate abuse. It may be entirely innocent, but abuse-prone TLDs are worth a second look.`;
        }
      }

      if (severity) {
        out.push({
          id: `net.host.${host}`,
          category: "network",
          severity,
          title,
          detail,
          file: file.path,
          line: lineNumber(c, m.index),
          evidence: raw,
          snippet: snippetAround(c, m.index, 100),
        });
      }
    }
  }

  return out;
}
