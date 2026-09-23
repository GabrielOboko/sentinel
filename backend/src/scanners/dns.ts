import { promises as dns } from "node:dns";
import type { PinnedTarget } from "../lib/security/ssrf.js";
import type { RawFinding } from "../types/index.js";

async function safeResolveTxt(hostname: string): Promise<string[]> {
  try {
    const records = await dns.resolveTxt(hostname);
    return records.map((chunks) => chunks.join(""));
  } catch {
    return [];
  }
}

export async function scanDns(pinned: PinnedTarget): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const hostname = pinned.hostname;

  // --- SPF ---
  const rootTxt = await safeResolveTxt(hostname);
  const spf = rootTxt.find((t) => t.startsWith("v=spf1"));
  if (!spf) {
    findings.push({
      module: "dns",
      severity: "medium",
      title: "No SPF record found",
      description: "Without SPF, receiving mail servers can't verify which hosts are allowed to send email as this domain, making spoofing easier.",
      remediation: 'Publish a TXT record like "v=spf1 include:_spf.example.com -all".',
    });
  } else if (spf.includes("+all")) {
    findings.push({
      module: "dns",
      severity: "high",
      title: "SPF record allows any sender (+all)",
      description: `SPF record "${spf}" ends in +all, which permits any server to send mail as this domain.`,
      remediation: 'Change the SPF mechanism to "-all" (hard fail) or "~all" (soft fail).',
      rawEvidence: { spf },
    });
  }

  // --- DMARC ---
  const dmarcTxt = await safeResolveTxt(`_dmarc.${hostname}`);
  const dmarc = dmarcTxt.find((t) => t.startsWith("v=DMARC1"));
  if (!dmarc) {
    findings.push({
      module: "dns",
      severity: "medium",
      title: "No DMARC record found",
      description: "Without DMARC, there's no policy telling receiving servers what to do with mail that fails SPF/DKIM, and no reporting on abuse.",
      remediation: 'Publish "_dmarc.<domain>" TXT record, e.g. "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com".',
    });
  } else if (/p=none/i.test(dmarc)) {
    findings.push({
      module: "dns",
      severity: "low",
      title: "DMARC policy is set to 'none'",
      description: "DMARC is published but set to monitor-only (p=none), so failing mail is not rejected or quarantined.",
      remediation: 'Move to "p=quarantine" or "p=reject" once reports confirm legitimate mail passes.',
      rawEvidence: { dmarc },
    });
  }

  // --- Common DKIM selectors (best-effort; DKIM selectors aren't discoverable via DNS alone) ---
  const commonSelectors = ["default", "google", "selector1", "selector2", "k1"];
  const dkimResults = await Promise.all(
    commonSelectors.map(async (sel) => ({
      sel,
      found: (await safeResolveTxt(`${sel}._domainkey.${hostname}`)).length > 0,
    }))
  );
  if (!dkimResults.some((r) => r.found)) {
    findings.push({
      module: "dns",
      severity: "info",
      title: "No DKIM record found at common selectors",
      description: `Checked selectors [${commonSelectors.join(", ")}] — none published a DKIM key. This is a best-effort check; a non-standard selector would be missed.`,
      remediation: "Confirm your mail provider's DKIM selector and ensure the corresponding TXT record is published.",
    });
  }

  if (findings.length === 0) {
    findings.push({
      module: "dns",
      severity: "info",
      title: "Email authentication records look healthy",
      description: "SPF and DMARC are present with reasonably strict policies.",
    });
  }

  return findings;
}
