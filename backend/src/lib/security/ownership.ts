import { promises as dns } from "node:dns";
import { randomBytes } from "node:crypto";

/**
 * Ownership verification, same pattern used by Google Search Console /
 * AWS domain verification: the target owner must publish a random token
 * as a DNS TXT record before scans against that hostname are allowed.
 * This is what stops SENTINEL from becoming an open scanning service —
 * you can't authorize a scan against a domain you don't control DNS for.
 */

const TXT_PREFIX = "sentinel-verify=";

export function generateVerificationToken(): string {
  return randomBytes(16).toString("hex");
}

export async function checkTxtVerification(
  hostname: string,
  expectedToken: string
): Promise<boolean> {
  let records: string[][];
  try {
    records = await dns.resolveTxt(hostname);
  } catch {
    return false; // NXDOMAIN, no TXT records, etc. — treat as unverified
  }

  const flat = records.map((chunks) => chunks.join(""));
  return flat.some((txt) => txt.trim() === `${TXT_PREFIX}${expectedToken}`);
}

export function verificationRecordFor(token: string): string {
  return `${TXT_PREFIX}${token}`;
}
