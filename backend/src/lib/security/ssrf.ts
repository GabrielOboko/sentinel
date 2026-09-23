import { promises as dns } from "node:dns";
import net from "node:net";

/**
 * SSRF / private-network protection.
 *
 * SENTINEL is an external attack-surface scanner, so the scanner must NEVER
 * be capable of reaching private, loopback, link-local, multicast, reserved,
 * documentation, benchmarking, or otherwise non-public addresses.
 *
 * Security invariant:
 *
 *   hostname -> DNS resolution -> validate ALL answers -> pin ONE safe IP
 *   -> every scanner connects directly to that pinned IP
 *
 * Scanner modules must never perform another hostname lookup.
 */

export class UnsafeTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsafeTargetError";
  }
}

interface Cidr {
  base: bigint;
  mask: bigint;
  family: 4 | 6;
}

function ipv4ToBigInt(ip: string): bigint {
  const parts = ip.split(".");

  if (parts.length !== 4) {
    throw new UnsafeTargetError(`Invalid IPv4 address: ${ip}`);
  }

  let value = 0n;

  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      throw new UnsafeTargetError(`Invalid IPv4 address: ${ip}`);
    }

    const octet = Number(part);

    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      throw new UnsafeTargetError(`Invalid IPv4 address: ${ip}`);
    }

    value = (value << 8n) + BigInt(octet);
  }

  return value;
}

/**
 * Converts an IPv6 address to a 128-bit integer.
 *
 * Handles:
 *   - normal IPv6
 *   - compressed IPv6 (::)
 *   - IPv4-embedded addresses
 */
function ipv6ToBigInt(ip: string): bigint {
  const normalized = ip.toLowerCase();

  if (normalized.includes("%")) {
    throw new UnsafeTargetError(`IPv6 zone identifiers are not allowed: ${ip}`);
  }

  const pieces = normalized.split("::");

  if (pieces.length > 2) {
    throw new UnsafeTargetError(`Invalid IPv6 address: ${ip}`);
  }

  const hasCompression = pieces.length === 2;

  const head = pieces[0] ? pieces[0].split(":") : [];
  const tail = hasCompression && pieces[1] ? pieces[1].split(":") : [];

  const expandPart = (part: string): number[] => {
    if (part.includes(".")) {
      const ipv4 = ipv4ToBigInt(part);

      return [
        Number((ipv4 >> 16n) & 0xffffn),
        Number(ipv4 & 0xffffn),
      ];
    }

    if (!/^[0-9a-f]{1,4}$/i.test(part)) {
      throw new UnsafeTargetError(`Invalid IPv6 address: ${ip}`);
    }

    return [parseInt(part, 16)];
  };

  const groups = [
    ...head.flatMap(expandPart),
    ...tail.flatMap(expandPart),
  ];

  if (hasCompression) {
    const missing = 8 - groups.length;

    if (missing < 1) {
      throw new UnsafeTargetError(`Invalid IPv6 compression: ${ip}`);
    }

    const expanded = [
      ...groups.slice(0, head.flatMap(expandPart).length),
      ...Array(missing).fill(0),
      ...groups.slice(head.flatMap(expandPart).length),
    ];

    return expanded.reduce(
      (value, group) => (value << 16n) + BigInt(group),
      0n
    );
  }

  if (groups.length !== 8) {
    throw new UnsafeTargetError(`Invalid IPv6 address: ${ip}`);
  }

  return groups.reduce(
    (value, group) => (value << 16n) + BigInt(group),
    0n
  );
}

function ipToBigInt(ip: string, family: 4 | 6): bigint {
  return family === 4 ? ipv4ToBigInt(ip) : ipv6ToBigInt(ip);
}

function cidr(cidrStr: string, family: 4 | 6): Cidr {
  const [base, bits] = cidrStr.split("/");
  const prefixLen = Number(bits);
  const totalBits = family === 4 ? 32 : 128;

  if (
    !Number.isInteger(prefixLen) ||
    prefixLen < 0 ||
    prefixLen > totalBits
  ) {
    throw new Error(`Invalid CIDR: ${cidrStr}`);
  }

  const mask =
    prefixLen === 0
      ? 0n
      : ((1n << BigInt(totalBits)) - 1n) ^
        ((1n << BigInt(totalBits - prefixLen)) - 1n);

  return {
    base: ipToBigInt(base, family),
    mask,
    family,
  };
}

/**
 * IPv4 ranges that must never be scanned.
 *
 * This intentionally includes more than RFC1918 private space.
 * SENTINEL should only connect to globally routable public addresses.
 */
const BLOCKED_V4: Cidr[] = [
  "0.0.0.0/8",        // unspecified / "this network"
  "10.0.0.0/8",       // private
  "100.64.0.0/10",    // carrier-grade NAT
  "127.0.0.0/8",      // loopback
  "169.254.0.0/16",   // link-local / cloud metadata
  "172.16.0.0/12",    // private
  "192.0.0.0/24",     // IETF protocol assignments
  "192.0.2.0/24",     // documentation
  "192.168.0.0/16",   // private
  "198.18.0.0/15",    // benchmarking
  "198.51.100.0/24",  // documentation
  "203.0.113.0/24",   // documentation
  "224.0.0.0/4",      // multicast
  "240.0.0.0/4",      // reserved
  "255.255.255.255/32", // limited broadcast
].map((range) => cidr(range, 4));

/**
 * IPv6 ranges that must never be scanned.
 *
 * We intentionally reject IPv6 that isn't globally routable.
 */
const BLOCKED_V6: Cidr[] = [
  "::/128",           // unspecified
  "::1/128",          // loopback
  "::ffff:0:0/96",    // IPv4-mapped IPv6
  "64:ff9b::/96",     // NAT64 well-known prefix
  "64:ff9b:1::/48",   // IPv4/IPv6 translation
  "100::/64",         // discard-only
  "2001::/32",        // Teredo
  "2001:2::/48",      // benchmarking
  "2001:db8::/32",    // documentation
  "2001:10::/28",     // ORCHID
  "fc00::/7",         // unique-local
  "fe80::/10",        // link-local
  "ff00::/8",         // multicast
].map((range) => cidr(range, 6));

function isBlocked(ip: string, family: 4 | 6): boolean {
  const value = ipToBigInt(ip, family);
  const ranges = family === 4 ? BLOCKED_V4 : BLOCKED_V6;

  return ranges.some(
    ({ base, mask }) => (value & mask) === (base & mask)
  );
}

function assertPublicIp(ip: string, family: 4 | 6): void {
  if (family === 4 && !net.isIPv4(ip)) {
    throw new UnsafeTargetError(`Invalid IPv4 address: ${ip}`);
  }

  if (family === 6 && !net.isIPv6(ip)) {
    throw new UnsafeTargetError(`Invalid IPv6 address: ${ip}`);
  }

  if (isBlocked(ip, family)) {
    throw new UnsafeTargetError(
      `Target resolves to a non-public address (${ip})`
    );
  }
}

export interface PinnedTarget {
  hostname: string;
  ip: string;
  family: 4 | 6;
}

/**
 * Resolve hostname, validate EVERY DNS answer, then pin one safe IP.
 *
 * Important:
 *
 * If ANY returned DNS address is unsafe, the entire hostname is rejected.
 *
 * We do not simply discard unsafe answers because an attacker could otherwise
 * return both a public address and an internal address and rely on resolver
 * selection behavior.
 */
export async function resolvePinnedIp(
  hostname: string
): Promise<PinnedTarget> {
  if (net.isIP(hostname)) {
    const family = net.isIPv6(hostname) ? 6 : 4;

    assertPublicIp(hostname, family);

    return {
      hostname,
      ip: hostname,
      family,
    };
  }

  let records: Awaited<ReturnType<typeof dns.lookup>>[];

  try {
    records = await dns.lookup(hostname, {
      all: true,
      verbatim: true,
    });
  } catch {
    throw new UnsafeTargetError(
      `Could not resolve hostname: ${hostname}`
    );
  }

  if (records.length === 0) {
    throw new UnsafeTargetError(
      `Could not resolve hostname: ${hostname}`
    );
  }

  for (const record of records) {
    const family = record.family === 6 ? 6 : 4;
    assertPublicIp(record.address, family);
  }

  const chosen =
    records.find((record) => record.family === 4) ??
    records[0];

  return {
    hostname,
    ip: chosen.address,
    family: chosen.family === 6 ? 6 : 4,
  };
}

/**
 * Cheap defense-in-depth check immediately before a socket connection.
 */
export function assertStillSafe(pinned: PinnedTarget): void {
  assertPublicIp(pinned.ip, pinned.family);
}
