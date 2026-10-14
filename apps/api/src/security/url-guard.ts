import { promises as dns } from 'node:dns';
import { BlockList, isIP } from 'node:net';

/** Ranges that must never be reachable from a webhook destination (SSRF protection). */
const blocked = new BlockList();
const V4: Array<[string, number]> = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, includes cloud metadata (169.254.169.254)
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // documentation
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // documentation
  ['203.0.113.0', 24], // documentation
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, includes 255.255.255.255
];
const V6: Array<[string, number]> = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['64:ff9b::', 96], // NAT64: can embed any IPv4 address
  ['100::', 64], // discard-only
  ['2001:db8::', 32], // documentation
  ['fc00::', 7], // unique local (private)
  ['fe80::', 10], // link-local
  ['ff00::', 8], // multicast
];
for (const [net, prefix] of V4) blocked.addSubnet(net, prefix, 'ipv4');
for (const [net, prefix] of V6) blocked.addSubnet(net, prefix, 'ipv6');

/** True if the address is private, local, reserved, or not a valid IP. IPv4-mapped IPv6 is handled. */
export function isBlockedIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return blocked.check(ip, 'ipv4');
  if (version === 6) return blocked.check(ip, 'ipv6');
  return true; // anything we cannot classify is refused
}

export class UnsafeUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeUrlError';
  }
}

export type Resolver = (hostname: string) => Promise<string[]>;

export const systemResolver: Resolver = async (hostname) => {
  const results = await dns.lookup(hostname, { all: true, verbatim: true });
  return results.map((r) => r.address);
};

export interface UrlGuardOptions {
  /**
   * Development only: allows http and private addresses, for a receiver running on your own
   * machine. Must be false in production.
   */
  allowPrivateDestinations?: boolean;
  resolver?: Resolver;
}

const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.lan', '.home', '.corp'];
export const MAX_URL_LENGTH = 2048;

/** Static checks that do not need the network. Returns the parsed URL. */
export function parseDestination(raw: string, allowPrivate = false): URL {
  if (raw.length > MAX_URL_LENGTH) throw new UnsafeUrlError('URL is too long');
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UnsafeUrlError('URL is not valid');
  }
  if (url.protocol !== 'https:' && !(allowPrivate && url.protocol === 'http:')) {
    throw new UnsafeUrlError('Only https URLs are allowed');
  }
  if (url.username || url.password) {
    throw new UnsafeUrlError('URLs with credentials are not allowed');
  }
  if (allowPrivate) return url;

  const host = url.hostname
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '')
    .toLowerCase();
  if (host === 'localhost' || BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
    throw new UnsafeUrlError('This host name is not allowed');
  }
  if (isIP(host) !== 0 && isBlockedIp(host)) {
    throw new UnsafeUrlError('This IP address is not allowed');
  }
  return url;
}

/**
 * Full check: static rules, then DNS resolution. Every address the name resolves to must be
 * public. Returns the resolved addresses.
 *
 * Important: a DNS answer can change between this check and the real request ("DNS rebinding").
 * The delivery worker must call this again right before each send and connect to one of the
 * returned addresses, not to the host name.
 */
export async function assertPublicDestination(
  raw: string,
  options: UrlGuardOptions = {},
): Promise<{ url: URL; addresses: string[] }> {
  const allowPrivate = options.allowPrivateDestinations ?? false;
  const url = parseDestination(raw, allowPrivate);
  if (allowPrivate) return { url, addresses: [] };

  const host = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (isIP(host) !== 0) return { url, addresses: [host] };

  let addresses: string[];
  try {
    addresses = await (options.resolver ?? systemResolver)(host);
  } catch {
    throw new UnsafeUrlError('The host name cannot be resolved');
  }
  if (addresses.length === 0) throw new UnsafeUrlError('The host name cannot be resolved');
  if (addresses.some(isBlockedIp)) {
    throw new UnsafeUrlError('This host name points to a private or reserved address');
  }
  return { url, addresses };
}
