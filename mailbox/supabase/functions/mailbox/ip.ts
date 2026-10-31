// The client address behind the gateway, and its rate key (spec 4.9).
//
// The address comes from one configured header. For X-Forwarded-For the
// entry is taken `trustedHops` places from the right: every trusted proxy
// appends the peer it saw, so the entries to its left were written by the
// client and are never used. An IPv6 address counts as its /64 (one
// subscriber's prefix), an IPv4-mapped IPv6 address as its IPv4 address.
// A missing or malformed value maps to one shared fallback key: all such
// requests are limited as one address.

export interface IpSource {
  /** Lowercase header name, MAILBOX_CLIENT_IP_HEADER (default x-forwarded-for). */
  header: string;
  /** MAILBOX_TRUSTED_HOPS (default 1): proxies that append to X-Forwarded-For. */
  trustedHops: number;
}

export const DEFAULT_IP_SOURCE: IpSource = { header: "x-forwarded-for", trustedHops: 1 };

/** What a missing or malformed address is counted as. Never a valid address. */
export const FALLBACK_ADDRESS = "-";

/** Reads the source settings; throws on a bad value (the function fails at boot). */
export function ipSourceFromEnv(header: string | undefined, hops: string | undefined): IpSource {
  const h = (header || DEFAULT_IP_SOURCE.header).toLowerCase();
  if (!/^[a-z0-9-]{1,64}$/.test(h)) throw new Error("mailbox: bad MAILBOX_CLIENT_IP_HEADER");
  const n = hops === undefined || hops === "" ? DEFAULT_IP_SOURCE.trustedHops : Number(hops);
  if (!Number.isInteger(n) || n < 1 || n > 16) throw new Error("mailbox: MAILBOX_TRUSTED_HOPS must be 1 to 16");
  return { header: h, trustedHops: n };
}

function parseV4(s: string): number[] | null {
  const m = /^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/.exec(s);
  if (!m) return null;
  const b = m.slice(1).map(Number);
  return b.every((x) => x <= 255) ? b : null;
}

function parseV6(s: string): number[] | null {
  if (!/^[0-9a-fA-F:.]{2,45}$/.test(s)) return null;
  let text = s;
  if (s.includes(".")) {
    const at = s.lastIndexOf(":");
    const v4 = parseV4(s.slice(at + 1));
    if (at < 0 || !v4) return null;
    text = s.slice(0, at + 1) + ((v4[0] << 8) | v4[1]).toString(16) + ":" + ((v4[2] << 8) | v4[3]).toString(16);
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const groups = (h: string) => (h === "" ? [] : h.split(":"));
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  const all = [...head, ...tail];
  if (!all.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  if (halves.length === 1 && all.length !== 8) return null;
  if (halves.length === 2 && all.length > 7) return null;
  const fill = new Array(8 - all.length).fill(0);
  return [
    ...head.map((g) => parseInt(g, 16)),
    ...(halves.length === 2 ? fill : []),
    ...tail.map((g) => parseInt(g, 16)),
  ];
}

/**
 * The address as counted: IPv4 as dotted decimal, IPv6 as its /64
 * (`2001:db8:1:2::/64`), IPv4-mapped IPv6 as IPv4. Null when malformed.
 */
export function normalizeIp(s: string): string | null {
  const v4 = parseV4(s);
  if (v4) return v4.join(".");
  const g = parseV6(s);
  if (!g) return null;
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    return [g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff].join(".");
  }
  return g.slice(0, 4).map((x) => x.toString(16)).join(":") + "::/64";
}

/** The normalized client address, or FALLBACK_ADDRESS. */
export function clientAddress(headers: { get(name: string): string | null }, src: IpSource): string {
  const raw = headers.get(src.header);
  if (raw === null) return FALLBACK_ADDRESS;
  let entry: string;
  if (src.header === "x-forwarded-for") {
    const parts = raw.split(",").map((p) => p.trim());
    const at = parts.length - src.trustedHops;
    if (at < 0) return FALLBACK_ADDRESS;
    entry = parts[at];
  } else {
    entry = raw.trim();
  }
  return normalizeIp(entry) ?? FALLBACK_ADDRESS;
}

/**
 * Rate keys of one secret: HMAC-SHA-256(secret, UTC date || address), the
 * date as YYYY-MM-DD. The HMAC key is imported once.
 */
export function ipKeyer(secret: Uint8Array): (nowMs: number, address: string) => Promise<Uint8Array> {
  const key = crypto.subtle.importKey("raw", secret as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const enc = new TextEncoder();
  return async (nowMs, address) => {
    const date = new Date(nowMs).toISOString().slice(0, 10);
    return new Uint8Array(await crypto.subtle.sign("HMAC", await key, enc.encode(date + address)));
  };
}

/** One-off form of ipKeyer. */
export function ipKey(secret: Uint8Array, nowMs: number, address: string): Promise<Uint8Array> {
  return ipKeyer(secret)(nowMs, address);
}
