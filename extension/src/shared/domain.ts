import { getDomain } from "tldts";

export interface ParsedOrigin {
  /** `scheme://host[:port]`, host lowercase ASCII (punycode), no trailing dot. */
  origin: string;
  host: string;
  /** Registrable domain (eTLD+1, private suffixes included), or the host. */
  site: string;
  https: boolean;
  /**
   * A page OnePass may list, plan or fill on: `https`, or `http` on a loopback host (`LOOPBACK_HOSTS`,
   * a local development server). The mirror of `onepass_bridge::origin::Origin::parse_page`.
   * Passkeys, saves and provider pages stay `https` only.
   */
  page: boolean;
}

/** The only hosts whose `http` pages count as pages (after URL normalization: `127.1` is `127.0.0.1`). */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Parse a page URL. Only http(s) URLs with a host are accepted; everything
 * else (about:, data:, javascript:, garbage) returns null. Mirrors
 * `onepass_bridge::origin::Origin` for the site computation.
 */
export function parseOrigin(url: string): ParsedOrigin | null {
  let u: URL;
  try {
    u = new URL(url.trim());
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  const host = u.hostname.toLowerCase().replace(/\.+$/, "");
  if (host === "") return null;
  const site = getDomain(host, { allowPrivateDomains: true }) ?? host;
  const port = u.port === "" ? "" : `:${u.port}`;
  const https = u.protocol === "https:";
  return {
    origin: `${u.protocol}//${host}${port}`,
    host,
    site,
    https,
    page: https || LOOPBACK_HOSTS.has(host),
  };
}

/** Same registrable domain; false when either URL is unparsable. */
export function sameSite(a: string, b: string): boolean {
  const pa = parseOrigin(a);
  const pb = parseOrigin(b);
  return pa !== null && pb !== null && pa.site === pb.site;
}

/** A page to list, plan or fill on (`ParsedOrigin.page`); false when the URL is unparsable. */
export function isPage(url: string): boolean {
  return parseOrigin(url)?.page === true;
}

/** True only for a parsable `https` URL. */
export function isSecure(url: string): boolean {
  return parseOrigin(url)?.https === true;
}
