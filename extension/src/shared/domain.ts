import { getDomain } from "tldts";

export interface ParsedOrigin {
  /** `scheme://host[:port]`, host lowercase ASCII (punycode), no trailing dot. */
  origin: string;
  host: string;
  /** Registrable domain (eTLD+1, private suffixes included), or the host. */
  site: string;
  https: boolean;
}

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
  return {
    origin: `${u.protocol}//${host}${port}`,
    host,
    site,
    https: u.protocol === "https:",
  };
}

/** Same registrable domain; false when either URL is unparsable. */
export function sameSite(a: string, b: string): boolean {
  const pa = parseOrigin(a);
  const pb = parseOrigin(b);
  return pa !== null && pb !== null && pa.site === pb.site;
}

/** True only for a parsable `https` URL. */
export function isSecure(url: string): boolean {
  return parseOrigin(url)?.https === true;
}
