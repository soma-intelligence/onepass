// Shallow checks of what a page offers as a two-factor seed. The bridge and the core
// parse the URI for real; this only decides whether a scanned or pasted text is worth
// offering to save, so it never validates more than the bridge would accept.

export interface OtpauthShallow {
  uri: string;
  issuer: string;
  account: string;
}

/** The bridge refuses a longer URI, counted in UTF-8 bytes as it does. */
const MAX_URI = 2048;
const utf8 = new TextEncoder();
const BASE32 = /^[A-Z2-7]{16,}$/;

/**
 * null unless `otpauth://totp/` (scheme and type case-insensitive), at most 2048 UTF-8 bytes,
 * with a `secret` of 16+ base32 chars (lowercase and `=` padding allowed).
 */
export function shallowOtpauth(text: string): OtpauthShallow | null {
  const uri = text.trim();
  if (uri.length === 0 || uri.length > MAX_URI || utf8.encode(uri).length > MAX_URI) return null;
  const m = /^otpauth:\/\/totp\/([^?#]*)(?:\?([^#]*))?(?:#.*)?$/i.exec(uri);
  if (!m) return null;
  const params = new URLSearchParams(m[2] ?? "");
  const secret = (params.get("secret") ?? "").replace(/=+$/, "").toUpperCase();
  if (!BASE32.test(secret)) return null;
  let label: string;
  try {
    label = decodeURIComponent(m[1] ?? "");
  } catch {
    return null;
  }
  const colon = label.indexOf(":");
  const labelIssuer = colon >= 0 ? label.slice(0, colon).trim() : "";
  const account = (colon >= 0 ? label.slice(colon + 1) : label).trim();
  const issuer = (params.get("issuer") ?? "").trim() || labelIssuer;
  return { uri, issuer, account };
}

/** A pasted setup key: spaces and dashes dropped, 16+ base32 chars, returned upper-cased. */
export function pastedSecret(text: string): string | null {
  const s = text.replace(/[\s-]+/g, "").replace(/=+$/, "").toUpperCase();
  return BASE32.test(s) ? s : null;
}
