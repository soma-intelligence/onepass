// Cleaning applied to every string captured from a page before it is written:
// no address, no digit run, no long opaque token, no long text.

const EMAIL = /[^\s@]+@[^\s@]+\.[^\s@]+/;
const LONG_TOKEN = /[A-Za-z0-9]{25,}/;
const MAX_TEXT = 60;
const MAX_TOKEN = 40;

function isSensitive(t: string): boolean {
  const digits = t.replace(/(?<=\d)[ \-]+(?=\d)/g, "");
  return EMAIL.test(t) || /\d{4,}/.test(digits) || LONG_TOKEN.test(t);
}

export function sanitizeText(s: string | null | undefined): string | undefined {
  if (s == null) return undefined;
  const t = s.replace(/\s+/g, " ").trim();
  if (!t) return undefined;
  if (isSensitive(t)) return "<redacted>";
  return t.length > MAX_TEXT ? t.slice(0, MAX_TEXT) : t;
}

export function sanitizeToken(s: string | null | undefined): string | undefined {
  if (s == null || s === "") return undefined;
  if (isSensitive(s)) return "<redacted>";
  return s.length > MAX_TOKEN ? "<long>" : s;
}
