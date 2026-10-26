// Cleaning applied to every string captured from a page before it is written:
// no address, no digit run, no long opaque token, no long text.

const EMAIL = /[^\s@]+@[^\s@]+\.[^\s@]+/;
const LONG_TOKEN = /[A-Za-z0-9]{25,}/;
const MAX_TEXT = 60;
const MAX_TOKEN = 40;

export function sanitizeText(s: string | null | undefined): string | undefined {
  if (s == null) return undefined;
  const t = s.replace(/\s+/g, " ").trim();
  if (!t) return undefined;
  const digits = t.replace(/(?<=\d)[ \-]+(?=\d)/g, "");
  if (EMAIL.test(t) || /\d{4,}/.test(digits) || LONG_TOKEN.test(t)) return "<redacted>";
  return t.length > MAX_TEXT ? t.slice(0, MAX_TEXT) : t;
}

export function sanitizeToken(s: string | null | undefined): string | undefined {
  if (s == null || s === "") return undefined;
  return s.length > MAX_TOKEN ? "<long>" : s;
}
