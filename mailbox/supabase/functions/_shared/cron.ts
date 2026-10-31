// The cron key the pg_net jobs send (migration 20261031120400): both
// janitor functions run with verify_jwt = false and check
// `Authorization: Bearer <mailbox_cron_key>` themselves, before any
// database or Storage call.

const enc = new TextEncoder();

/** Shortest key accepted at boot: 32 characters (random, from the Vault). */
export const CRON_KEY_MIN = 32;

/** The key from the environment; refuses to boot without a long enough one. */
export function cronKeyFromEnv(value: string | undefined): string {
  if (!value) throw new Error("missing secret MAILBOX_CRON_KEY");
  if (value.length < CRON_KEY_MIN) throw new Error(`MAILBOX_CRON_KEY is shorter than ${CRON_KEY_MIN} characters`);
  return value;
}

async function sha256(s: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}

/**
 * True when `header` is exactly `Bearer <key>`. Both sides are hashed and
 * the digests compared without an early exit, so neither the content nor
 * the length of the key shows in the time taken. The header is used as
 * given, never trimmed.
 */
export async function cronAuthorized(header: string | null, key: string): Promise<boolean> {
  const prefixOk = header !== null && header.startsWith("Bearer ");
  const given = prefixOk ? header.slice(7) : "";
  const [a, b] = await Promise.all([sha256(given), sha256(key)]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return prefixOk && key.length >= CRON_KEY_MIN && diff === 0;
}

/** 401 with no detail: what an unauthorised caller learns is that it is one. */
export function unauthorized(): Response {
  return new Response(null, { status: 401, headers: { "www-authenticate": "Bearer" } });
}

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
