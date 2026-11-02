// mailbox-push (spec 4.10): pg_cron calls it every 10 seconds with
// `Authorization: Bearer <mailbox_cron_key>`. It takes mailboxes off the
// push queue and sends each active credential's token an empty wake-up.
//
// Queue rows: push_take reads and deletes a mailbox's row in one statement
// under its row lock (migration 20261031120400), so a commit that enqueues
// meanwhile either waits and inserts a fresh row, or is taken whole. That is
// the "delete only if enqueued_at is unchanged" rule, held by the database:
// this function never deletes a row itself. The author a row excludes is left
// out by push_take, so it never reaches a provider here. A wake-up that
// cannot be sent is lost on purpose: clients still poll.
import { cronAuthorized, json, unauthorized } from "../_shared/cron.ts";
import type { PushProvider } from "./providers.ts";

export interface PushTarget {
  mailboxId: Uint8Array;
  credentialId: Uint8Array;
  /**
   * The device tag of a per-device target (migration 20261101120100), null
   * for the credential's historical token.
   */
  tag: Uint8Array | null;
  kind: number;
  token: Uint8Array;
}

export interface PushStore {
  /** push_take(limit): the tokens to wake for up to `limit` mailboxes. */
  take(limit: number): Promise<PushTarget[]>;
  /**
   * push_forget(credential, token) for the historical token (tag null),
   * push_forget_target(credential, tag, token) for a device target: either
   * only if it still holds that token.
   */
  forget(credential: Uint8Array, tag: Uint8Array | null, token: Uint8Array): Promise<void>;
}

export interface PushDeps {
  cronKey: string;
  store: PushStore;
  providers: PushProvider[];
  now(): number;
  sleep(ms: number): Promise<void>;
  log(message: string): void;
}

/** Mailboxes taken per push_take. */
export const TAKE_LIMIT = 100;
/** Sends in flight at once. */
export const CONCURRENCY = 16;
/** Tries per token (the first plus two retries). */
export const ATTEMPTS = 3;
/** Takes per invocation at most, and the time after which none starts. */
export const MAX_TAKES = 20;
export const BUDGET_MS = 8_000;

interface Summary {
  taken: number;
  sent: number;
  gone: number;
  failed: number;
  skipped: number;
}

export function handler(deps: PushDeps): (req: Request) => Promise<Response> {
  const byKind = new Map<number, PushProvider>();
  for (const p of deps.providers) byKind.set(p.kind, p);

  async function sendOne(t: PushTarget, s: Summary): Promise<void> {
    const provider = byKind.get(t.kind);
    if (!provider) {
      s.skipped++;
      return;
    }
    for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
      let answer: "sent" | "gone" | "retry";
      try {
        answer = await provider.send(t.token);
      } catch {
        answer = "retry";
      }
      if (answer === "sent") {
        s.sent++;
        return;
      }
      if (answer === "gone") {
        s.gone++;
        try {
          await deps.store.forget(t.credentialId, t.tag, t.token);
        } catch {
          deps.log("mailbox-push: forgetting a gone token failed");
        }
        return;
      }
      if (attempt < ATTEMPTS) await deps.sleep(200 * attempt);
    }
    s.failed++;
  }

  async function run(): Promise<Summary> {
    const s: Summary = { taken: 0, sent: 0, gone: 0, failed: 0, skipped: 0 };
    const deadline = deps.now() + BUDGET_MS;
    for (let n = 0; n < MAX_TAKES && deps.now() < deadline; n++) {
      const targets = await deps.store.take(TAKE_LIMIT);
      if (targets.length === 0) break;
      s.taken += targets.length;
      for (let i = 0; i < targets.length; i += CONCURRENCY) {
        await Promise.all(targets.slice(i, i + CONCURRENCY).map((t) => sendOne(t, s)));
      }
    }
    return s;
  }

  return async (req) => {
    // Before anything else: no key, no database call.
    if (!(await cronAuthorized(req.headers.get("authorization"), deps.cronKey))) return unauthorized();
    if (req.method !== "POST") return new Response(null, { status: 405, headers: { allow: "POST" } });
    try {
      const s = await run();
      if (s.taken > 0) deps.log(`mailbox-push: ${JSON.stringify(s)}`);
      return json(200, s);
    } catch {
      // The cause was logged where it happened (the store); never echoed.
      return json(503, { error: "retry" });
    }
  };
}
