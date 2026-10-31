// mailbox-gc (spec 4.11): pg_cron calls it every hour with
// `Authorization: Bearer <mailbox_cron_key>`. It drains blob_graves, the
// object names of collected blobs:
//
//   gc_take(limit)  -> (mailbox, object name) rows, marked taken;
//   Storage remove  -> the object is gone (an object already absent counts
//                      as deleted);
//   gc_done(...)    -> the grave is dropped (idempotent).
//
// The object is always deleted before gc_done. A Storage error skips gc_done:
// the grave stays taken and maintenance hands it out again after 10 minutes.
// This function keeps its own 10 minute timer from each gc_take reply and
// drops older takes without deleting (maintenance may already have handed
// them to another collector): defense in depth, since a name is never reused
// (generations only grow) and a grave never names a live object.
import { cronAuthorized, json, unauthorized } from "../_shared/cron.ts";

export interface Grave {
  mailboxId: Uint8Array;
  objectName: string;
}

export interface GraveStore {
  /** gc_take(limit). */
  take(limit: number): Promise<Grave[]>;
  /** gc_done(mailbox, name). */
  done(grave: Grave): Promise<void>;
}

export interface ObjectStore {
  /**
   * Resolves when the bucket exists; rejects when it is missing or Storage
   * cannot say. Checked before every run: Storage answers a bulk delete in a
   * missing bucket the way it answers one of a missing object (an empty
   * list), so without this check a wrong bucket or project would drop every
   * grave while the real objects stay.
   */
  ready(): Promise<void>;
  /** Deletes one object; "missing" when it was not there. Rejects on any Storage error. */
  remove(objectName: string): Promise<"deleted" | "missing">;
}

export interface GcDeps {
  cronKey: string;
  graves: GraveStore;
  objects: ObjectStore;
  now(): number;
  log(message: string): void;
}

/** A take older than this is dropped without deleting (matches maintenance). */
export const TAKE_TTL_MS = 10 * 60 * 1000;
export const TAKE_LIMIT = 100;
export const MAX_TAKES = 50;
/** No new take starts after this; the rest waits for the next hour. */
export const BUDGET_MS = 25_000;

const NAME = /^([0-9a-f]{32})\/[0-9a-f]{64}\.[1-9][0-9]{0,18}$/;

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

interface Summary {
  taken: number;
  deleted: number;
  missing: number;
  failed: number;
  dropped: number;
}

export function handler(deps: GcDeps): (req: Request) => Promise<Response> {
  async function one(g: Grave, tookAt: number, s: Summary): Promise<void> {
    // Never delete a name that is not of the form and mailbox the database
    // constrains it to: this key can remove any object of the bucket.
    const m = NAME.exec(g.objectName);
    if (!m || g.mailboxId.length !== 16 || m[1] !== hex(g.mailboxId)) {
      s.failed++;
      deps.log("mailbox-gc: a grave with a malformed object name was left alone");
      return;
    }
    if (deps.now() - tookAt > TAKE_TTL_MS) {
      s.dropped++;
      return;
    }
    try {
      const r = await deps.objects.remove(g.objectName);
      if (r === "missing") s.missing++;
    } catch {
      s.failed++;
      deps.log("mailbox-gc: Storage refused a deletion");
      return;
    }
    try {
      await deps.graves.done(g);
      s.deleted++;
    } catch {
      s.failed++;
      deps.log("mailbox-gc: gc_done failed after a deletion");
    }
  }

  async function run(): Promise<Summary> {
    const s: Summary = { taken: 0, deleted: 0, missing: 0, failed: 0, dropped: 0 };
    // No take before the bucket is known to exist: graves stay untouched.
    try {
      await deps.objects.ready();
    } catch (e) {
      deps.log("mailbox-gc: the Storage bucket is missing or unreachable, no grave taken");
      throw e;
    }
    const deadline = deps.now() + BUDGET_MS;
    for (let n = 0; n < MAX_TAKES && deps.now() < deadline; n++) {
      const graves = await deps.graves.take(TAKE_LIMIT);
      const tookAt = deps.now();
      if (graves.length === 0) break;
      s.taken += graves.length;
      // One at a time: each deletion is checked against the timer just
      // before it starts.
      for (const g of graves) await one(g, tookAt, s);
    }
    return s;
  }

  return async (req) => {
    if (!(await cronAuthorized(req.headers.get("authorization"), deps.cronKey))) return unauthorized();
    if (req.method !== "POST") return new Response(null, { status: 405, headers: { allow: "POST" } });
    try {
      const s = await run();
      if (s.taken > 0) deps.log(`mailbox-gc: ${JSON.stringify(s)}`);
      return json(200, s);
    } catch {
      return json(503, { error: "retry" });
    }
  };
}
