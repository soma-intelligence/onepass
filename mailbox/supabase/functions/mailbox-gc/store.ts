// The database and Storage sides of mailbox-gc.
import { type JanitorDb, logSqlError } from "../_shared/janitor.ts";
import type { GraveStore, ObjectStore } from "./gc.ts";

export const BUCKET = "onepass-mailbox";

/** gc_take and gc_done as the janitor role (migration 20261031120400). */
export function graveStore(db: JanitorDb): GraveStore {
  return {
    async take(limit) {
      try {
        const rows = await db.call("gc_take", [{ value: limit, cast: "integer" }]);
        return rows.map((r) => ({ mailboxId: r.mailbox_id as Uint8Array, objectName: String(r.object_name) }));
      } catch (e) {
        logSqlError("mailbox-gc", e);
        throw e;
      }
    },
    async done(g) {
      try {
        await db.call("gc_done", [{ value: g.mailboxId, cast: "bytea" }, { value: g.objectName, cast: "text" }]);
      } catch (e) {
        logSqlError("mailbox-gc", e);
        throw e;
      }
    },
  };
}

/** The part of a Storage bucket client this function uses. */
export interface Bucket {
  remove(
    paths: string[],
  ): Promise<{ data: unknown[] | null; error: { status?: number; statusCode?: string | number } | null }>;
}

/**
 * Storage answers a bulk delete with the objects it removed: none means the
 * object was not there (so it counts as deleted); a 404 means the same.
 */
export function objectStore(bucket: Bucket): ObjectStore {
  return {
    async remove(name) {
      const { data, error } = await bucket.remove([name]);
      if (error) {
        const status = error.status ?? Number(error.statusCode);
        if (status === 404) return "missing";
        throw new Error("storage remove failed");
      }
      return data && data.length > 0 ? "deleted" : "missing";
    },
  };
}
