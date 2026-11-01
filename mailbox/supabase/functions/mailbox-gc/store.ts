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

type StorageError = { status?: number; statusCode?: string | number; message?: string; error?: string } | null;

/** The part of a Storage bucket client this function uses. */
export interface Bucket {
  remove(paths: string[]): Promise<{ data: unknown[] | null; error: StorageError }>;
}

/** The part of a Storage client this function uses. */
export interface Storage {
  getBucket(id: string): Promise<{ data: unknown; error: StorageError }>;
  from(id: string): Bucket;
}

/** Storage's NoSuchBucket, whatever field carries it. */
function bucketMissing(error: NonNullable<StorageError>): boolean {
  const e = error as Record<string, unknown>;
  return [e.code, e.error, e.message].some((v) => typeof v === "string" && /NoSuchBucket|bucket not found/i.test(v));
}

/**
 * Storage answers a bulk delete with the objects it removed: none means the
 * object was not there (so it counts as deleted); a 404 about the object
 * means the same. A missing bucket is never "missing": it rejects, and ready()
 * catches it before any take (a bulk delete in a missing bucket also answers
 * an empty list, on hosted Supabase).
 */
export function objectStore(storage: Storage): ObjectStore {
  const bucket = storage.from(BUCKET);
  return {
    async ready() {
      const { data, error } = await storage.getBucket(BUCKET);
      if (error || !data) throw new Error(error && bucketMissing(error) ? "bucket missing" : "bucket lookup failed");
    },
    async remove(name) {
      const { data, error } = await bucket.remove([name]);
      if (error) {
        if (bucketMissing(error)) throw new Error("bucket missing");
        const status = error.status ?? Number(error.statusCode);
        if (status === 404) return "missing";
        throw new Error("storage remove failed");
      }
      return data && data.length > 0 ? "deleted" : "missing";
    },
  };
}
