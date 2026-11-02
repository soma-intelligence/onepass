// The database side of mailbox-push: push_take, push_forget and
// push_forget_target as the janitor role (migrations 20261031120400 and
// 20261101120100).
import { type JanitorDb, logSqlError } from "../_shared/janitor.ts";
import type { PushStore } from "./push.ts";

export function pushStore(db: JanitorDb): PushStore {
  return {
    async take(limit) {
      try {
        const rows = await db.call("push_take", [{ value: limit, cast: "integer" }]);
        return rows.map((r) => ({
          mailboxId: r.mailbox_id as Uint8Array,
          credentialId: r.credential_id as Uint8Array,
          tag: r.tag instanceof Uint8Array ? r.tag : null,
          kind: Number(r.push_kind),
          token: r.push_token as Uint8Array,
        }));
      } catch (e) {
        logSqlError("mailbox-push", e);
        throw e;
      }
    },
    async forget(credential, tag, token) {
      try {
        if (tag === null) {
          await db.call("push_forget", [{ value: credential, cast: "bytea" }, { value: token, cast: "bytea" }]);
        } else {
          await db.call("push_forget_target", [
            { value: credential, cast: "bytea" },
            { value: tag, cast: "bytea" },
            { value: token, cast: "bytea" },
          ]);
        }
      } catch (e) {
        logSqlError("mailbox-push", e);
        throw e;
      }
    },
  };
}
