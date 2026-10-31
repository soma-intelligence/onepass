// The database side of mailbox-push: push_take and push_forget as the
// janitor role (migration 20261031120400).
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
          kind: Number(r.push_kind),
          token: r.push_token as Uint8Array,
        }));
      } catch (e) {
        logSqlError("mailbox-push", e);
        throw e;
      }
    },
    async forget(credential, token) {
      try {
        await db.call("push_forget", [{ value: credential, cast: "bytea" }, { value: token, cast: "bytea" }]);
      } catch (e) {
        logSqlError("mailbox-push", e);
        throw e;
      }
    },
  };
}
