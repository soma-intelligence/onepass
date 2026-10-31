// mailbox-gc entry point: secrets and wiring. verify_jwt = false in
// config.toml: the gateway is open, gc.ts checks the cron key itself.
//
// Secrets: MAILBOX_CRON_KEY (at least 32 characters), MAILBOX_JANITOR_DB_URL
// (as onepass_mailbox_janitor), and the platform's SUPABASE_URL and
// SUPABASE_SERVICE_ROLE_KEY (Storage only; the database is never reached with
// the service key). MAILBOX_STORAGE_INTERNAL_URL overrides SUPABASE_URL for
// Storage calls on a local stack.
import { createClient } from "@supabase/supabase-js";
import { cronKeyFromEnv } from "../_shared/cron.ts";
import { connectJanitor } from "../_shared/janitor.ts";
import { handler } from "./gc.ts";
import { graveStore, objectStore } from "./store.ts";

function required(name: string): string {
  const v = Deno.env.get(name);
  if (!v) throw new Error(`mailbox-gc: missing secret ${name}`);
  return v;
}

const db = connectJanitor(required("MAILBOX_JANITOR_DB_URL"), "onepass-mailbox-gc");

const storage = createClient(
  Deno.env.get("MAILBOX_STORAGE_INTERNAL_URL") || required("SUPABASE_URL"),
  required("SUPABASE_SERVICE_ROLE_KEY"),
  { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } },
).storage;

const handle = handler({
  cronKey: cronKeyFromEnv(Deno.env.get("MAILBOX_CRON_KEY")),
  graves: graveStore(db),
  objects: objectStore(storage),
  now: Date.now,
  log: (m) => console.log(m),
});

Deno.serve((req) => handle(req));
