// mailbox-push entry point: secrets and wiring. verify_jwt = false in
// config.toml: the gateway is open, push.ts checks the cron key itself.
//
// Secrets: MAILBOX_CRON_KEY (the Vault's mailbox_cron_key, at least 32
// characters), MAILBOX_JANITOR_DB_URL (as onepass_mailbox_janitor).
// MAILBOX_PUSH_PROVIDERS: "log" (default; wake-ups are logged without the
// token, clients poll) or "none". APNs and FCM providers come with plans X1b
// and X4.
import { cronKeyFromEnv } from "../_shared/cron.ts";
import { connectJanitor } from "../_shared/janitor.ts";
import { LogProvider, type PushProvider } from "./providers.ts";
import { handler } from "./push.ts";
import { pushStore } from "./store.ts";

const dbUrl = Deno.env.get("MAILBOX_JANITOR_DB_URL");
if (!dbUrl) throw new Error("mailbox-push: missing secret MAILBOX_JANITOR_DB_URL");
const db = connectJanitor(dbUrl, "onepass-mailbox-push");

const mode = Deno.env.get("MAILBOX_PUSH_PROVIDERS") ?? "log";
if (mode !== "log" && mode !== "none") throw new Error("mailbox-push: MAILBOX_PUSH_PROVIDERS is log or none");
const providers: PushProvider[] = mode === "log" ? [1, 2, 3].map((k) => new LogProvider(k)) : [];

const handle = handler({
  cronKey: cronKeyFromEnv(Deno.env.get("MAILBOX_CRON_KEY")),
  store: pushStore(db),
  providers,
  now: Date.now,
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  log: (m) => console.log(m),
});

Deno.serve((req) => handle(req));
