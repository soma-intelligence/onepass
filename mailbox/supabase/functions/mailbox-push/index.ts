// mailbox-push entry point: secrets and wiring. verify_jwt = false in
// config.toml: the gateway is open, push.ts checks the cron key itself.
//
// Secrets: MAILBOX_CRON_KEY (the Vault's mailbox_cron_key, at least 32
// characters), MAILBOX_JANITOR_DB_URL (as onepass_mailbox_janitor).
// MAILBOX_PUSH_PROVIDERS (required, no default): "none" (the hosted
// instance: wake-ups are skipped, clients rely on Realtime and polling) or
// "log" (local stack: wake-ups are logged without the token). APNs is added
// when its five secrets are set (MAILBOX_APNS_KEY, _KEY_ID, _TEAM_ID, _TOPIC,
// _HOST); FCM comes with plan X4.
import { cronKeyFromEnv } from "../_shared/cron.ts";
import { connectJanitor } from "../_shared/janitor.ts";
import { apnsConfigFromEnv, ApnsProvider } from "./apns.ts";
import { providersFromEnv } from "./providers.ts";
import { handler } from "./push.ts";
import { pushStore } from "./store.ts";

const dbUrl = Deno.env.get("MAILBOX_JANITOR_DB_URL");
if (!dbUrl) throw new Error("mailbox-push: missing secret MAILBOX_JANITOR_DB_URL");
const db = connectJanitor(dbUrl, "onepass-mailbox-push");

const apns = apnsConfigFromEnv((name) => Deno.env.get(name));
const providers = providersFromEnv(Deno.env.get("MAILBOX_PUSH_PROVIDERS"), apns ? new ApnsProvider(apns) : null);

const handle = handler({
  cronKey: cronKeyFromEnv(Deno.env.get("MAILBOX_CRON_KEY")),
  store: pushStore(db),
  providers,
  now: Date.now,
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  log: (m) => console.log(m),
});

Deno.serve((req) => handle(req));
