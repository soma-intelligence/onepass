// OnePass mailbox edge function (spec 4.6 to 4.9, 4.11). Routes and checks
// are in routes.ts; this file reads the secrets and wires the database,
// Storage and the clock.
//
// Secrets: MAILBOX_DB_URL (pooler, transaction mode, as onepass_mailbox_api),
// MAILBOX_IP_HMAC_SECRET (at least 32 characters), MAILBOX_OPEN_SIGNUP
// ("true" or absent), MAILBOX_PUBLISHABLE_KEY, MAILBOX_REALTIME_URL, and the
// platform's SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (Storage only).
// MAILBOX_STORAGE_PUBLIC_URL is for a local stack only: the origin and path
// clients reach Storage at, when SUPABASE_URL is a container address.
import { connect } from "./db.ts";
import { storageSigner } from "./storage.ts";
import { clientIp, handler } from "./routes.ts";

function required(name: string): string {
  const v = Deno.env.get(name);
  if (!v) throw new Error(`mailbox: missing secret ${name}`);
  return v;
}

const ipSecret = required("MAILBOX_IP_HMAC_SECRET");
if (ipSecret.length < 32) throw new Error("mailbox: MAILBOX_IP_HMAC_SECRET is shorter than 32 characters");

const handle = handler({
  db: connect(required("MAILBOX_DB_URL")),
  signer: storageSigner(
    required("SUPABASE_URL"),
    required("SUPABASE_SERVICE_ROLE_KEY"),
    Deno.env.get("MAILBOX_STORAGE_PUBLIC_URL") || undefined,
  ),
  ipSecret: new TextEncoder().encode(ipSecret),
  openSignup: Deno.env.get("MAILBOX_OPEN_SIGNUP") === "true",
  publishableKey: Deno.env.get("MAILBOX_PUBLISHABLE_KEY") || undefined,
  realtimeUrl: Deno.env.get("MAILBOX_REALTIME_URL") || undefined,
  now: Date.now,
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
});

Deno.serve((req, info) => {
  const peer = info.remoteAddr.transport === "tcp" || info.remoteAddr.transport === "udp"
    ? info.remoteAddr.hostname
    : "";
  return handle(req, clientIp(req.headers, peer));
});
