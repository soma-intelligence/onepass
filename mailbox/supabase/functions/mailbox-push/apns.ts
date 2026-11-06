// APNs provider (plan X1b Task 10): a silent background push, no content.
// The app wakes, runs one sync round and goes back to sleep; the push says
// nothing about what changed.
import type { PushProvider } from "./providers.ts";

/** The secrets of the APNs provider; all five or none. */
export interface ApnsConfig {
  /** The .p8 key, PEM (PKCS#8, P-256). */
  key: string;
  keyId: string;
  teamId: string;
  /** The app's bundle id. */
  topic: string;
  /** api.push.apple.com, or api.sandbox.push.apple.com for development builds. */
  host: string;
}

/** The exact body of every push: a background wake, no alert, no data. */
export const APNS_PAYLOAD = '{"aps":{"content-available":1}}';

/** A provider JWT is reused this long (Apple refuses tokens older than 60 min). */
export const JWT_LIFETIME_MS = 50 * 60 * 1000;

const SECRET_NAMES = [
  "MAILBOX_APNS_KEY",
  "MAILBOX_APNS_KEY_ID",
  "MAILBOX_APNS_TEAM_ID",
  "MAILBOX_APNS_TOPIC",
  "MAILBOX_APNS_HOST",
] as const;

const HOSTS = new Set(["api.push.apple.com", "api.sandbox.push.apple.com"]);

/**
 * The APNs config from the environment: null when no secret is set, an
 * error when only some are (a deployment half configured fails at boot).
 */
export function apnsConfigFromEnv(get: (name: string) => string | undefined): ApnsConfig | null {
  const values = SECRET_NAMES.map((n) => get(n));
  if (values.every((v) => v === undefined || v === "")) return null;
  if (values.some((v) => v === undefined || v === "")) {
    throw new Error("mailbox-push: the APNs secrets are set only in part");
  }
  const [key, keyId, teamId, topic, host] = values as string[];
  if (!HOSTS.has(host)) throw new Error("mailbox-push: MAILBOX_APNS_HOST is not an APNs host");
  return { key, keyId, teamId, topic, host };
}

type Fetch = (url: string, init: RequestInit) => Promise<Response>;

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function pemBody(pem: string): Uint8Array<ArrayBuffer> {
  const body = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export class ApnsProvider implements PushProvider {
  kind = 2;
  private jwt: { token: string; at: number } | null = null;
  private signingKey: Promise<CryptoKey>;

  constructor(
    private config: ApnsConfig,
    private fetcher: Fetch = fetch,
    private now: () => number = Date.now,
  ) {
    this.signingKey = crypto.subtle.importKey(
      "pkcs8",
      pemBody(config.key),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
  }

  /** The provider token (ES256), signed again only after JWT_LIFETIME_MS. */
  async token(): Promise<string> {
    const now = this.now();
    if (this.jwt && now - this.jwt.at < JWT_LIFETIME_MS) return this.jwt.token;
    const enc = new TextEncoder();
    const header = b64url(enc.encode(JSON.stringify({ alg: "ES256", kid: this.config.keyId })));
    const claims = b64url(enc.encode(JSON.stringify({ iss: this.config.teamId, iat: Math.floor(now / 1000) })));
    const input = `${header}.${claims}`;
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      await this.signingKey,
      enc.encode(input),
    );
    const token = `${input}.${b64url(new Uint8Array(sig))}`;
    this.jwt = { token, at: now };
    return token;
  }

  async send(token: Uint8Array): Promise<"sent" | "gone" | "retry"> {
    const res = await this.fetcher(`https://${this.config.host}/3/device/${hex(token)}`, {
      method: "POST",
      headers: {
        authorization: `bearer ${await this.token()}`,
        "apns-push-type": "background",
        "apns-priority": "5",
        "apns-topic": this.config.topic,
        "content-type": "application/json",
      },
      body: APNS_PAYLOAD,
    });
    if (res.status === 200) {
      await res.body?.cancel();
      return "sent";
    }
    let reason = "";
    try {
      reason = (await res.json())?.reason ?? "";
    } catch {
      // No JSON body: the status decides.
    }
    if (res.status === 410 || (res.status === 400 && reason === "BadDeviceToken")) return "gone";
    if (res.status === 429 || res.status >= 500) return "retry";
    // A refusal that will not change on retry (bad topic, bad payload): the
    // wake is dropped, the token kept. Never logged with the token.
    return "sent";
  }
}
