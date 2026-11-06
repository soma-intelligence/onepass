import { assertEquals, assertThrows } from "@std/assert";
import { APNS_PAYLOAD, type ApnsConfig, apnsConfigFromEnv, ApnsProvider, JWT_LIFETIME_MS } from "./apns.ts";
import { providersFromEnv } from "./providers.ts";

async function testKey(): Promise<string> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  let s = "";
  for (const b of der) s += String.fromCharCode(b);
  return `-----BEGIN PRIVATE KEY-----\n${btoa(s)}\n-----END PRIVATE KEY-----\n`;
}

async function config(): Promise<ApnsConfig> {
  return {
    key: await testKey(),
    keyId: "KEYID12345",
    teamId: "TEAMID1234",
    topic: "me.somalabs.onepass",
    host: "api.sandbox.push.apple.com",
  };
}

type Call = { url: string; init: RequestInit };

function fakeFetch(status: number, body?: unknown) {
  const calls: Call[] = [];
  const f = (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return Promise.resolve(new Response(body === undefined ? null : JSON.stringify(body), { status }));
  };
  return { f, calls };
}

Deno.test("apns_jwt_cached_50_min", async () => {
  let now = 1_700_000_000_000;
  const { f } = fakeFetch(200);
  const p = new ApnsProvider(await config(), f, () => now);
  const first = await p.token();
  now += JWT_LIFETIME_MS - 1;
  assertEquals(await p.token(), first);
  now += 2;
  const second = await p.token();
  assertEquals(second === first, false);
  const [header] = second.split(".");
  assertEquals(JSON.parse(atob(header.replaceAll("-", "+").replaceAll("_", "/"))), { alg: "ES256", kid: "KEYID12345" });
});

Deno.test("apns_410_is_gone", async () => {
  const token = new Uint8Array([0xab, 0xcd]);
  assertEquals(await new ApnsProvider(await config(), fakeFetch(410).f).send(token), "gone");
  assertEquals(
    await new ApnsProvider(await config(), fakeFetch(400, { reason: "BadDeviceToken" }).f).send(token),
    "gone",
  );
  assertEquals(await new ApnsProvider(await config(), fakeFetch(429).f).send(token), "retry");
  assertEquals(await new ApnsProvider(await config(), fakeFetch(503).f).send(token), "retry");
  assertEquals(await new ApnsProvider(await config(), fakeFetch(400, { reason: "BadTopic" }).f).send(token), "sent");
  assertEquals(await new ApnsProvider(await config(), fakeFetch(200).f).send(token), "sent");
});

Deno.test("apns_payload_has_no_content", async () => {
  const { f, calls } = fakeFetch(200);
  await new ApnsProvider(await config(), f).send(new Uint8Array([1, 2, 255]));
  assertEquals(calls.length, 1);
  assertEquals(calls[0].url, "https://api.sandbox.push.apple.com/3/device/0102ff");
  assertEquals(calls[0].init.body, APNS_PAYLOAD);
  assertEquals(APNS_PAYLOAD, '{"aps":{"content-available":1}}');
  const h = calls[0].init.headers as Record<string, string>;
  assertEquals(h["apns-push-type"], "background");
  assertEquals(h["apns-priority"], "5");
  assertEquals(h["apns-topic"], "me.somalabs.onepass");
});

Deno.test("apns_without_secrets_not_registered", async () => {
  assertEquals(apnsConfigFromEnv(() => undefined), null);
  assertThrows(() => apnsConfigFromEnv((n) => (n === "MAILBOX_APNS_KEY" ? "x" : undefined)));
  const all: Record<string, string> = {
    MAILBOX_APNS_KEY: "k",
    MAILBOX_APNS_KEY_ID: "i",
    MAILBOX_APNS_TEAM_ID: "t",
    MAILBOX_APNS_TOPIC: "me.somalabs.onepass",
    MAILBOX_APNS_HOST: "example.com",
  };
  assertThrows(() => apnsConfigFromEnv((n) => all[n]));
  assertEquals(providersFromEnv("none"), []);
  const apns = new ApnsProvider(await config(), fakeFetch(200).f);
  assertEquals(providersFromEnv("none", apns).map((p) => p.kind), [2]);
  assertEquals(providersFromEnv("log", apns).map((p) => p.kind), [1, 3, 2]);
  assertEquals(providersFromEnv("log", apns).find((p) => p.kind === 2), apns);
});
