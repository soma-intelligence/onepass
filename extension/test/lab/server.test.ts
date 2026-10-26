// @vitest-environment node
// Lab server end to end over HTTPS (no browser): a 10-site world, a
// certificate for its hosts, requests routed by the Host header. Entry pages,
// password and TOTP sign-in, refusal, lookalike trap, honeypot, card check,
// mock provider sign-in and the canary.
import { createHash, createPrivateKey, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import * as https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { generateCert } from "../../e2e/cert.ts";
import { CANARY_PATH, totp } from "../../e2e/server.ts";
import patternsJson from "../../lab/corpus/patterns.json";
import type { Patterns } from "../../lab/corpus/types.ts";
import { generate } from "../../lab/gen/generate.ts";
import type { Site, World } from "../../lab/gen/model.ts";
import { IDP_HOST } from "../../lab/gen/render.ts";
import { expectedValues } from "../../lab/server/rp.ts";
import { startLabServer } from "../../lab/server/server.ts";
import type { LabServer } from "../../lab/server/server.ts";

const PATTERNS = patternsJson as unknown as Patterns;

/** First seed whose 10-site world has a lookalike and a honeypot on a password login site. */
function pickWorld(): World {
  for (let k = 0; k < 500; k++) {
    const w = generate(`lab-server-${k}`, { sites: 10, patterns: PATTERNS });
    if (w.sites.some((s) => s.lookalike) && w.sites.some((s) => s.honeypot && s.account?.password)) return w;
  }
  throw new Error("no seed with a lookalike and a honeypot");
}

const world = pickWorld();
const flow = (f: Site["flow"]) => world.sites.find((s) => s.flow === f)!;
const field = (s: Site, role: string) => s.fields.find((f) => f.role === role)!.name;

interface Res { status: number; location?: string; body: string }

/** One HTTPS client with a cookie jar per host (enough for the lab's host-only cookies). */
function client(port: number) {
  const jar = new Map<string, string>();
  return async function req(host: string, path: string, form?: Record<string, string>, json?: unknown): Promise<Res> {
    const payload = json !== undefined ? JSON.stringify(json) : form ? new URLSearchParams(form).toString() : undefined;
    const headers: Record<string, string> = { host };
    if (payload !== undefined) {
      headers["content-type"] = json !== undefined ? "application/json" : "application/x-www-form-urlencoded";
      headers["content-length"] = String(Buffer.byteLength(payload));
    }
    const cookie = jar.get(host);
    if (cookie) headers.cookie = cookie;
    return new Promise<Res>((resolve, reject) => {
      const r = https.request({
        host: "127.0.0.1", port, path, servername: host.startsWith("xn--") ? undefined : host,
        method: payload !== undefined ? "POST" : "GET", headers, rejectUnauthorized: false,
      }, (res) => {
        const set = res.headers["set-cookie"]?.[0];
        if (set) jar.set(host, set.split(";")[0]!);
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, location: res.headers.location, body: Buffer.concat(chunks).toString("utf8") }));
      });
      r.on("error", reject);
      r.end(payload);
    });
  };
}

let dir: string;
let server: LabServer;
let req: ReturnType<typeof client>;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "lab-server-"));
  server = await startLabServer(world, generateCert(dir, world.hosts));
});
afterAll(async () => {
  await server?.close();
  rmSync(dir, { recursive: true, force: true });
});
beforeEach(() => {
  server.reset();
  req = client(server.port);
});

describe("lab server", () => {
  it("entry_200_per_site", async () => {
    for (const s of world.sites) {
      const r = await req(s.host, "/");
      expect(r.status, s.host).toBe(200);
      expect(r.body).toContain(s.brand);
      if (s.lookalike) expect((await req(s.lookalike.host, "/")).status).toBe(200);
      if (s.frameHost) expect((await req(s.frameHost, `/frame?site=${s.index}`)).status).toBe(200);
    }
    expect((await req("unknown-host.test", "/")).status).toBe(404);
  });

  it("password_login_signs_in", async () => {
    const s = flow("login_single");
    const r = await req(s.host, "/", { [field(s, "username")]: s.account!.username, [field(s, "password")]: s.account!.password });
    expect(r.status).toBe(303);
    expect(r.location).toBe("/home");
    expect((await req(s.host, "/home")).body).toContain(s.account!.username);
    expect(server.events()).toEqual([
      { at: expect.any(Number), host: s.host, kind: "submit", form: "login_single", ok: true, fields: [] },
      { at: expect.any(Number), host: s.host, kind: "signin", user: s.account!.username },
    ]);
  });

  it("username_first_then_totp", async () => {
    const s = flow("login_totp");
    const id = s.fields.find((f) => f.role === "username" || f.role === "email")!.name;
    const pw = field(s, "password");
    const first = s.loginStyle === "username_first"
      ? await req(s.host, "/", { [id]: s.account!.username })
      : await req(s.host, "/", { [id]: s.account!.username, [pw]: s.account!.password });
    if (s.loginStyle === "username_first") {
      expect(first.location).toBe("/password");
      expect((await req(s.host, "/password", { [pw]: s.account!.password })).location).toBe("/otp");
    } else {
      expect(first.location).toBe("/otp");
    }
    expect((await req(s.host, "/otp", { [field(s, "otp")]: "000000" === totp(s.account!.totpSecret!) ? "111111" : "000000" })).status).toBe(200);
    const ok = await req(s.host, "/otp", { [field(s, "otp")]: totp(s.account!.totpSecret!) });
    expect(ok.location).toBe("/home");
    expect(server.events().filter((e) => e.kind === "signin")).toMatchObject([{ host: s.host, user: s.account!.username }]);
  });

  it("wrong_password_refused", async () => {
    const s = flow("login_single");
    const r = await req(s.host, "/", { [field(s, "username")]: s.account!.username, [field(s, "password")]: "nope" });
    expect(r.status).toBe(200);
    expect(r.body).toContain('class="status error"');
    expect(server.events()).toEqual([
      { at: expect.any(Number), host: s.host, kind: "submit", form: "login_single", ok: false, fields: [field(s, "password")], reason: "wrong_password" },
    ]);
    expect((await req(s.host, "/home")).body).not.toContain(s.account!.username);
  });

  it("trap_records_post", async () => {
    const s = world.sites.find((x) => x.lookalike)!;
    const pw = field(s, "password");
    const r = await req(s.lookalike!.host, "/", { [pw]: s.account!.password });
    expect(r.status).toBe(200);
    expect(server.events()).toEqual([
      { at: expect.any(Number), host: s.lookalike!.host, kind: "leak", secret: "password", field: pw, owner: s.host },
      { at: expect.any(Number), host: s.lookalike!.host, kind: "submit", form: "trap", ok: false, fields: [pw], reason: "trap" },
    ]);
    expect(JSON.stringify(server.events())).not.toContain(s.account!.password);
  });

  it("honeypot_post_refused", async () => {
    const s = world.sites.find((x) => x.honeypot && x.account?.password)!;
    const id = s.fields.find((f) => f.role === "username" || f.role === "email")!.name;
    const r = await req(s.host, "/", {
      [id]: s.account!.username, [field(s, "password")]: s.account!.password, [s.honeypot!.name]: "filled",
    });
    expect(r.status).toBe(200);
    expect(server.events()).toEqual([
      { at: expect.any(Number), host: s.host, kind: "submit", form: s.flow, ok: false, fields: [s.honeypot!.name], reason: "honeypot" },
    ]);
  });

  it("checkout_names_wrong_fields", async () => {
    const s = flow("checkout_card");
    const exp = expectedValues(world, s);
    const body = Object.fromEntries(s.fields.map((f) => [f.name, f.role === "cc_exp_month" ? exp.cc_exp!.slice(0, 2)
      : f.role === "cc_exp_year" ? exp.cc_exp!.slice(3) : exp[f.role]!]));
    const csc = field(s, "cc_csc");
    await req(s.host, "/", { ...body, [csc]: "0000" });
    await req(s.host, "/", body);
    expect(server.events().map((e) => e.kind === "submit" && [e.ok, e.fields])).toEqual([[false, [csc]], [true, []]]);
  });

  it("sso_via_provider", async () => {
    const s = flow("sso");
    const p = s.sso!.provider;
    const idp = IDP_HOST[p];
    const acct = world.idp[p].find((a) => a.email === s.sso!.email)!;
    const auth = `/o/oauth2/auth?client=${s.host}&redirect_uri=${encodeURIComponent(`https://${s.host}/oauth/callback`)}`;
    expect((await req(s.host, "/")).body).toContain(`https://${idp}/o/oauth2/auth?client=${s.host}`);
    expect((await req(idp, auth)).body).toContain(acct.email);
    expect((await req(idp, "/o/oauth2/auth", { email: acct.email, client: s.host })).location).toBe("/signin/identifier");
    expect((await req(idp, "/signin/identifier")).body).toContain(acct.email);
    let done: Res;
    if (p === "microsoft") {
      expect((await req(idp, "/signin/identifier", { email: acct.email, client: s.host })).location).toBe("/signin/password");
      done = await req(idp, "/signin/password", { email: acct.email, password: acct.password, client: s.host });
    } else {
      done = await req(idp, "/signin/identifier", { email: acct.email, password: acct.password, client: s.host });
    }
    const back = new URL(done.location!);
    expect(back.host).toBe(s.host);
    expect((await req(s.host, `${back.pathname}${back.search}`)).location).toBe("/home");
    // A code is single use.
    expect((await req(s.host, `${back.pathname}${back.search}`)).location).toBeUndefined();
    expect(server.events().filter((e) => e.kind === "signin")).toEqual([
      { at: expect.any(Number), host: s.host, kind: "signin", user: acct.email, via: p },
    ]);
    expect(server.events().some((e) => e.kind === "leak")).toBe(false);
  });

  it("passkey_assertion_signs_in", async () => {
    const s = flow("login_passkey");
    const key = s.account!.passkey!;
    const priv = createPrivateKey({ key: { kty: "EC", crv: "P-256", x: key.x, y: key.y, d: Buffer.from(key.d, "hex").toString("base64url") }, format: "jwk" });
    const assertion = (challenge: string, counter: number) => {
      const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: `https://${s.host}` }));
      const authData = Buffer.alloc(37);
      createHash("sha256").update(s.host).digest().copy(authData, 0);
      authData[32] = 0x01;
      authData.writeUInt32BE(counter, 33);
      const sig = sign("sha256", Buffer.concat([authData, createHash("sha256").update(clientData).digest()]), { key: priv, dsaEncoding: "der" });
      return { credentialId: key.credentialId, clientDataJSON: clientData.toString("base64url"),
        authenticatorData: authData.toString("base64url"), signature: sig.toString("base64url") };
    };
    const challengeOf = (html: string) => /"challenge":"([A-Za-z0-9_-]+)"/.exec(html)![1]!;
    const c1 = challengeOf((await req(s.host, "/passkey")).body);
    expect((await req(s.host, "/passkey", undefined, assertion(c1, 1))).status).toBe(200);
    // The challenge is single use, and the counter must grow.
    expect((await req(s.host, "/passkey", undefined, assertion(c1, 2))).status).toBe(403);
    const c2 = challengeOf((await req(s.host, "/passkey")).body);
    expect((await req(s.host, "/passkey", undefined, assertion(c2, 1))).status).toBe(403);
    expect(server.events().filter((e) => e.kind !== "signin").map((e) => e.kind === "submit" && e.reason))
      .toEqual([undefined, "wrong_challenge", "counter_not_increasing"]);
    expect(server.events().filter((e) => e.kind === "signin")).toMatchObject([{ host: s.host, user: s.account!.username }]);
  });

  it("password_then_passkey_requires_both", async () => {
    let w: World | undefined;
    for (let k = 0; k < 500 && !w; k++) {
      const c = generate(`lab-server-pk-${k}`, { sites: 10, patterns: PATTERNS });
      if (c.sites.some((x) => x.flow === "login_passkey" && !x.passkeyOnly && x.loginStyle === "single")) w = c;
    }
    const s = w!.sites.find((x) => x.flow === "login_passkey" && !x.passkeyOnly && x.loginStyle === "single")!;
    const d = mkdtempSync(join(tmpdir(), "lab-server-pk-"));
    const own = await startLabServer(w!, generateCert(d, w!.hosts));
    try {
      const r = client(own.port);
      // Without the password step, the passkey endpoint refuses.
      expect((await r(s.host, "/passkey", undefined, { credentialId: s.account!.passkey!.credentialId })).status).toBe(403);
      const first = await r(s.host, "/", { [field(s, "username")]: s.account!.username, [field(s, "password")]: s.account!.password });
      expect(first.location).toBe("/passkey");
      expect(own.events().filter((e) => e.kind === "signin")).toEqual([]);
      expect(own.events().filter((e) => e.kind === "submit").map((e) => e.kind === "submit" && e.reason)).toEqual(["no_pending", undefined]);
    } finally {
      await own.close();
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("sso_password_form_refused", async () => {
    let w: World | undefined;
    for (let k = 0; k < 500 && !w; k++) {
      const c = generate(`lab-server-sso-${k}`, { sites: 10, patterns: PATTERNS });
      if (c.sites.some((x) => x.flow === "sso" && x.fields.length > 0)) w = c;
    }
    const s = w!.sites.find((x) => x.flow === "sso" && x.fields.length > 0)!;
    const d = mkdtempSync(join(tmpdir(), "lab-server-sso-"));
    const own = await startLabServer(w!, generateCert(d, w!.hosts));
    try {
      const r = client(own.port);
      const acct = w!.idp[s.sso!.provider].find((a) => a.email === s.sso!.email)!;
      const res = await r(s.host, "/", { [field(s, "username")]: acct.email, [field(s, "password")]: "anything" });
      expect(res.status).toBe(200);
      expect(own.events()).toEqual([
        { at: expect.any(Number), host: s.host, kind: "submit", form: "sso", ok: false, fields: [field(s, "username")], reason: "unknown_user" },
      ]);
      // The provider password posted to the site is a leak.
      await r(s.host, "/", { [field(s, "username")]: acct.email, [field(s, "password")]: acct.password });
      expect(own.events().some((e) => e.kind === "leak" && e.owner === IDP_HOST[s.sso!.provider])).toBe(true);
    } finally {
      await own.close();
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("signup_requires_generated_password", async () => {
    const s = flow("signup");
    const email = field(s, "email");
    const [p1, p2] = s.fields.filter((f) => f.role === "new_password").map((f) => f.name);
    const weak = await req(s.host, "/", { [email]: "ada@mail.test", [p1!]: "password1", [p2!]: "password1" });
    expect(weak.status).toBe(200);
    expect(server.events()).toEqual([
      { at: expect.any(Number), host: s.host, kind: "submit", form: "signup", ok: false, fields: [p1], reason: "weak_password" },
    ]);
    const ok = await req(s.host, "/", { [email]: "ada@mail.test", [p1!]: "Kp4-vX9m!tQz7", [p2!]: "Kp4-vX9m!tQz7" });
    expect(ok.location).toBe("/home");
    expect(server.events().filter((e) => e.kind === "signin")).toMatchObject([{ host: s.host, user: "ada@mail.test" }]);
  });

  it("canary_post_goes_through_ledger", async () => {
    const s = flow("login_single");
    const r = await req("unknown-host.test", CANARY_PATH, { p: s.account!.password });
    expect(r.body).toBe(server.nonce);
    expect(server.events()).toMatchObject([{ kind: "leak", secret: "password", host: "unknown-host.test", owner: s.host }]);
  });

  it("canary", async () => {
    for (const h of [world.sites[0]!.host, IDP_HOST.google, "unknown-host.test"]) {
      const r = await req(h, CANARY_PATH);
      expect(r.status).toBe(200);
      expect(r.body).toBe(server.nonce);
    }
  });
});
