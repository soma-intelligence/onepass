// Seeded world generator of the autofill lab: determinism, pinned digest,
// host and fixture invariants, synthetic data and the expectation table.
import { createHash } from "node:crypto";
import { p256 } from "@noble/curves/p256";
import { getDomain } from "tldts";
import { describe, expect, it } from "vitest";
import patternsJson from "../../lab/corpus/patterns.json";
import type { Patterns } from "../../lab/corpus/types.ts";
import { expectationFor } from "../../lab/gen/capabilities.ts";
import { PUBLIC_TEST_CARDS, card, passkey, password, totpSecret } from "../../lab/gen/data.ts";
import { generate, loadPatterns } from "../../lab/gen/generate.ts";
import type { FlowId, Site } from "../../lab/gen/model.ts";
import { Rng } from "../../lab/gen/rng.ts";

const FIXED = patternsJson as unknown as Patterns;
const ALL_FLOWS: FlowId[] = ["login_single", "login_username_first", "login_email_then_password", "login_totp",
  "login_passkey", "sso", "signup", "checkout_card", "address", "identity"];
const LOGIN_FLOWS: FlowId[] = ["login_single", "login_username_first", "login_email_then_password", "login_totp", "login_passkey", "sso"];
const PROVIDER_HOSTS = ["accounts.google.com", "appleid.apple.com", "login.microsoftonline.com"];

const big = generate("props", { sites: 200, patterns: FIXED });

interface FixtureItem {
  type: string; title: string; vault: string; urls?: { url: string; rule: string }[];
  fields: Record<string, unknown>; totp_uri?: string; login_methods?: { provider: string; account_title: string }[];
}
const items = (w: typeof big) => w.fixture.items as FixtureItem[];

function site(over: Partial<Site>): Site {
  return {
    index: 0, seed: "s", host: "a-b-1.test", brand: "A B", lang: "en", labelLang: "en", flow: "login_single",
    traits: [], fields: [], buttons: { submit: "Sign in" }, ...over,
  };
}

describe("generate", () => {
  it("deterministic", () => {
    const a = generate("x", { sites: 40, patterns: FIXED });
    const b = generate("x", { sites: 40, patterns: FIXED });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(JSON.stringify(generate("y", { sites: 40, patterns: FIXED }))).not.toBe(JSON.stringify(a));
  });

  it("pinned_digest", () => {
    const w = generate("lab-smoke-1", { sites: 12, patterns: FIXED });
    const digest = createHash("sha256").update(JSON.stringify(w)).digest("hex");
    expect(digest).toBe("c6b5ee185b34e62143b190973f50bf81477314f616000f5b0b15974785ebb449");
  });

  it("sso_with_and_without_password_form", () => {
    const w = generate("sso-variants", { sites: 300, patterns: FIXED });
    const sso = w.sites.filter((s) => s.flow === "sso");
    const withForm = sso.filter((s) => s.fields.length > 0);
    // Both variants occur, roughly half and half.
    expect(withForm.length).toBeGreaterThan(sso.length * 0.25);
    expect(withForm.length).toBeLessThan(sso.length * 0.75);
    for (const s of sso) {
      expect(s.account).toBeUndefined();
      expect(s.itemTitle).toMatch(new RegExp(`^${s.brand} via (Google|Apple|Microsoft)$`));
      if (s.fields.length > 0) expect(s.fields.map((f) => f.role)).toEqual(["username", "password"]);
      const item = (w.fixture.items as { urls?: { url: string }[]; fields: Record<string, string>; login_methods?: unknown[] }[])
        .find((i) => i.urls?.[0]?.url === `https://${s.host}`)!;
      // The vault item stays provider-only: no password, one login method.
      expect(item.fields.password).toBeUndefined();
      expect(item.login_methods).toHaveLength(1);
    }
  });

  it("load_patterns_reads_committed_file", () => {
    expect(loadPatterns()).toEqual(FIXED);
  });

  it("first_ten_cover_all_flows", () => {
    const w = generate("cover", { sites: 10, patterns: FIXED });
    expect(new Set(w.sites.map((s) => s.flow))).toEqual(new Set(ALL_FLOWS));
  });

  it("hosts_unique_and_test_tld", () => {
    const hosts = big.sites.flatMap((s) => [s.host, s.lookalike?.host, s.frameHost].filter((h): h is string => !!h));
    for (const h of hosts) expect(h).toMatch(/^[a-z0-9.-]+\.test$/);
    expect(new Set(hosts).size).toBe(hosts.length);
    expect(big.hosts).toEqual([...new Set([...hosts, ...PROVIDER_HOSTS])].sort());
    expect(big.sites.some((s) => s.lookalike) && big.sites.some((s) => s.frameHost)).toBe(true);
  });

  it("lookalike_never_same_registrable_domain", () => {
    const withLookalike = big.sites.filter((s) => s.lookalike);
    expect(withLookalike.length).toBeGreaterThan(0);
    for (const s of withLookalike) {
      expect(getDomain(s.lookalike!.host)).not.toBe(getDomain(s.host));
      expect(["login_single", "login_username_first", "login_email_then_password", "login_totp"]).toContain(s.flow);
    }
  });

  it("cross_site_frame_differs", () => {
    for (const s of big.sites) {
      expect(!!s.frameHost).toBe(s.traits.includes("iframe_cross_site"));
      if (s.frameHost) expect(getDomain(s.frameHost)).not.toBe(getDomain(s.host));
    }
  });

  it("traits_compatible", () => {
    for (const s of big.sites) {
      expect(s.traits.length).toBeLessThanOrEqual(3);
      expect(s.traits.filter((t) => /^(iframe|shadow)_/.test(t)).length).toBeLessThanOrEqual(1);
      if (s.traits.includes("split_otp")) expect(s.flow).toBe("login_totp");
      if (s.traits.includes("honeypot")) expect(s.fields.map((f) => f.role)).toContain(s.honeypot!.role);
      expect(s.labelLang !== s.lang).toBe(s.traits.includes("mixed_language"));
      if (s.traits.includes("no_autocomplete")) for (const f of s.fields) expect(f.autocomplete).toBeUndefined();
      expect(s.lang).not.toBe("und");
      expect(!!s.totpCells).toBe(s.traits.includes("split_otp"));
      if (s.flow === "sso" || s.passkeyOnly) for (const t of s.traits) expect(t).toBe("mixed_language");
    }
  });

  it("trait_rates_measurable", () => {
    const w = generate("rates", { sites: 2000, patterns: FIXED });
    const rate = (flows: FlowId[], t: string) => {
      const xs = w.sites.filter((s) => flows.includes(s.flow));
      return xs.filter((s) => s.traits.includes(t as never)).length / xs.length;
    };
    const split = rate(["login_totp"], "split_otp");
    expect(split).toBeGreaterThan(0.25);
    expect(split).toBeLessThan(0.45);
    const decoy = rate(["login_single", "login_username_first", "login_email_then_password", "login_totp"], "decoy_form");
    expect(decoy).toBeGreaterThan(0.07);
    expect(decoy).toBeLessThan(0.12);
  });

  it("languages_fr_en_majority", () => {
    const w = generate("langs", { sites: 400, patterns: FIXED });
    for (const l of ["fr", "en"]) {
      const share = w.sites.filter((s) => s.lang === l).length / 400;
      expect(share).toBeGreaterThanOrEqual(0.3);
      expect(share).toBeLessThanOrEqual(0.5);
    }
    expect(w.sites.some((s) => s.lang === "de" || s.lang === "es")).toBe(true);
  });

  it("fixture_has_item_per_login_site", () => {
    const w = big;
    const vaults = new Set(w.fixture.vaults.map((v) => v.name));
    for (const it of items(w)) expect(vaults.has(it.vault)).toBe(true);
    expect(w.fixture._comment).toContain("Fictional data generated by the OnePass autofill lab");
    expect(w.fixture.account).toBe("lab@onepass.test");
    for (const s of w.sites.filter((x) => LOGIN_FLOWS.includes(x.flow))) {
      const own = items(w).filter((i) => i.type === "login" && i.urls?.[0]?.url === `https://${s.host}`);
      expect(own).toHaveLength(1);
      const item = own[0]!;
      expect(item.title).toBe(s.brand);
      expect(item.urls![0]!.rule).toBe("domain");
      if (s.flow === "sso") {
        const provider = s.sso!.provider;
        const acct = w.idp[provider].find((a) => a.email === s.sso!.email)!;
        expect(item.fields.username).toBe(acct.email);
        expect(item.login_methods).toEqual([{ provider, account_title: acct.itemTitle }]);
        expect(s.itemTitle).toMatch(new RegExp(`^${s.brand} via (Google|Apple|Microsoft)$`));
      } else {
        expect(item.fields).toEqual({ username: s.account!.username, password: s.account!.password });
        expect(s.itemTitle).toBe(s.brand);
      }
      if (s.flow === "login_totp") {
        expect(item.totp_uri).toBe(`otpauth://totp/${encodeURIComponent(s.brand)}:${encodeURIComponent(s.account!.username)}`
          + `?secret=${s.account!.totpSecret}&issuer=${encodeURIComponent(s.brand)}`);
      }
    }
    for (const [provider, host] of [["google", "accounts.google.com"], ["apple", "appleid.apple.com"], ["microsoft", "login.microsoftonline.com"]] as const) {
      expect(w.idp[provider].length).toBeGreaterThanOrEqual(2);
      expect(w.idp[provider].length).toBeLessThanOrEqual(3);
      for (const a of w.idp[provider]) {
        const it = items(w).find((i) => i.title === a.itemTitle)!;
        expect(it.urls).toEqual([{ url: `https://${host}`, rule: "exact_host" }]);
        expect(it.fields).toEqual({ username: a.email, password: a.password });
      }
    }
    for (const s of w.sites.filter((x) => x.flow === "checkout_card")) {
      expect(s.cardTitle).toBe(`Carte ${s.brand}`);
      expect(items(w).filter((i) => i.type === "credit_card" && i.title === s.cardTitle)).toHaveLength(1);
    }
    for (const s of w.sites.filter((x) => x.flow === "address" || x.flow === "identity")) {
      const it = items(w).find((i) => i.type === "identity" && i.title === s.identityTitle)!;
      expect(s.identityTitle).toBe(`${it.fields.first_name} ${it.fields.last_name} (${s.brand})`);
    }
    const allowed = new Set(["type", "title", "vault", "urls", "fields", "totp_uri", "archived", "hide_from_autofill", "reprompt", "login_methods"]);
    for (const it of items(w)) for (const k of Object.keys(it)) expect(allowed.has(k)).toBe(true);
    const emails = items(w).flatMap((i) => [i.fields.username, i.fields.email]).filter((v) => String(v ?? "").includes("@"));
    emails.push(...Object.values(w.idp).flat().map((a) => a.email), ...w.sites.flatMap((s) => s.sso ? [s.sso.email] : []));
    expect(emails.length).toBeGreaterThan(20);
    for (const e of emails) expect(e).toMatch(/^[a-z0-9._-]+@([a-z0-9-]+\.)*(test|example\.com|example\.org)$/);
  });

  it("scenarios_per_site", () => {
    for (const s of big.sites) {
      const drivers = big.scenarios.filter((x) => x.site === s.index).map((x) => x.driver);
      const main = LOGIN_FLOWS.includes(s.flow) ? "one_click" : "menu_fill";
      // The control needs a passkey step on the site's own host: a cross-site widget has none.
      const control = s.flow === "login_passkey" && (s.passkeyOnly === true || !s.traits.includes("iframe_cross_site"));
      const want = [main, ...(s.lookalike ? ["lookalike"] : []), ...(control ? ["passkey_control"] : [])];
      expect(drivers).toEqual(want);
    }
  });

  it("no_passkey_control_behind_cross_site_password_widget", () => {
    // lab-2026-10-26 site 88: password in a cross-site frame, then a passkey the frame host cannot ask for.
    const w = generate("lab-2026-10-26", { sites: 89, patterns: loadPatterns() });
    const s = w.sites[88]!;
    expect(s.flow).toBe("login_passkey");
    expect(s.passkeyOnly).toBe(false);
    expect(s.traits).toContain("iframe_cross_site");
    expect(w.scenarios.filter((x) => x.site === 88).map((x) => x.driver)).toEqual(["one_click"]);
  });

  it("passkey_public_matches_private", () => {
    const pk = passkey(new Rng("pk"));
    const pub = p256.getPublicKey(new Uint8Array(Buffer.from(pk.d, "hex")), false);
    expect(Buffer.from(pub.slice(1, 33)).toString("base64url")).toBe(pk.x);
    expect(Buffer.from(pub.slice(33)).toString("base64url")).toBe(pk.y);
    expect(Buffer.from(pk.credentialId, "base64url")).toHaveLength(16);
    for (const s of big.sites.filter((x) => x.flow === "login_passkey")) expect(s.account!.passkey).toBeDefined();
  });

  it("cards_are_public_test_numbers", () => {
    const r = new Rng("cards");
    for (let i = 0; i < 50; i++) {
      const c = card(r);
      expect(PUBLIC_TEST_CARDS).toContain(c.number);
      expect(c.expYear).toBeGreaterThanOrEqual(2028);
      expect(c.expYear).toBeLessThanOrEqual(2033);
      expect(c.cvc).toMatch(c.number.startsWith("3") ? /^\d{4}$/ : /^\d{3}$/);
    }
    for (const it of items(big).filter((i) => i.type === "credit_card")) {
      expect(PUBLIC_TEST_CARDS).toContain(String(it.fields.number).replace(/ /g, ""));
      expect(String(it.fields.expiry)).toMatch(/^(0[1-9]|1[0-2])\/20(2[89]|3[0-3])$/);
    }
  });

  it("password_and_totp_shape", () => {
    const r = new Rng("pw");
    for (let i = 0; i < 50; i++) {
      const p = password(r);
      expect(p.length).toBeGreaterThanOrEqual(16);
      expect(p.length).toBeLessThanOrEqual(24);
      expect(p).toMatch(/[a-z]/); expect(p).toMatch(/[A-Z]/); expect(p).toMatch(/[0-9]/); expect(p).toMatch(/[^A-Za-z0-9]/);
      expect(totpSecret(r)).toMatch(/^[A-Z2-7]{32}$/);
    }
  });

  it("expectations_table", () => {
    expect(expectationFor(site({ flow: "login_passkey" }), "one_click")).toEqual({ expect: "xfail", reason: "R-16 passkeys" });
    expect(expectationFor(site({ traits: ["shadow_open"] }), "one_click")).toEqual({ expect: "xfail", reason: "shadow DOM (content/index.ts)" });
    expect(expectationFor(site({ traits: ["shadow_closed"] }), "menu_fill")).toEqual({ expect: "xfail", reason: "shadow DOM (content/index.ts)" });
    expect(expectationFor(site({ traits: ["iframe_cross_site"] }), "one_click")).toEqual({ expect: "nofill", reason: "R-10" });
    expect(expectationFor(site({ flow: "login_passkey", traits: ["iframe_cross_site"] }), "one_click")).toEqual({ expect: "nofill", reason: "R-10" });
    expect(expectationFor(site({}), "lookalike").expect).toBe("nofill");
    expect(expectationFor(site({ flow: "login_passkey" }), "passkey_control")).toEqual({ expect: "pass" });
    expect(expectationFor(site({ traits: ["honeypot", "iframe_same_origin"] }), "one_click")).toEqual({ expect: "pass" });
  });

  it("no_secret_in_scenarios", () => {
    const text = JSON.stringify(big.scenarios);
    const secrets: string[] = [];
    for (const s of big.sites) {
      if (s.account?.password) secrets.push(s.account.password);
      if (s.account?.totpSecret) secrets.push(s.account.totpSecret);
      if (s.account?.passkey) secrets.push(s.account.passkey.d);
    }
    for (const a of Object.values(big.idp).flat()) secrets.push(a.password);
    for (const it of items(big).filter((i) => i.type === "credit_card")) secrets.push(String(it.fields.number).replace(/ /g, ""), String(it.fields.number));
    expect(secrets.length).toBeGreaterThan(20);
    for (const s of secrets) expect(text).not.toContain(s);
  });
});
