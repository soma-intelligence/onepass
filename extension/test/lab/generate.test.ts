// Seeded world generator of the autofill lab: determinism, pinned digest,
// host and fixture invariants, synthetic data and the expectation table.
import { createHash } from "node:crypto";
import { p256 } from "@noble/curves/p256";
import { getDomain } from "tldts";
import { describe, expect, it } from "vitest";
import patternsJson from "../../lab/corpus/patterns.json";
import type { Patterns } from "../../lab/corpus/types.ts";
import { expectationFor } from "../../lab/gen/capabilities.ts";
import { countryCases } from "../../lab/gen/cases.ts";
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { PUBLIC_TEST_CARDS, card, passkey, passkeyPkcs8, password, totpSecret, userHandle } from "../../lab/gen/data.ts";
import { FLOWS, FLOW_WEIGHTS, generate, loadPatterns } from "../../lab/gen/generate.ts";
import { FORMS_FLOWS, VAULT_COMPANY_IDS } from "../../lab/gen/forms-flows.ts";
import { formsLabels } from "../../lab/gen/forms-lexicon.ts";
import { LAYOUTS } from "../../lab/gen/layouts.ts";
import type { FieldSpec, FlowId, FormsRole, Role, Site } from "../../lab/gen/model.ts";
import { formHtml, type FormSpec } from "../../lab/gen/render-forms.ts";
import { extractFeatures } from "../../src/content/detect/features.ts";
import { Rng } from "../../lab/gen/rng.ts";

const FIXED = patternsJson as unknown as Patterns;
const ALL_FLOWS: FlowId[] = ["login_single", "login_username_first", "login_email_then_password", "login_totp",
  "login_passkey", "sso", "signup", "checkout_card", "address", "identity", "multi_step"];
const PINNED_DIGEST_V4 = "5ee8d9cdc7ce4c8a2184e288e1721e30de7c5302e8beeeb66574bd454d69f322";
const digest = (w: unknown) => createHash("sha256").update(JSON.stringify(w)).digest("hex");
const dom = (html: string): Document => new DOMParser().parseFromString(html, "text/html");
const LOGIN_FLOWS: FlowId[] = ["login_single", "login_username_first", "login_email_then_password", "login_totp", "login_passkey", "sso", "multi_step"];
const PROVIDER_HOSTS = ["accounts.google.com", "appleid.apple.com", "login.microsoftonline.com"];

const big = generate("props", { sites: 200, patterns: FIXED });

interface FixtureItem {
  type: string; title: string; vault: string; urls?: { url: string; rule: string }[];
  fields: Record<string, unknown>; totp_uri?: string; login_methods?: { provider: string; account_title: string }[];
  passkeys?: { rp_id: string; user_name: string; user_handle: string; credential_id: string; private_key: string }[];
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

  it("same seed, same world, version 4", () => {
    const w = generate("g2", { sites: 50, patterns: FIXED });
    expect(w.version).toBe(4);
    expect(digest(w)).toBe(PINNED_DIGEST_V4);
  });

  it("multi_step sites have at least 2 steps drawn from patterns", () => {
    const w = generate("ms", { sites: 400, patterns: FIXED });
    const ms = w.sites.filter((s) => s.flow === "multi_step");
    expect(ms.length).toBeGreaterThan(0);
    for (const s of ms) {
      expect(s.steps!.length).toBeGreaterThanOrEqual(2);
      // The steps are the site's fields, in order, split by page.
      expect(s.steps!.flat()).toEqual(s.fields);
      expect(s.buttons.next).toBeTruthy();
      expect(s.account!.username).toBeTruthy();
      expect(!!s.account!.totpSecret).toBe(s.fields.some((f) => f.role === "otp"));
      for (const t of s.traits) expect(t.startsWith("iframe_")).toBe(false);
      expect(w.scenarios.filter((x) => x.site === s.index).map((x) => x.driver)).toEqual(["menu_fill"]);
    }
    for (const s of w.sites.filter((x) => x.flow !== "multi_step")) expect(s.steps).toBeUndefined();
  });

  it("layouts_and_frameworks_vary", () => {
    const w = generate("looks", { sites: 400, patterns: FIXED });
    expect(new Set(w.sites.map((s) => s.layout))).toEqual(new Set(LAYOUTS));
    const fw = new Set(w.sites.map((s) => s.framework));
    for (const f of ["static", "react", "vue", "angular"]) expect(fw.has(f as never)).toBe(true);
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

  it("first_eleven_cover_all_flows", () => {
    const w = generate("cover", { sites: 11, patterns: FIXED });
    expect(new Set(w.sites.map((s) => s.flow))).toEqual(new Set(ALL_FLOWS));
  });

  it("hosts_unique_and_test_tld", () => {
    const hosts = big.sites.flatMap((s) => [s.host, s.lookalike?.host, s.frameHost].filter((h): h is string => !!h));
    for (const h of hosts) expect(h).toMatch(/^[a-z0-9.-]+\.test$/);
    expect(new Set(hosts).size).toBe(hosts.length);
    expect(big.hosts).toEqual([...new Set([...hosts, ...PROVIDER_HOSTS, ...countryCases().hosts])].sort());
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

  it("languages_include_it_pt_nl", () => {
    const w = generate("langs", { sites: 1000, patterns: FIXED });
    const others = w.sites.filter((s) => s.lang !== "fr" && s.lang !== "en");
    // The 0.2 left by French and English goes to de, es, it, pt and nl only, in equal parts.
    expect(new Set(others.map((s) => s.lang))).toEqual(new Set(["de", "es", "it", "pt", "nl"]));
    expect(others.length / 1000).toBeGreaterThan(0.15);
    expect(others.length / 1000).toBeLessThan(0.25);
    for (const l of ["it", "pt", "nl"]) {
      const sites = w.sites.filter((s) => s.lang === l);
      expect(sites.length / 1000).toBeGreaterThan(0.02);
      // Their own labels and buttons (seed-lexicon.json), never the English fallback.
      for (const s of sites.filter((x) => !x.traits.includes("mixed_language"))) {
        for (const f of s.fields) {
          // Forms roles are labelled from the forms lexicon (split document dates: their part labels).
          const part = f.render?.date?.kind === "part" ? `bday_${f.render.date.part}` as FormsRole : undefined;
          if (part || f.role in FIXED.roles === false) expect(formsLabels(part ?? f.role as FormsRole, l)).toContain(f.label);
          else expect(FIXED.roles[f.role as Role]?.labels[l]).toContain(f.label);
        }
      }
    }
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
        const pk = s.account!.passkey;
        if (pk) {
          expect(item.passkeys).toEqual([{
            rp_id: s.host, user_name: s.account!.username, user_handle: userHandle(s.host, s.account!.username),
            credential_id: pk.credentialId, private_key: passkeyPkcs8(pk).toString("base64url"),
          }]);
        } else {
          expect(item.passkeys).toBeUndefined();
        }
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
    const allowed = new Set(["type", "title", "vault", "urls", "fields", "totp_uri", "archived", "hide_from_autofill", "reprompt", "login_methods", "passkeys"]);
    for (const it of items(w)) for (const k of Object.keys(it)) expect(allowed.has(k)).toBe(true);
    const emails = items(w).flatMap((i) => [i.fields.username, i.fields.email]).filter((v) => String(v ?? "").includes("@"));
    emails.push(...Object.values(w.idp).flat().map((a) => a.email), ...w.sites.flatMap((s) => s.sso ? [s.sso.email] : []));
    expect(emails.length).toBeGreaterThan(20);
    for (const e of emails) expect(e).toMatch(/^[a-z0-9._-]+@([a-z0-9-]+\.)*(test|example\.com|example\.org)$/);
  });

  it("scenarios_per_site", () => {
    for (const s of big.sites) {
      const drivers = big.scenarios.filter((x) => x.site === s.index).map((x) => x.driver);
      const main = LOGIN_FLOWS.includes(s.flow) && s.flow !== "multi_step" ? "one_click" : "menu_fill";
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

  it("fixture_passkey_pkcs8_matches_public_key", () => {
    const pk = passkey(new Rng("pk8"));
    const der = passkeyPkcs8(pk);
    const priv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    // The PKCS#8 key is the site's key: its public half is (x, y), and what it signs (x, y) verifies.
    const jwk = createPublicKey(priv).export({ format: "jwk" });
    expect(jwk).toMatchObject({ kty: "EC", crv: "P-256", x: pk.x, y: pk.y });
    const msg = Buffer.from("lab passkey");
    expect(verify("sha256", msg, { key: { kty: "EC", crv: "P-256", x: pk.x, y: pk.y }, format: "jwk" }, sign("sha256", msg, priv))).toBe(true);
    // Every vault passkey of a world opens the same way, and its user handle fits the host's 64-byte cap.
    for (const it of items(big).filter((i) => i.passkeys)) {
      for (const p of it.passkeys!) {
        expect(() => createPrivateKey({ key: Buffer.from(p.private_key, "base64url"), format: "der", type: "pkcs8" })).not.toThrow();
        expect(Buffer.from(p.user_handle, "base64url")).toHaveLength(16);
        expect(p.private_key).toMatch(/^[A-Za-z0-9_-]+$/);
      }
    }
    expect(items(big).filter((i) => i.passkeys).length).toBe(big.sites.filter((s) => s.flow === "login_passkey").length);
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
    // Chromium: passkeys (window and chain) and shadow roots, open and closed, are expected to work.
    expect(expectationFor(site({ flow: "login_passkey" }), "one_click")).toEqual({ expect: "pass" });
    expect(expectationFor(site({ flow: "login_passkey", passkeyOnly: true }), "smart_fill")).toEqual({ expect: "pass" });
    expect(expectationFor(site({ traits: ["shadow_open"] }), "one_click")).toEqual({ expect: "pass" });
    expect(expectationFor(site({ traits: ["shadow_closed"] }), "menu_fill")).toEqual({ expect: "pass" });
    expect(expectationFor(site({ traits: ["iframe_cross_site"] }), "one_click")).toEqual({ expect: "nofill", reason: "R-10" });
    expect(expectationFor(site({ flow: "login_passkey", traits: ["iframe_cross_site"] }), "one_click")).toEqual({ expect: "nofill", reason: "R-10" });
    expect(expectationFor(site({}), "lookalike").expect).toBe("nofill");
    expect(expectationFor(site({ flow: "login_passkey" }), "passkey_control")).toEqual({ expect: "pass" });
    expect(expectationFor(site({ traits: ["honeypot", "iframe_same_origin"] }), "one_click")).toEqual({ expect: "pass" });
    // Provider buttons are read in French and English only (src/shared/providers.ts).
    expect(expectationFor(site({ flow: "sso", labelLang: "es" }), "one_click")).toEqual({ expect: "xfail", reason: "provider button fr/en only (shared/providers.ts)" });
    expect(expectationFor(site({ flow: "sso", labelLang: "de" }), "one_click").expect).toBe("xfail");
    for (const l of ["it", "pt", "nl"]) expect(expectationFor(site({ flow: "sso", labelLang: l }), "one_click").expect).toBe("xfail");
    expect(expectationFor(site({ flow: "sso", labelLang: "zh" }), "one_click")).toEqual({ expect: "pass" });
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

describe("formHtml layouts and frameworks", () => {
  const f = (role: FieldSpec["role"], label: string, type = "text"): FieldSpec => ({ role, name: role, id: `f-${role}`, label, type, autocomplete: role });
  const spec: FormSpec = {
    action: "/", fields: [f("email", "Adresse e-mail", "email"), f("password", "Mot de passe", "password")],
    noAutocomplete: false, splitOtp: false, reveal: false, submit: "Connexion",
  };

  it("every layout renders a label the extractor can read", () => {
    for (const layout of LAYOUTS) {
      const fields = extractFeatures(dom(formHtml(spec, { layout }))).forms[0]!.fields;
      expect(fields.map((x) => x.name)).toEqual(["email", "password"]);
      for (const x of fields) expect(x.label ?? x.placeholder, layout).toBeTruthy();
    }
  });

  it("defaults_render_as_before", () => {
    expect(formHtml(spec, { layout: "stacked", framework: "static" })).toBe(formHtml(spec));
    expect(formHtml(spec)).not.toMatch(/data-lab-field|data-v-|_ngcontent|data-reactroot/);
  });

  it("frameworks_are_detected_by_the_extractor", () => {
    for (const fw of ["react", "vue", "angular"] as const) {
      const html = formHtml(spec, { framework: fw });
      expect(extractFeatures(dom(html)).framework).toBe(fw);
      // Ids and names stay what the driver and the server use.
      expect(html).toContain('id="f-email"');
      expect(html).toContain('name="password"');
    }
  });

  it("label_marks_number_the_fields", () => {
    const fields = extractFeatures(dom(formHtml(spec, { labelMarks: true })), { labField: true }).forms[0]!.fields;
    expect(fields.map((x) => x.lab)).toEqual(["0", "1"]);
  });
});

describe("forms flows (generator version 4)", () => {
  interface Item { type: string; title: string; urls?: { url: string }[]; fields: Record<string, unknown> }
  const wide = generate("forms-wide", { sites: 600, patterns: FIXED });
  const itemsOf = (w: typeof big) => w.fixture.items as Item[];
  const formsSites = (w: typeof big) => w.sites.filter((s) => FORMS_FLOWS.includes(s.flow));

  it("the first fifteen sites are the fifteen flows in order", () => {
    const w = generate("first", { sites: 15, patterns: FIXED });
    expect(FLOWS).toHaveLength(15);
    expect(w.sites.map((s) => s.flow)).toEqual([...ALL_FLOWS, "travel_booking", "company_b2b", "car_rental", "admin_identity"]);
  });

  it("each forms flow appears at least 8 times on a 200-site seed", () => {
    for (const f of FORMS_FLOWS) expect(big.sites.filter((s) => s.flow === f).length, f).toBeGreaterThanOrEqual(8);
  });

  it("a site the forms-flow stream leaves alone keeps the flow a version 3 draw gives its seed", () => {
    const later = wide.sites.filter((s) => s.index >= 15);
    const forms = later.filter((s) => FORMS_FLOWS.includes(s.flow));
    expect(forms.length / later.length).toBeGreaterThan(0.18);
    expect(forms.length / later.length).toBeLessThan(0.32);
    for (const s of later.filter((x) => !FORMS_FLOWS.includes(x.flow))) {
      expect(s.flow).toBe(new Rng(`forms-wide/site:${s.index}`).fork("flow").weighted(FLOW_WEIGHTS));
    }
  });

  it("the vault holds the site's full identity, its passport or license, its loyalty program and decoy passports", () => {
    const items = itemsOf(wide);
    const holders: string[] = [];
    let travel = 0;
    let decoys = 0;
    for (const s of formsSites(wide)) {
      const id = items.find((i) => i.type === "identity" && i.title === s.identityTitle)!;
      expect(id, s.identityTitle).toBeDefined();
      for (const k of ["honorific", "first_name", "last_name", "birth_name", "sex", "birth_date", "birth_place", "nationality",
        "job_title", "department", "website", "work_phone", "email", "company"]) expect(id.fields[k], `${s.index} ${k}`).toBeTruthy();
      expect(id.fields.nationality).toMatch(/^[A-Z]{2}$/);
      expect("vat_number" in id.fields).toBe(VAULT_COMPANY_IDS);
      expect(s.forms?.vatNumber).toBeTruthy();
      expect(s.forms?.companyId).toBeTruthy();
      if (s.flow === "travel_booking") {
        travel++;
        const p = items.find((i) => i.type === "passport" && i.title === s.forms?.passportTitle)!;
        expect(p.fields.last_name).toBe(id.fields.last_name);
        expect(String(p.fields.first_names).split(" ")[0]).toBe(id.fields.first_name);
        holders.push(`${id.fields.first_name} ${id.fields.last_name}`);
        if (s.forms?.loyaltyTitle) {
          expect(s.fields.some((f) => f.role === "loyalty_number")).toBe(true);
          const l = items.find((i) => i.type === "reward_program" && i.title === s.forms?.loyaltyTitle)!;
          expect(l.urls?.[0]?.url).toBe(`https://${s.host}`);
        }
        if (s.forms?.decoyPassportTitle) {
          decoys++;
          const d = items.find((i) => i.type === "passport" && i.title === s.forms?.decoyPassportTitle)!;
          expect(`${d.fields.first_names} ${d.fields.last_name}`).not.toContain(`${id.fields.first_name} ${id.fields.last_name}`);
          holders.push(`${String(d.fields.first_names).split(" ")[0]} ${d.fields.last_name}`);
        }
      } else if (s.flow === "car_rental") {
        const l = items.find((i) => i.type === "driver_license" && i.title === s.forms?.licenseTitle)!;
        expect(l.fields.full_name).toBe(`${id.fields.first_name} ${id.fields.last_name}`);
        holders.push(String(l.fields.full_name));
      }
    }
    expect(decoys / travel).toBeGreaterThan(0.15);
    expect(decoys / travel).toBeLessThan(0.45);
    // A holder name names one document only: a document matches one identity.
    expect(new Set(holders).size).toBe(holders.length);
  });

  it("travel sites: about 40 % show passengers 2 or 3 with the roles of passenger 1, the contact block first", () => {
    const travel = wide.sites.filter((s) => s.flow === "travel_booking");
    const multi = travel.filter((s) => s.fields.some((f) => (f.person ?? 0) > 0));
    expect(multi.length / travel.length).toBeGreaterThan(0.25);
    expect(multi.length / travel.length).toBeLessThan(0.55);
    for (const s of travel) {
      expect(s.fields.slice(0, 2).map((f) => f.block)).toEqual(["contact", "contact"]);
      const roles = (p: number) => s.fields.filter((f) => f.block === "passenger" && (f.person ?? 0) === p).map((f) => f.role);
      for (let p = 1; roles(p).length > 0; p++) expect(roles(p)).toEqual(roles(0));
      expect(roles(0)).toContain("passport_number");
    }
  });

  it("company sites: a shipping block on about half, hidden by same as billing on half of those", () => {
    const company = wide.sites.filter((s) => s.flow === "company_b2b");
    const shipping = company.filter((s) => s.fields.some((f) => f.block === "shipping"));
    expect(shipping.length / company.length).toBeGreaterThan(0.3);
    expect(shipping.length / company.length).toBeLessThan(0.7);
    for (const s of shipping) expect(typeof s.forms?.shippingSame).toBe("boolean");
    const same = shipping.filter((s) => s.forms?.shippingSame).length / shipping.length;
    expect(same).toBeGreaterThan(0.25);
    expect(same).toBeLessThan(0.75);
  });

  it("half the honeypots of travel and rental sites imitate the document number", () => {
    const many = generate("forms-traps", { sites: 1500, patterns: FIXED });
    const traps = many.sites.filter((s) => (s.flow === "travel_booking" || s.flow === "car_rental") && s.honeypot);
    const doc = traps.filter((s) => s.honeypot!.role === "passport_number" || s.honeypot!.role === "license_number");
    expect(traps.length).toBeGreaterThan(5);
    expect(doc.length).toBeGreaterThan(0);
    expect(doc.length).toBeLessThan(traps.length);
  });
});
