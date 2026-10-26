// @vitest-environment node
// Leak ledger of the lab server: fictional secrets indexed to their owner
// host, leaks to another host or into a trap field (honeypot, decoy form),
// TOTP codes of the current periods, cross-site frame hosts,
// card number normalization, CVC only in card fields, and events that never
// carry a value.
import { describe, expect, it } from "vitest";
import { totp } from "../../e2e/server.ts";
import patternsJson from "../../lab/corpus/patterns.json";
import type { Patterns } from "../../lab/corpus/types.ts";
import { generate } from "../../lab/gen/generate.ts";
import { IDP_HOST } from "../../lab/gen/render.ts";
import { Ledger } from "../../lab/server/ledger.ts";

const world = generate("ledger-test", { sites: 80, patterns: patternsJson as unknown as Patterns });
const login = world.sites.find((s) => s.flow === "login_single" && s.lookalike)
  ?? world.sites.find((s) => s.lookalike)!;
const pw = login.account!.password;
const pwField = login.fields.find((f) => f.role === "password")!.name;
const checkout = world.sites.find((s) => s.flow === "checkout_card")!;
const cardItem = world.fixture.items.find((i) => (i as { title: string }).title === checkout.cardTitle) as
  { fields: { number: string; cvv: string } };

describe("Ledger", () => {
  it("password_to_owner_ok", () => {
    const l = new Ledger(world);
    expect(l.record(login.host, "/", { [pwField]: pw })).toEqual([]);
    const google = world.idp.google[0]!;
    expect(l.record(IDP_HOST.google, "/signin/identifier", { email: google.email, password: google.password })).toEqual([]);
    expect(l.events).toEqual([]);
  });
  it("password_to_lookalike_is_leak", () => {
    const l = new Ledger(world);
    const leaks = l.record(login.lookalike!.host, "/", { [pwField]: pw });
    expect(leaks).toEqual([{ at: expect.any(Number), host: login.lookalike!.host, kind: "leak", secret: "password", field: pwField, owner: login.host }]);
    expect(l.events).toEqual(leaks);
    // An IdP password posted to a site is a leak too.
    const apple = world.idp.apple[0]!;
    expect(l.record(login.host, "/", { pw: apple.password })[0]).toMatchObject({ owner: IDP_HOST.apple, secret: "password" });
  });
  it("honeypot_field_is_leak", () => {
    const l = new Ledger(world);
    const site = world.sites.find((s) => s.honeypot && s.account?.password)!;
    expect(site, "an 80-site world has a honeypot on a login site").toBeDefined();
    const leaks = l.record(site.host, "/", { [site.honeypot!.name]: site.account!.password });
    expect(leaks).toMatchObject([{ kind: "leak", secret: "password", field: site.honeypot!.name, owner: site.host }]);
    // Any field posted to the decoy form is a trap field.
    expect(l.record(site.host, "/decoy", { whatever: site.account!.password })).toHaveLength(1);
    // Empty values and non-secrets are not leaks.
    expect(l.record(site.host, "/", { [site.honeypot!.name]: "" })).toEqual([]);
  });
  it("card_spaces_normalized", () => {
    const l = new Ledger(world);
    const digits = cardItem.fields.number.replace(/\s/g, "");
    const num = checkout.fields.find((f) => f.role === "cc_number")!.name;
    const csc = checkout.fields.find((f) => f.role === "cc_csc")!.name;
    expect(l.record(checkout.host, "/", { [num]: digits, [csc]: cardItem.fields.cvv })).toEqual([]);
    const leaks = l.record("other-host-1.test", "/", { n: cardItem.fields.number, n2: digits.replace(/(\d{4})/g, "$1-") });
    expect(leaks.map((e) => e.kind === "leak" && e.secret)).toEqual(["card", "card"]);
    // A CVC outside a card field of the receiving site is not counted (short numbers are common).
    expect(l.record("other-host-1.test", "/", { code: cardItem.fields.cvv })).toEqual([]);
  });
  it("signup_password_becomes_secret_and_reset_clears", () => {
    const l = new Ledger(world);
    const signup = world.sites.find((s) => s.flow === "signup")!;
    l.addSecret("Fresh-Signup-Pass-123", "password", signup.host);
    expect(l.record(login.host, "/", { p: "Fresh-Signup-Pass-123" })).toHaveLength(1);
    expect(l.record(login.host, "/", { p: "" })).toEqual([]);
    l.reset();
    expect(l.events).toEqual([]);
    expect(l.record(login.host, "/", { p: "Fresh-Signup-Pass-123" })).toEqual([]);
  });
  it("short_signup_secret_matches_whole_values_only", () => {
    const l = new Ledger(world);
    const signup = world.sites.find((s) => s.flow === "signup")!;
    l.addSecret("ab12", "password", signup.host);
    expect(l.record(login.host, "/", { note: "xab12y" })).toEqual([]);
    expect(l.record(login.host, "/", { p: "ab12" })).toHaveLength(1);
  });
  it("totp_codes_to_other_host_or_trap_are_leaks", () => {
    const l = new Ledger(world);
    const site = world.sites.find((s) => s.account?.totpSecret)!;
    expect(site, "an 80-site world has a TOTP site").toBeDefined();
    const otp = site.fields.find((f) => f.role === "otp")!.name;
    const now = totp(site.account!.totpSecret!);
    const next = totp(site.account!.totpSecret!, Date.now() + 30_000);
    // To its owner: fine.
    expect(l.record(site.host, "/otp", { [otp]: now })).toEqual([]);
    // To another host, current or next period: leaks (spaces ignored).
    expect(l.record(login.host, "/", { code: now })).toMatchObject([{ kind: "leak", secret: "totp", field: "code", owner: site.host }]);
    expect(l.record(login.host, "/", { code: `${next.slice(0, 3)} ${next.slice(3)}` })).toMatchObject([{ secret: "totp" }]);
    // Only whole values: a code inside a longer value is not counted.
    expect(l.record(login.host, "/", { note: `ref ${now} x` })).toEqual([]);
    // Into the owner's decoy form: a trap.
    expect(l.record(site.host, "/decoy", { [otp]: now })).toMatchObject([{ secret: "totp", owner: site.host }]);
  });
  it("csc_into_honeypot_is_leak", () => {
    // The honeypot imitates the CVC field: its role makes the CVC recognizable there.
    const w = JSON.parse(JSON.stringify(world)) as typeof world;
    const site = w.sites.find((s) => s.host === checkout.host)!;
    site.honeypot = { role: "cc_csc", name: "hp_csc", style: "display_none" };
    const l = new Ledger(w);
    expect(l.record(site.host, "/", { hp_csc: cardItem.fields.cvv })).toMatchObject([{ kind: "leak", secret: "csc", field: "hp_csc", owner: site.host }]);
  });
  it("frame_host_of_cross_site_frame_gets_a_leak", () => {
    const framed = world.sites.find((s) => s.traits.includes("iframe_cross_site") && s.account?.password)!;
    expect(framed, "an 80-site world has a cross-site frame on a login site").toBeDefined();
    const l = new Ledger(world);
    const pwName = framed.fields.find((f) => f.role === "password")!.name;
    // The site's password posted to its cross-site auth widget leaves the site (spec R-10).
    expect(l.record(framed.frameHost!, "/frame", { [pwName]: framed.account!.password }))
      .toMatchObject([{ kind: "leak", secret: "password", field: pwName, host: framed.frameHost, owner: framed.host }]);
  });
  it("no_values_in_events", () => {
    const l = new Ledger(world);
    l.record(login.lookalike!.host, "/", { [pwField]: pw, user: login.account!.username });
    l.record("other-host-1.test", "/", { n: cardItem.fields.number });
    l.note({ at: 1, host: login.host, kind: "submit", form: "login_single", ok: false, fields: [pwField], reason: "wrong_password" });
    const dump = JSON.stringify(l.events);
    expect(l.events).toHaveLength(3);
    for (const secret of [pw, cardItem.fields.number, cardItem.fields.number.replace(/\s/g, "")]) expect(dump).not.toContain(secret);
  });
});
