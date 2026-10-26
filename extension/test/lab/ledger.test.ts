// @vitest-environment node
// Leak ledger of the lab server: fictional secrets indexed to their owner
// host, leaks to another host or into a trap field (honeypot, decoy form),
// card number normalization, CVC only in card fields, and events that never
// carry a value.
import { describe, expect, it } from "vitest";
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
