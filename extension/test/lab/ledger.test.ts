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
import { archiveHostOf, DEFAULT_PROFILE, fixtureFor } from "../../lab/gen/population.ts";
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

  it("a domain-wide login saved for another host of the site's domain is the site's own secret, a lookalike's never", () => {
    const fixture = { ...world.fixture, items: [...world.fixture.items, { type: "login", title: "Second", vault: "Lab", urls: [{ url: `https://www.${login.host}`, rule: "domain" }], fields: { username: "second", password: "Second-Pass-42x" } }] };
    const l = new Ledger(world, [fixture]);
    expect(l.record(login.host, "/", { [pwField]: "Second-Pass-42x" })).toEqual([]);
    expect(l.record(login.lookalike!.host, "/", { [pwField]: "Second-Pass-42x" })).toMatchObject([{ kind: "leak", secret: "password" }]);
    // An exact-host item stays its own host's alone.
    const exact = { ...world.fixture, items: [...world.fixture.items, { type: "login", title: "Third", vault: "Lab", urls: [{ url: `https://www.${login.host}`, rule: "exact_host" }], fields: { username: "third", password: "Third-Pass-42xyz" } }] };
    expect(new Ledger(world, [exact]).record(login.host, "/", { [pwField]: "Third-Pass-42xyz" })).toMatchObject([{ kind: "leak" }]);
  });

  describe("population vaults", () => {
    const filled = fixtureFor({ ...DEFAULT_PROFILE, id: "p7", vaultSize: 500, multiAccount: true, duplicates: 2 }, world.sites, world.fixture);
    const others = fixtureFor({ ...DEFAULT_PROFILE, id: "p8", vaultSize: 300 }, world.sites, world.fixture);
    type Item = { type: string; title: string; fields: { number?: string; cvv?: string; password?: string }; urls?: { url: string }[] };
    const fillerCard = (filled.items as Item[]).find((i) => i.type === "credit_card" && archiveHostOf(i.title))!;
    const plain = world.sites.find((s) => !s.cardTitle && !s.lookalike)!;

    it("filler_card_posted_to_a_world_site_is_a_leak", () => {
      const l = new Ledger(world, [filled]);
      const owner = archiveHostOf(fillerCard.title)!;
      expect(owner).toMatch(/-archive\.test$/);
      expect(l.record(plain.host, "/", { n: fillerCard.fields.number! })[0]).toMatchObject({ kind: "leak", secret: "card" });
      expect(l.record(owner, "/", { n: fillerCard.fields.number! })).toEqual([]);
    });

    it("world_cards_stay_indexed_whatever_the_vault", () => {
      const l = new Ledger(world, [{ ...world.fixture, items: [] }]);
      expect(l.record(plain.host, "/", { n: cardItem.fields.number })[0]).toMatchObject({ kind: "leak", secret: "card" });
    });

    it("every_profile_secret_counts_whatever_the_active_vault", () => {
      // Profile A's second account and filler login are secrets even when profile B is the one playing.
      const l = new Ledger(world, [filled, others]);
      const logins = (filled.items as Item[]).filter((i) => i.type === "login" && i.urls?.[0]);
      const second = logins.find((i) => i.title.endsWith(" (2)"))!;
      const filler = logins.find((i) => archiveHostOf(i.title))!;
      expect(l.record("unknown-host.test", "/", { p: second.fields.password! })[0]).toMatchObject({ kind: "leak", owner: new URL(second.urls![0]!.url).hostname });
      expect(l.record("unknown-host.test", "/", { p: filler.fields.password! })[0]).toMatchObject({ kind: "leak", owner: archiveHostOf(filler.title) });
    });
  });
});

describe("Ledger documents (generator version 4)", () => {
  const fw = generate("ledger-forms", { sites: 400, patterns: patternsJson as unknown as Patterns });
  interface Item { type: string; title: string; fields: Record<string, string> }
  const items = fw.fixture.items as Item[];
  const doc = (title: string | undefined) => items.find((i) => i.title === title)!.fields;
  const travel = fw.sites.find((s) => s.flow === "travel_booking" && s.fields.some((f) => f.role === "passport_number"))!;
  const withDecoy = fw.sites.find((s) => s.flow === "travel_booking" && s.forms?.decoyPassportTitle)!;
  const rental = fw.sites.find((s) => s.flow === "car_rental" && s.fields.some((f) => f.role === "license_number"))!;
  const loyal = fw.sites.find((s) => s.forms?.loyaltyTitle && s.fields.some((f) => f.role === "loyalty_number"))!;
  const other = fw.sites.find((s) => s.flow === "address")!;
  const numberField = travel.fields.find((f) => f.role === "passport_number")!.name;
  const passport = doc(travel.forms!.passportTitle).number!;

  it("a passport number on its own site is no leak, even spaced", () => {
    const l = new Ledger(fw);
    expect(l.record(travel.host, "/", { [numberField]: passport })).toEqual([]);
    expect(l.record(travel.host, "/", { [numberField]: passport.split("").join(" ") })).toEqual([]);
  });

  it("a passport, license or loyalty number posted to another host is a document leak", () => {
    const l = new Ledger(fw);
    const ev = l.record(other.host, "/", { any: passport.toLowerCase() });
    expect(ev).toEqual([expect.objectContaining({ kind: "leak", secret: "document", field: "any", owner: travel.host })]);
    expect(l.record(other.host, "/", { x: doc(rental.forms!.licenseTitle).number! })[0]).toMatchObject({ secret: "document", owner: rental.host });
    expect(l.record(other.host, "/", { y: doc(loyal.forms!.loyaltyTitle).member_number! })[0]).toMatchObject({ secret: "document", owner: loyal.host });
    expect(JSON.stringify(l.events)).not.toContain(passport);
  });

  it("a passport number in the site's honeypot is a leak", () => {
    const hp = fw.sites.find((s) => s.flow === "travel_booking" && s.honeypot !== undefined)!;
    const l = new Ledger(fw);
    const own = doc(hp.forms!.passportTitle).number!;
    expect(l.record(hp.host, "/", { [hp.honeypot!.name]: own })[0]).toMatchObject({ secret: "document", owner: hp.host });
  });

  it("the decoy passport is a leak wherever it goes, its site included", () => {
    const l = new Ledger(fw);
    const n = doc(withDecoy.forms!.decoyPassportTitle).number!;
    const f = withDecoy.fields.find((x) => x.role === "passport_number")?.name ?? "p";
    expect(l.record(withDecoy.host, "/", { [f]: n })[0]).toMatchObject({ secret: "document", owner: `decoy:${withDecoy.host}` });
  });
});
