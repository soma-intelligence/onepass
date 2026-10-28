// @vitest-environment node
// Simulated user population of the autofill lab (plan task 8): seeded
// profiles (vault size, duplicates, several accounts, country formats,
// behaviour), the vault each one gets, and what the oracle judges under a
// behaviour. The default profile is the lab's historical single user.
import { describe, expect, it } from "vitest";
import patternsJson from "../../lab/corpus/patterns.json";
import type { Patterns } from "../../lab/corpus/types.ts";
import { addressFor, phoneFor, postalFor } from "../../lab/gen/data.ts";
import { generate } from "../../lab/gen/generate.ts";
import type { FixtureFile, Scenario, Site } from "../../lab/gen/model.ts";
import { DEFAULT_PROFILE, drawProfiles, fixtureFor, type Profile, profileOf } from "../../lab/gen/population.ts";
import { Rng } from "../../lab/gen/rng.ts";
import { fillCheck, judge, type Observation } from "../../lab/run/oracle.ts";
import { renderReport, summarize } from "../../lab/report.ts";
import type { Result } from "../../lab/run/oracle.ts";

const FIXED = patternsJson as unknown as Patterns;
const world = generate("pop", { sites: 60, patterns: FIXED });
interface Item { type: string; title: string; urls?: { url: string }[]; fields: Record<string, unknown> }
const itemsOf = (f: FixtureFile) => f.items as Item[];
const profile_ = (over: Partial<Profile>): Profile => ({ ...DEFAULT_PROFILE, id: "p9", ...over });
const profile = (over: Partial<Profile>): Profile => ({ ...DEFAULT_PROFILE, id: "p9", ...over });

describe("drawProfiles", () => {
  it("same_seed_same_profiles", () => {
    expect(drawProfiles("s", 12)).toEqual(drawProfiles("s", 12));
    expect(drawProfiles("t", 12)).not.toEqual(drawProfiles("s", 12));
  });

  it("first_profile_is_the_default_whatever_the_seed", () => {
    expect(drawProfiles("a", 1)).toEqual([DEFAULT_PROFILE]);
    expect(drawProfiles("b", 4)[0]).toEqual(DEFAULT_PROFILE);
  });

  it("adding_profiles_never_perturbs_the_earlier_ones", () => {
    expect(drawProfiles("s", 9).slice(0, 5)).toEqual(drawProfiles("s", 5));
  });

  it("vault_size_in_range_and_every_axis_varies", () => {
    const ps = drawProfiles("range", 300);
    for (const p of ps) {
      expect(p.vaultSize).toBeGreaterThanOrEqual(0);
      expect(p.vaultSize).toBeLessThanOrEqual(500);
      expect(p.browser).toBe("chromium");
    }
    expect(new Set(ps.map((p) => p.id)).size).toBe(300);
    expect(ps.some((p) => p.vaultSize === 0)).toBe(true);
    expect(ps.some((p) => p.vaultSize >= 300)).toBe(true);
    expect(ps.some((p) => p.multiAccount) && ps.some((p) => !p.multiAccount)).toBe(true);
    expect(ps.some((p) => p.duplicates > 0)).toBe(true);
    expect(new Set(ps.map((p) => p.behaviour))).toEqual(new Set(["complete", "partial", "corrects_field", "abandons_step"]));
    expect(new Set(ps.map((p) => p.country))).toEqual(new Set(["US", "FR", "DE", "ES", "GB", "JP"]));
  });
});

describe("country formats", () => {
  it("phone_and_postal_per_country", () => {
    const r = new Rng("fmt");
    for (let k = 0; k < 20; k++) {
      expect(postalFor(r, "US")).toMatch(/^\d{5}$/);
      expect(postalFor(r, "FR")).toMatch(/^\d{5}$/);
      expect(postalFor(r, "DE")).toMatch(/^\d{5}$/);
      expect(postalFor(r, "ES")).toMatch(/^\d{5}$/);
      expect(postalFor(r, "GB")).toMatch(/^[A-Z]{1,2}\d[A-Z\d]? \d[A-Z]{2}$/);
      expect(postalFor(r, "JP")).toMatch(/^\d{3}-\d{4}$/);
      expect(phoneFor(r, "US")).toMatch(/^\+1 /);
      expect(phoneFor(r, "FR")).toMatch(/^\+33 /);
      expect(phoneFor(r, "DE")).toMatch(/^\+49 /);
      expect(phoneFor(r, "ES")).toMatch(/^\+34 /);
      expect(phoneFor(r, "GB")).toMatch(/^\+44 /);
      expect(phoneFor(r, "JP")).toMatch(/^\+81 /);
      expect(addressFor(r, "JP").country).toBe("JP");
    }
  });
});

describe("fixtureFor", () => {
  it("default_profile_returns_the_world_fixture_unchanged", () => {
    expect(fixtureFor(DEFAULT_PROFILE, world.sites, world.fixture)).toEqual(world.fixture);
  });

  it("jp_profile_gives_jp_postal_codes_and_phones", () => {
    const f = fixtureFor(profile({ country: "JP", lang: "ja" }), world.sites, world.fixture);
    const ids = itemsOf(f).filter((i) => i.type === "identity");
    expect(ids.length).toBeGreaterThan(0);
    for (const i of ids) {
      const a = i.fields.address as { postal_code: string; country: string };
      expect(a.postal_code).toMatch(/^\d{3}-\d{4}$/);
      expect(a.country).toBe("JP");
      expect(String(i.fields.mobile_phone)).toMatch(/^\+81 /);
    }
    // The titles the scenarios look for are untouched.
    const want = world.sites.filter((s) => s.identityTitle).map((s) => s.identityTitle).sort();
    expect(ids.map((i) => i.title).sort()).toEqual(want);
  });

  it("multi_account_gives_at_least_two_accounts_for_one_site", () => {
    const f = fixtureFor(profile({ multiAccount: true }), world.sites, world.fixture);
    const bySite = new Map<string, Item[]>();
    for (const i of itemsOf(f)) {
      if (i.type !== "login" || !i.urls?.[0]) continue;
      bySite.set(i.urls[0].url, [...(bySite.get(i.urls[0].url) ?? []), i]);
    }
    const accounts = world.sites.filter((s) => s.account && s.flow !== "signup").map((s) => bySite.get(`https://${s.host}`) ?? []);
    expect(accounts.length).toBeGreaterThan(0);
    for (const a of accounts) {
      expect(a.length).toBeGreaterThanOrEqual(2);
      expect(new Set(a.map((i) => i.fields.username)).size).toBe(a.length);
      expect(new Set(a.map((i) => i.title)).size).toBe(a.length);
    }
  });

  it("duplicates_repeat_site_logins_exactly", () => {
    const base = itemsOf(world.fixture).length;
    const f = fixtureFor(profile({ duplicates: 3 }), world.sites, world.fixture);
    expect(itemsOf(f)).toHaveLength(base + 3);
    const logins = itemsOf(f).filter((i) => i.type === "login");
    const keys = logins.map((i) => JSON.stringify(i));
    expect(keys.length - new Set(keys).size).toBe(3);
  });

  it("empty_vault", () => {
    expect(itemsOf(fixtureFor(profile({ vaultSize: 0 }), world.sites, world.fixture))).toEqual([]);
  });

  it("large_vault_fills_up_with_synthetic_items_outside_the_world", () => {
    const p = profile({ vaultSize: 500 });
    const f = fixtureFor(p, world.sites, world.fixture);
    expect(itemsOf(f)).toHaveLength(500);
    expect(JSON.stringify(fixtureFor(p, world.sites, world.fixture))).toBe(JSON.stringify(f));
    const base = itemsOf(world.fixture);
    // The world's own items come first, in order (identity values aside, rewritten for the country).
    expect(itemsOf(f).slice(0, base.length).map((i) => i.title)).toEqual(base.map((i) => i.title));
    expect(itemsOf(f).slice(0, base.length).filter((i) => i.type !== "identity")).toEqual(base.filter((i) => i.type !== "identity"));
    const hosts = new Set(world.hosts);
    for (const i of itemsOf(f).slice(base.length)) {
      for (const u of i.urls ?? []) {
        const h = new URL(u.url).hostname;
        expect(h).toMatch(/\.test$/);
        expect(hosts.has(h)).toBe(false);
        expect(world.sites.some((s) => h === s.host || h.endsWith(`.${s.host}`))).toBe(false);
      }
    }
    const titles = itemsOf(f).map((i) => i.title);
    expect(new Set(titles).size).toBe(titles.length);
    expect(itemsOf(f).slice(base.length).some((i) => i.type !== "login")).toBe(true);
  });

  it("vault_size_below_the_world_items_adds_nothing", () => {
    const f = itemsOf(fixtureFor(profile({ vaultSize: 1 }), world.sites, world.fixture));
    expect(f.map((i) => i.title)).toEqual(itemsOf(world.fixture).map((i) => i.title));
  });
});

describe("generate with profiles", () => {
  it("default_single_profile_has_no_profile_keys", () => {
    const w = generate("pop", { sites: 20, patterns: FIXED });
    expect(w.profiles).toBeUndefined();
    expect(w.scenarios.every((s) => s.profile === undefined && s.behaviour === undefined)).toBe(true);
    expect(generate("pop", { sites: 20, patterns: FIXED, profiles: 1 })).toEqual(w);
  });

  it("more_profiles_never_change_sites_or_fixture", () => {
    const one = generate("pop", { sites: 30, patterns: FIXED });
    const three = generate("pop", { sites: 30, patterns: FIXED, profiles: 3 });
    expect(three.sites).toEqual(one.sites);
    expect(three.fixture).toEqual(one.fixture);
    expect(three.idp).toEqual(one.idp);
    expect(three.hosts).toEqual(one.hosts);
    expect(three.profiles).toEqual(drawProfiles("pop", 3));
    expect(three.scenarios).toHaveLength(one.scenarios.length * 3);
    const p0 = three.scenarios.filter((s) => profileOf(s) === "p0").map(({ profile, ...s }) => { void profile; return s; });
    expect(p0).toEqual(one.scenarios);
  });

  it("empty_vault_expects_nofill_but_signup_still_generates", () => {
    const w = generate("pop", { sites: 40, patterns: FIXED, profiles: 40 });
    const empty = w.profiles!.filter((p) => p.vaultSize === 0).map((p) => p.id);
    expect(empty.length).toBeGreaterThan(0);
    let checked = 0;
    for (const s of w.scenarios.filter((x) => empty.includes(profileOf(x)) && x.driver !== "passkey_control")) {
      const site = w.sites[s.site]!;
      const plain = w.scenarios.find((b) => profileOf(b) === "p0" && b.site === s.site && b.driver === s.driver)!;
      // The password generator of a signup needs no item: that scenario keeps its historical expectation.
      if (site.flow === "signup" && s.driver === "menu_fill") expect(s.expect).toBe(plain.expect);
      else expect(s.expect).toBe("nofill");
      checked++;
    }
    expect(checked).toBeGreaterThan(0);
    // Profiles with a vault keep the historical expectations.
    const full = w.scenarios.filter((x) => !empty.includes(profileOf(x)));
    const base = w.scenarios.filter((x) => profileOf(x) === "p0");
    for (const s of full.filter((x) => x.driver === "one_click")) {
      expect(s.expect).toBe(base.find((b) => b.site === s.site && b.driver === s.driver)!.expect);
    }
  });

  it("behaviour_only_on_menu_fill_and_abandon_only_on_multi_step", () => {
    const w = generate("pop", { sites: 60, patterns: FIXED, profiles: 40 });
    const byId = new Map(w.profiles!.map((p) => [p.id, p]));
    let seen = new Set<string>();
    for (const s of w.scenarios) {
      const p = byId.get(profileOf(s))!;
      const site = w.sites[s.site]!;
      if (s.driver !== "menu_fill" || p.behaviour === "complete" || (p.behaviour === "abandons_step" && site.flow !== "multi_step")) {
        expect(s.behaviour).toBeUndefined();
      } else {
        expect(s.behaviour).toBe(p.behaviour);
        seen = new Set([...seen, p.behaviour]);
      }
    }
    expect(seen).toEqual(new Set(["partial", "corrects_field", "abandons_step"]));
  });
});

describe("oracle under a behaviour", () => {
  const form: Site = {
    index: 0, seed: "s0", host: "keen-glade-90.test", brand: "Keen Glade", lang: "en", labelLang: "en",
    flow: "address", traits: [], identityTitle: "Ada (Keen Glade)", buttons: { submit: "Save" },
    fields: [
      { role: "given_name", name: "gn", id: "gn", label: "Prenom", type: "text" },
      { role: "family_name", name: "fn", id: "fn", label: "Nom", type: "text" },
    ],
  };
  const multi: Site = {
    ...form, flow: "multi_step", account: { username: "ada", password: "x" }, itemTitle: "Keen Glade",
    fields: [
      { role: "username", name: "u", id: "u", label: "U", type: "text" },
      { role: "password", name: "p", id: "p", label: "P", type: "password" },
    ],
    steps: [
      [{ role: "username", name: "u", id: "u", label: "U", type: "text" }],
      [{ role: "password", name: "p", id: "p", label: "P", type: "password" }],
    ],
  };
  const sc = (site: Site, behaviour: Scenario["behaviour"], expectation: Scenario["expect"] = "pass"): Scenario =>
    ({ id: "0:menu_fill", site: 0, driver: "menu_fill", expect: expectation, ...(behaviour ? { behaviour } : {}) });
  const obs = (over: Partial<Observation>): Observation =>
    ({ driver: "menu_fill", overlayShown: true, itemOffered: true, events: [], filled: {}, durationMs: 1, ...over });

  it("corrects_field_judges_the_fill_not_the_later_edit", () => {
    // The user's edit makes the post wrong; the fill itself was complete: pass.
    const posted = { at: 1, host: form.host, kind: "submit" as const, form: "address", ok: false, fields: ["gn"], reason: "wrong_fields" };
    expect(judge(sc(form, "corrects_field"), form, obs({ filled: { gn: true, fn: true }, events: [posted] }))).toEqual({ verdict: "pass" });
    // A field the extension left empty fails, whatever the user typed afterwards.
    expect(judge(sc(form, "partial"), form, obs({ filled: { gn: true, fn: false } })).verdict).toBe("fail");
  });

  it("complete_still_needs_the_accepted_post", () => {
    expect(judge(sc(form, undefined), form, obs({ filled: { gn: true, fn: true } })).verdict).toBe("fail");
  });

  it("abandons_step_is_judged_on_step_one_only", () => {
    const s = sc(multi, "abandons_step");
    expect(judge(s, multi, obs({ filled: { u: true, p: false } }))).toEqual({ verdict: "pass" });
    expect(judge(s, multi, obs({ filled: { u: false, p: false } })).verdict).toBe("fail");
  });

  it("expected_failure_under_a_behaviour_turns_xpass_on_a_full_fill", () => {
    expect(judge(sc(form, "partial", "xfail"), form, obs({ filled: { gn: true, fn: true } }))).toEqual({ verdict: "xpass" });
    expect(judge(sc(form, "partial", "xfail"), form, obs({ filled: { gn: false, fn: false }, overlayShown: false, itemOffered: false })).verdict).toBe("xfail");
  });
});

describe("oracle checks the values of the fill", () => {
  const BEHAVIOURS = ["partial", "corrects_field", "abandons_step"] as const;
  const w = generate("pop-values", { sites: 80, patterns: FIXED });
  const multi = w.sites.find((s) => s.flow === "multi_step" && s.steps && s.account)!;
  const form = w.sites.find((s) => s.flow === "identity")!;
  const sc = (site: Site, behaviour: Scenario["behaviour"]): Scenario =>
    ({ id: `${site.index}:menu_fill`, site: site.index, driver: "menu_fill", expect: "pass", behaviour });
  const base = (site: Site, values: Record<string, string>): Observation => ({
    driver: "menu_fill", overlayShown: true, itemOffered: true, events: [], durationMs: 1, values,
    filled: Object.fromEntries(site.fields.map((f) => [f.name, true])),
  });
  const fieldOf = (site: Site, role: string) => site.fields.find((f) => f.role === role || (role === "username" && f.role === "email"))!;

  it("second_account_or_duplicate_filled_in_place_of_the_right_item_is_a_wrong_fill_under_each_behaviour", () => {
    const profile = profile_({ multiAccount: true, duplicates: 3 });
    const vault = fixtureFor(profile, w.sites, w.fixture);
    const check = fillCheck(w, multi, vault);
    const items = (vault.items as { title: string; urls?: { url: string }[]; fields: { username?: string; password?: string } }[])
      .filter((i) => i.urls?.[0]?.url === `https://${multi.host}`);
    const second = items.find((i) => i.title.endsWith(" (2)"))!;
    const id = fieldOf(multi, "username"), pw = fieldOf(multi, "password");
    for (const b of BEHAVIOURS) {
      const right = base(multi, { [id.name]: multi.account!.username, [pw.name]: multi.account!.password });
      const wrong = base(multi, { [id.name]: second.fields.username!, [pw.name]: second.fields.password! });
      expect(judge(sc(multi, b), multi, right, check)).toEqual({ verdict: "pass" });
      expect(judge(sc(multi, b), multi, wrong, check)).toEqual({ verdict: "fail", cause: "wrong_fill" });
    }
  });

  it("wrong_country_format_is_a_wrong_fill", () => {
    const jp = profile_({ country: "JP", lang: "ja" });
    const check = fillCheck(w, form, fixtureFor(jp, w.sites, w.fixture));
    const want = (v: typeof w.fixture) => (v.items as { title: string; fields: { mobile_phone?: string } }[]).find((i) => i.title === form.identityTitle)!.fields.mobile_phone!;
    const values = (phone: string) => Object.fromEntries(form.fields.map((f) => [f.name, f.role === "tel" ? phone : ({ given_name: "", family_name: "", email: "", birth_date: "", organization: "" } as Record<string, string>)[f.role] ?? ""]));
    // Every other field is checked too: take them from the JP vault item.
    const item = (fixtureFor(jp, w.sites, w.fixture).items as { title: string; fields: Record<string, unknown> }[]).find((i) => i.title === form.identityTitle)!;
    const full = (phone: string) => ({ ...values(phone), ...Object.fromEntries(form.fields.filter((f) => f.role !== "tel").map((f) => [f.name, String(({ given_name: item.fields.first_name, family_name: item.fields.last_name, email: item.fields.email, birth_date: item.fields.birth_date, organization: item.fields.company } as Record<string, unknown>)[f.role] ?? "")])) });
    for (const b of ["partial", "corrects_field"] as const) {
      expect(judge(sc(form, b), form, base(form, full(want(fixtureFor(jp, w.sites, w.fixture)))), check)).toEqual({ verdict: "pass" });
      expect(judge(sc(form, b), form, base(form, full(want(w.fixture))), check)).toEqual({ verdict: "fail", cause: "wrong_fill" });
    }
  });
});

describe("report by profile", () => {
  const res = (n: number, profile: string | undefined, verdict: Result["verdict"]): Result => ({
    worldSeed: "w", site: n, siteSeed: `s${n}`, flow: "login_single", traits: [], lang: "en", labelLang: "en", driver: "one_click",
    expect: "pass", verdict, retried: false, durationMs: 1, repro: "r", ...(profile ? { profile } : {}),
  });

  it("groups_by_profile_and_defaults_to_p0", () => {
    const s = summarize([res(0, undefined, "pass"), res(1, "p0", "fail"), res(2, "p1", "pass"), res(3, "p1", "pass")]);
    expect(s.byProfile.p0!.total).toBe(2);
    expect(s.byProfile.p1!.rate).toBe(1);
    const md = renderReport({ seed: "w", sites: 4, profiles: drawProfiles("w", 2) }, s, {});
    expect(md).toContain("### Par profil");
    expect(md).not.toContain(String.fromCharCode(0x2014));
    expect(md).toContain("| p1 | 2 | 2 |");
  });
});
