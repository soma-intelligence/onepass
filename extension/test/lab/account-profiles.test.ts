// @vitest-environment node
// Account profiles and start states of the lab: p1 (two accounts, no site
// memory), p2 (two accounts, the second used last on the site), p3 (an
// exact-host item next to a domain-wide one), each with its stated outcome,
// and the scenario variants a locked vault, a stopped host and the shortcut
// add. The default world must not move.
import { describe, expect, it } from "vitest";
import patternsJson from "../../lab/corpus/patterns.json";
import type { Patterns } from "../../lab/corpus/types.ts";
import { generate, parseStarts, parseTriggers, withDrivers, withStarts } from "../../lab/gen/generate.ts";
import type { FixtureFile, World } from "../../lab/gen/model.ts";
import {
  ACCOUNT_FLOWS, ACCOUNT_OUTCOME, ACCOUNT_PROFILES, accountProfiles, DEFAULT_PROFILE, fixtureFor, meantAccount, otherUsername, type Profile,
} from "../../lab/gen/population.ts";
import { Ledger } from "../../lab/server/ledger.ts";

const FIXED = patternsJson as unknown as Patterns;
const SITES = 40;
const plain = generate("acct", { sites: SITES, patterns: FIXED });
const world = generate("acct", { sites: SITES, patterns: FIXED, accounts: ["p1", "p2", "p3"] });
interface Item { type: string; title: string; urls?: { url: string; rule: string }[]; fields: Record<string, unknown> }
const itemsOf = (f: FixtureFile) => f.items as Item[];
const byId = (id: string): Profile => ACCOUNT_PROFILES.find((p) => p.id === id)!;
const passwordSites = (w: World) => w.sites.filter((s) => ACCOUNT_FLOWS.has(s.flow));
const loginsOf = (f: FixtureFile, host: string) => itemsOf(f).filter((i) => i.type === "login" && i.urls?.[0]?.url === `https://${host}`);

describe("account profiles", () => {
  it("ids_are_fixed_and_checked", () => {
    expect(accountProfiles(["p2", "p0"]).map((p) => p.id)).toEqual(["p0", "p2"]);
    expect(accountProfiles(["p0"])).toEqual([DEFAULT_PROFILE]);
    expect(() => accountProfiles(["p4"])).toThrow(/unknown or repeated account profile p4/);
    expect(() => accountProfiles(["p1", "p1"])).toThrow();
    expect(() => generate("acct", { sites: 12, patterns: FIXED, accounts: ["p1"], profiles: 3 })).toThrow(/do not mix/);
  });

  it("the_world_and_its_vault_do_not_move", () => {
    expect(world.sites).toEqual(plain.sites);
    expect(world.fixture).toEqual(plain.fixture);
    expect(world.profiles?.map((p) => p.id)).toEqual(["p1", "p2", "p3"]);
    // Without account profiles nothing new appears in the world.
    expect(plain.scenarios.some((s) => s.account !== undefined || s.start !== undefined || s.shortcut !== undefined)).toBe(false);
    expect(plain.profiles).toBeUndefined();
  });

  it("p1_and_p2_add_a_second_account_on_every_plain_password_site", () => {
    expect(passwordSites(world).length).toBeGreaterThan(3);
    for (const id of ["p1", "p2"]) {
      const vault = fixtureFor(byId(id), world.sites, world.fixture);
      for (const s of world.sites) {
        const logins = loginsOf(vault, s.host);
        if (!ACCOUNT_FLOWS.has(s.flow)) {
          expect(logins).toEqual(loginsOf(world.fixture, s.host));
          continue;
        }
        expect(logins.map((i) => i.title)).toEqual([s.itemTitle, `${s.itemTitle} (2)`]);
        expect(logins.map((i) => i.urls![0]!.rule)).toEqual(["domain", "domain"]);
        expect(logins[1]!.fields.username).not.toBe(logins[0]!.fields.username);
        expect(logins[1]!.fields.password).not.toBe(logins[0]!.fields.password);
      }
    }
  });

  it("p3_has_one_exact_host_item_and_one_domain_wide_item", () => {
    const vault = fixtureFor(byId("p3"), world.sites, world.fixture);
    for (const s of passwordSites(world)) {
      // The exact-host item on the site's own host; the domain-wide one saved for another host of the same
      // registrable domain (on the very same host both would be exact-host matches: no sole one, the menu).
      expect(loginsOf(vault, s.host).map((i) => [i.title, i.urls![0]!.rule])).toEqual([[s.itemTitle, "exact_host"]]);
      expect(loginsOf(vault, `www.${s.host}`).map((i) => [i.title, i.urls![0]!.rule])).toEqual([[`${s.itemTitle} (domaine)`, "domain"]]);
    }
    // The world's own vault is not touched by the copy.
    expect(loginsOf(world.fixture, passwordSites(world)[0]!.host)[0]!.urls![0]!.rule).toBe("domain");
  });

  it("the_meant_account_is_the_last_used_one_under_p2_else_the_sites_own", () => {
    const s = passwordSites(world)[0]!;
    for (const id of ["p1", "p3"]) {
      const vault = fixtureFor(byId(id), world.sites, world.fixture);
      expect(meantAccount(byId(id), s, vault)).toEqual({ title: s.itemTitle, username: s.account!.username, password: s.account!.password });
      const other = id === "p3" ? loginsOf(vault, `www.${s.host}`)[0]! : loginsOf(vault, s.host)[1]!;
      expect(otherUsername(byId(id), s, vault)).toBe(other.fields.username);
      expect(other.fields.username).not.toBe(s.account!.username);
    }
    const vault = fixtureFor(byId("p2"), world.sites, world.fixture);
    const second = loginsOf(vault, s.host)[1]!;
    expect(meantAccount(byId("p2"), s, vault)).toEqual({ title: `${s.itemTitle} (2)`, username: second.fields.username, password: second.fields.password });
    expect(otherUsername(byId("p2"), s, vault)).toBe(s.account!.username);
    expect(meantAccount(DEFAULT_PROFILE, s, world.fixture)).toBeUndefined();
    const form = world.sites.find((x) => x.flow === "checkout_card")!;
    expect(meantAccount(byId("p1"), form, vault)).toBeUndefined();
  });

  it("each_scenario_states_its_account_and_its_expected_outcome", () => {
    const n = passwordSites(world).length;
    for (const p of ACCOUNT_PROFILES) {
      const mine = world.scenarios.filter((s) => s.profile === p.id);
      expect(mine).toHaveLength(n);
      for (const s of mine) {
        const site = world.sites[s.site]!;
        expect(ACCOUNT_FLOWS.has(site.flow)).toBe(true);
        expect(s.id).toBe(`${p.id}:${site.index}:one_click`);
        expect(s.account?.outcome).toBe(ACCOUNT_OUTCOME[p.accounts!]);
        expect(s.account?.title).toBe(p.id === "p2" ? `${site.itemTitle} (2)` : site.itemTitle);
      }
    }
    expect(ACCOUNT_OUTCOME.two).toMatch(/asks/);
    expect(ACCOUNT_OUTCOME.two_last_used).toMatch(/one gesture/);
    expect(ACCOUNT_OUTCOME.exact_and_domain).toMatch(/exact-host/);
    // No password in a scenario.
    const text = JSON.stringify(world.scenarios);
    for (const p of ACCOUNT_PROFILES) {
      for (const i of itemsOf(fixtureFor(p, world.sites, world.fixture))) if (i.type === "login" && i.fields.password) expect(text).not.toContain(String(i.fields.password));
    }
  });

  it("smart_fill_plays_the_account_profiles_too_and_p0_only_when_asked", () => {
    const smart = withDrivers(world, ["smart_fill"]);
    expect(smart.scenarios.every((s) => s.driver === "smart_fill" && s.account !== undefined)).toBe(true);
    expect(smart.scenarios).toHaveLength(3 * passwordSites(world).length);
    const withDefault = withDrivers(generate("acct", { sites: SITES, patterns: FIXED, accounts: ["p0", "p1"] }), ["smart_fill"]);
    expect(withDefault.scenarios.filter((s) => s.profile === undefined)).toHaveLength(SITES);
  });

  it("the_second_accounts_secrets_are_owned_by_the_sites_host", () => {
    const fixtures = ACCOUNT_PROFILES.map((p) => fixtureFor(p, world.sites, world.fixture));
    const ledger = new Ledger(world, fixtures);
    const s = passwordSites(world)[0]!;
    const second = loginsOf(fixtures[0]!, s.host)[1]!;
    const pw = s.fields.find((f) => f.role === "password")!.name;
    expect(ledger.record(s.host, "/", { [pw]: String(second.fields.password) })).toEqual([]);
    expect(ledger.record("elsewhere.test", "/", { [pw]: String(second.fields.password) })).toHaveLength(1);
  });
});

describe("start states and triggers", () => {
  const smart = withDrivers(plain, ["current", "smart_fill"]);

  it("the_defaults_change_nothing", () => {
    expect(withStarts(smart)).toEqual(smart);
    expect(withStarts(smart, ["unlocked_warm"], ["icon"]).scenarios).toEqual(smart.scenarios);
  });

  it("locked_and_cold_replay_the_scenarios_with_a_goal", () => {
    const w = withStarts(smart, ["unlocked_warm", "locked", "cold"]);
    const base = smart.scenarios.filter((s) => ["one_click", "menu_fill", "smart_fill"].includes(s.driver) && s.expect !== "nofill");
    for (const start of ["locked", "cold"] as const) {
      const mine = w.scenarios.filter((s) => s.start === start);
      expect(mine.map((s) => s.id)).toEqual(base.map((s) => `${s.id}@${start}`));
      expect(mine.some((s) => s.driver === "lookalike" || s.driver === "passkey_control" || s.expect === "nofill")).toBe(false);
    }
    expect(w.scenarios.filter((s) => s.start === undefined)).toEqual(smart.scenarios);
    expect(new Set(w.scenarios.map((s) => s.id)).size).toBe(w.scenarios.length);
  });

  it("a_start_state_alone_drops_the_unlocked_scenarios", () => {
    const w = withStarts(smart, ["cold"]);
    expect(w.scenarios.length).toBeGreaterThan(0);
    expect(w.scenarios.every((s) => s.start === "cold")).toBe(true);
  });

  it("the_shortcut_is_a_second_way_to_start_smart_fill", () => {
    const w = withStarts(smart, ["unlocked_warm", "locked"], ["icon", "shortcut"]);
    const keyed = w.scenarios.filter((s) => s.shortcut);
    expect(keyed.every((s) => s.driver === "smart_fill")).toBe(true);
    expect(keyed.filter((s) => s.start === undefined)).toHaveLength(SITES);
    expect(keyed.some((s) => s.id.endsWith("/shortcut@locked"))).toBe(true);
    const only = withStarts(smart, ["unlocked_warm"], ["shortcut"]);
    expect(only.scenarios.filter((s) => s.driver === "smart_fill").every((s) => s.shortcut)).toBe(true);
    expect(only.scenarios.filter((s) => s.driver !== "smart_fill")).toEqual(smart.scenarios.filter((s) => s.driver !== "smart_fill"));
  });

  it("lists_are_parsed_and_checked", () => {
    expect(parseStarts("cold, unlocked_warm")).toEqual(["unlocked_warm", "cold"]);
    expect(() => parseStarts("asleep")).toThrow(/unknown start state asleep/);
    expect(parseTriggers("shortcut,icon")).toEqual(["icon", "shortcut"]);
    expect(() => parseTriggers("")).toThrow();
  });
});
