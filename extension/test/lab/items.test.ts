// @vitest-environment node
// Smart fill lab support: which item a form was filled from (names only) and
// the driver sets of a run (same world, smart_fill scenarios added).
import { describe, expect, it } from "vitest";
import { generate, loadPatterns, parseDriverGroups, withDrivers } from "../../lab/gen/generate.ts";
import { foreignFields } from "../../lab/run/items.ts";
import { smartTarget } from "../../lab/run/target.ts";
import { expectedValues } from "../../lab/server/rp.ts";

const world = generate("items-seed", { sites: 120, patterns: loadPatterns() });
const cards = world.sites.filter((s) => s.cardTitle !== undefined);
const people = world.sites.filter((s) => s.identityTitle !== undefined);

/** The site's form filled with the item of `from` (field name -> value). */
function filledFrom(site: (typeof world.sites)[number], from: (typeof world.sites)[number]): Record<string, string> {
  const v = expectedValues(world, from);
  return Object.fromEntries(site.fields.map((f) => [f.name, v[f.role] ?? ""]));
}

describe("foreign fields", () => {
  it("own_item_is_never_foreign", () => {
    for (const s of [...cards, ...people]) expect(foreignFields(world, s, filledFrom(s, s))).toEqual([]);
  });

  it("another_items_values_are_foreign", () => {
    expect(cards.length).toBeGreaterThan(1);
    const [a, b] = cards;
    const names = foreignFields(world, a!, filledFrom(a!, b!));
    expect(names).toContain(a!.fields.find((f) => f.role === "cc_number")!.name);
    const [p, q] = people;
    expect(foreignFields(world, p!, filledFrom(p!, q!)).length).toBeGreaterThan(0);
  });

  it("unknown_values_and_typed_fields_are_not_foreign", () => {
    const [a, b] = cards;
    const unknown = Object.fromEntries(a!.fields.map((f) => [f.name, "nothing of the vault"]));
    expect(foreignFields(world, a!, unknown)).toEqual([]);
    const all = a!.fields.map((f) => f.name);
    expect(foreignFields(world, a!, filledFrom(a!, b!), all)).toEqual([]);
  });

  it("login_of_another_site_is_foreign", () => {
    const logins = world.sites.filter((s) => s.account && s.flow.startsWith("login_") && s.fields.length > 0);
    const [a, b] = logins;
    const user = a!.fields.find((f) => f.role === "username" || f.role === "email")!;
    expect(foreignFields(world, a!, { [user.name]: a!.account!.username })).toEqual([]);
    expect(foreignFields(world, a!, { [user.name]: b!.account!.username })).toEqual([user.name]);
  });
});

describe("driver sets", () => {
  it("smart_fill_adds_one_scenario_per_site_and_keeps_the_world", () => {
    const both = withDrivers(world, ["current", "smart_fill"]);
    expect(both.sites).toBe(world.sites);
    expect(both.scenarios.filter((s) => s.driver !== "smart_fill")).toEqual(world.scenarios);
    const smart = both.scenarios.filter((s) => s.driver === "smart_fill");
    expect(smart.map((s) => s.site)).toEqual(world.sites.map((s) => s.index));
    // Same capability table: a cross-site frame expects nothing filled, a passkey site is a known gap.
    for (const s of smart) {
      const site = world.sites[s.site]!;
      if (site.traits.includes("iframe_cross_site")) expect(s.expect).toBe("nofill");
      else if (site.flow === "login_passkey") expect(s.expect).toBe("xfail");
    }
    expect(withDrivers(world, ["smart_fill"]).scenarios.every((s) => s.driver === "smart_fill")).toBe(true);
    expect(withDrivers(world, ["current"]).scenarios).toEqual(world.scenarios);
  });

  it("parses_driver_sets", () => {
    expect(parseDriverGroups("smart_fill,current")).toEqual(["current", "smart_fill"]);
    expect(() => parseDriverGroups("current,menu")).toThrow(/unknown driver set menu/);
    expect(() => parseDriverGroups("")).toThrow();
  });
});

describe("smart fill target", () => {
  const base = world.sites.find((s) => s.flow === "login_single")!;
  const field = (role: (typeof base.fields)[number]["role"], id: string) => ({ role, name: id, id, label: id, type: "text" });
  it("follows_the_content_icon_roles", () => {
    // A password field carries the icon (current_password in content/icon.ts).
    expect(smartTarget({ ...base, flow: "login_single", fields: [field("password", "pw")] })?.id).toBe("pw");
    // No icon on a card expiry or a country: the first field with one.
    expect(smartTarget({ ...base, flow: "checkout_card", fields: [field("cc_exp", "e"), field("cc_number", "n")] })?.id).toBe("n");
    expect(smartTarget({ ...base, flow: "address", fields: [field("country", "c")] })).toBeUndefined();
    expect(smartTarget({ ...base, flow: "signup", fields: [field("email", "m"), field("new_password", "p")] })?.id).toBe("p");
  });
});
