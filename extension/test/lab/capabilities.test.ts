// @vitest-environment node
// Capabilities of the forms flows (spec 11.4): each site lists what it
// needs from the extension; a scenario whose need is still pending expects
// xfail with the capability as reason, a cross-site frame keeps its nofill,
// and once nothing it needs is pending the scenario expects a pass.
import { describe, expect, it } from "vitest";
import { CAPABILITIES, expectationFor, needs, PENDING } from "../../lab/gen/capabilities.ts";
import { isFormsFlow } from "../../lab/gen/forms-flows.ts";
import { generate, loadPatterns } from "../../lab/gen/generate.ts";

const world = generate("capabilities-seed", { sites: 400, patterns: loadPatterns() });
const forms = world.sites.filter((s) => isFormsFlow(s.flow));
const has = (cap: string) => forms.filter((s) => needs(s).includes(cap as never));

describe("needs", () => {
  it("lists the capabilities of spec 11.4 from the site's fields", () => {
    expect([...CAPABILITIES].sort()).toEqual(["date_parts", "date_text", "document_source", "honorific_sex", "intent_contact", "issuing_country",
      "loyalty", "nationality", "persons", "radio_group", "roles_company", "roles_document", "roles_person", "work_tel"]);
    for (const s of forms) {
      const n = needs(s);
      expect(n.length, `${s.index}`).toBeGreaterThan(0);
      expect(n.includes("roles_document")).toBe(s.fields.some((f) => /^(passport|license)_/.test(f.role)));
      expect(n.includes("persons")).toBe(s.fields.some((f) => (f.person ?? 0) > 0 || f.block === "shipping"));
      expect(n.includes("radio_group")).toBe(s.fields.some((f) => f.render?.choice?.kind === "radio"));
      expect(n.includes("date_parts")).toBe(s.fields.some((f) => f.render?.date?.kind === "part"));
      expect(n.includes("date_text")).toBe(s.fields.some((f) => f.render?.date?.kind === "text"));
      expect(n.includes("work_tel")).toBe(s.fields.some((f) => f.role === "tel_work"));
      expect(n.includes("loyalty")).toBe(s.fields.some((f) => f.role === "loyalty_number"));
      expect(n.includes("roles_company")).toBe(s.fields.some((f) => ["vat_number", "company_id", "job_title", "department", "website"].includes(f.role)));
    }
    for (const c of CAPABILITIES) expect(has(c).length, c).toBeGreaterThan(0);
  });

  it("the older flows need nothing", () => {
    for (const s of world.sites.filter((x) => !isFormsFlow(x.flow))) expect(needs(s)).toEqual([]);
  });
});

describe("expectations of the forms flows", () => {
  it("every forms scenario expects xfail with its first pending capability, a cross-site frame keeps nofill", () => {
    // Every capability is in the extension since Task 12: PENDING is empty, the scenarios expect a pass.
    expect(new Set(PENDING)).toEqual(new Set());
    const scenarios = world.scenarios.filter((sc) => isFormsFlow(world.sites[sc.site]!.flow));
    expect(scenarios.length).toBeGreaterThan(0);
    for (const sc of scenarios) {
      const site = world.sites[sc.site]!;
      const first = needs(site).find((c) => PENDING.has(c));
      if (site.traits.includes("iframe_cross_site")) {
        expect(sc).toMatchObject({ expect: "nofill", reason: "R-10" });
      } else if (first !== undefined) {
        expect(sc.expect).toBe("xfail");
        expect(sc.reason).toBe(`forms: ${first}`);
      } else {
        expect(sc.reason ?? "").not.toMatch(/^forms:/);
      }
    }
  });

  it("a scenario whose needs are no longer pending expects a pass", () => {
    const site = forms.find((s) => !s.traits.includes("iframe_cross_site"))!;
    const n = needs(site);
    expect(expectationFor(site, "menu_fill", undefined, new Set())).toEqual({ expect: "pass" });
    expect(expectationFor(site, "menu_fill", undefined, new Set([n.at(-1)!]))).toEqual({ expect: "xfail", reason: `forms: ${n.at(-1)}` });
    const others = new Set(CAPABILITIES.filter((c) => !n.includes(c)));
    expect(expectationFor(site, "smart_fill", undefined, others)).toEqual({ expect: "pass" });
  });
});
