// Security review M4: identity documents and personal data only go into fields the user perceives.
import { afterEach, describe, expect, it } from "vitest";
import { needsPerceivable } from "../../src/content/filler";
import { isPerceivable, PERCEIVABLE_MIN_OPACITY, PERCEIVABLE_MIN_PX } from "../../src/content/detect/visibility";
import type { FieldHitTest } from "../../src/content/detect/visibility";
import type { PageAnalysis } from "../../src/shared/messages";
import { testGeometry } from "../detect/helpers";
import { input, setPage, start, type Started } from "./harness";

const ORIGIN = "https://atlas-cloud.test";

let s: Started | null = null;
afterEach(() => {
  s?.cs.stop();
  s = null;
});

/**
 * A travel form (jsdom viewport 1024x768): a visible first name, e-mail and passport, then the same
 * roles in fields a hostile form hides: below the fold, 6x6 px, faded to 0.3, and one that the hit
 * test finds covered.
 */
const TRAVEL = `
<form id="travel">
  <input id="given" name="given" autocomplete="given-name" data-test-rect="0,0,200,30">
  <input id="mail" name="email" type="email" autocomplete="email" data-test-rect="0,40,200,30">
  <input id="passport" name="passport" data-test-rect="0,80,200,30">
  <input id="far" name="passport_far" data-test-rect="0,20000,200,30">
  <input id="tiny" name="passport_tiny" data-test-rect="0,120,6,6">
  <input id="faded" name="passport_faded" style="opacity:0.3" data-test-rect="0,160,200,30">
  <input id="covered" name="passport_covered" data-test-rect="0,200,200,30">
  <input id="far-tel" name="tel" autocomplete="tel" data-test-rect="0,30000,200,30">
  <button type="submit">Book</button>
</form>
<div id="cover"></div>`;

function travelForm(st: Started) {
  const all = st.ext.ofType("page_analysis");
  const a = all[all.length - 1]!.analysis as PageAnalysis;
  return a.forms.find((f) => f.fields.some((x) => x.role === "passport_number"))!;
}

describe("identity fill into perceivable fields only (M4)", () => {
  it("writes the visible fields and none of the hidden ones", () => {
    setPage(TRAVEL);
    const cover = () => document.getElementById("cover");
    const hitTest: FieldHitTest = (el) => (el.id === "covered" ? cover() : el);
    s = start(undefined, { fieldHitTest: hitTest });
    const form = travelForm(s);
    const roles = form.fields.map((f) => f.role);
    expect(roles.filter((r) => r === "passport_number").length).toBeGreaterThanOrEqual(4);
    s.ext.deliver({
      type: "fill",
      origin: ORIGIN,
      formRef: form.ref,
      values: { given_name: "Ada", email: "ada@atlas.dev", passport_number: "X1234567", tel: "+33600000000" },
    });
    expect(input("given").value).toBe("Ada");
    expect(input("mail").value).toBe("ada@atlas.dev");
    expect(input("passport").value).toBe("X1234567");
    for (const id of ["far", "tiny", "faded", "covered", "far-tel"]) expect(input(id).value, id).toBe("");
  });

  it("keeps the login rules for an identifier e-mail and for credentials", () => {
    expect(needsPerceivable("email", "login")).toBe(false);
    expect(needsPerceivable("username", "signup")).toBe(false);
    expect(needsPerceivable("current_password", "login")).toBe(false);
    expect(needsPerceivable("email", "signup")).toBe(true);
    expect(needsPerceivable("email", "identity")).toBe(true);
    expect(needsPerceivable("passport_number", "identity")).toBe(true);
    expect(needsPerceivable("loyalty_number", "identity")).toBe(true);
    expect(needsPerceivable("address_line1", "address")).toBe(true);
  });

  it("documents its thresholds", () => {
    expect(PERCEIVABLE_MIN_PX).toBe(10);
    expect(PERCEIVABLE_MIN_OPACITY).toBe(0.5);
  });

  it("accepts a hit on the field's own label or our icon, refuses anything else", () => {
    setPage(`<label id="l" for="f">Passport</label><input id="f"><div id="other"></div>`);
    const f = input("f");
    const own = document.createElement("onepass-root");
    const at = (hit: Element | null | undefined) => isPerceivable(f, testGeometry, { hitTest: () => hit, isOwn: (e) => e === own });
    expect(at(f)).toBe(true);
    expect(at(document.getElementById("l"))).toBe(true);
    expect(at(own)).toBe(true);
    expect(at(undefined)).toBe(true);
    expect(at(document.getElementById("other"))).toBe(false);
    expect(at(null)).toBe(false);
  });
});
