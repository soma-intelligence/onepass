import { describe, expect, it } from "vitest";
import { isVisible } from "../../src/content/detect/visibility";
import { byId, loadFixture, scrolledGeometry, testGeometry } from "./helpers";

describe("isVisible (spec 8.2)", () => {
  it("keeps plain visible fields", () => {
    loadFixture("hidden-fields.html");
    expect(isVisible(byId("u"), testGeometry)).toBe(true);
    expect(isVisible(byId("p"), testGeometry)).toBe(true);
  });

  it.each([
    "d-display",
    "d-display-parent",
    "d-visibility",
    "d-opacity",
    "d-opacity-self",
    "d-size",
    "d-offscreen",
    "d-aria",
    "d-aria-parent",
    "d-disabled",
    "d-fieldset",
    "d-readonly",
    "d-hidden",
    "d-aria-upper",
    "d-clip-path",
    "d-clip-rect",
    "d-overflow",
    "d-overflow-zero",
  ])("ignores %s", (id) => {
    loadFixture("hidden-fields.html");
    expect(isVisible(byId(id), testGeometry)).toBe(false);
  });

  it("treats a zero-size element as invisible with the real geometry (jsdom has no layout)", () => {
    loadFixture("hidden-fields.html");
    expect(isVisible(byId("u"))).toBe(false);
  });

  it("keeps a field far down a long page (no limit downward)", () => {
    document.body.innerHTML = '<input id="f" type="text" data-test-rect="0,5000,200,30">';
    expect(isVisible(byId("f"), testGeometry)).toBe(true);
  });

  it("hides a field more than 2000 px above the document", () => {
    document.body.innerHTML = '<input id="f" type="text" data-test-rect="0,-5000,200,30">';
    expect(isVisible(byId("f"), testGeometry)).toBe(false);
  });

  it("hides a field more than 2000 px right of the document", () => {
    document.body.innerHTML = '<input id="f" type="text" data-test-rect="4000,0,200,30">';
    expect(isVisible(byId("f"), testGeometry)).toBe(false);
  });

  it("keeps a header field after the page scrolled down (document coordinates)", () => {
    document.body.innerHTML = '<input id="f" type="text" data-test-rect="0,10,200,30">';
    expect(isVisible(byId("f"), scrolledGeometry({ x: 0, y: 6000 }))).toBe(true);
  });

  it("keeps a field inside a normal overflow:hidden container", () => {
    document.body.innerHTML =
      '<div style="overflow:hidden" data-test-rect="0,0,400,300"><input id="f" type="text" data-test-rect="10,10,200,30"></div>';
    expect(isVisible(byId("f"), testGeometry)).toBe(true);
  });

  it("hides a field scrolled out of an overflow:auto container of zero size", () => {
    document.body.innerHTML =
      '<div style="overflow:auto" data-test-rect="0,0,0,0"><input id="f" type="text" data-test-rect="0,0,200,30"></div>';
    expect(isVisible(byId("f"), testGeometry)).toBe(false);
  });
});
