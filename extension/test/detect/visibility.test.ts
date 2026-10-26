import { describe, expect, it } from "vitest";
import { isVisible } from "../../src/content/detect/visibility";
import { byId, loadFixture, testGeometry } from "./helpers";

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
  ])("ignores %s", (id) => {
    loadFixture("hidden-fields.html");
    expect(isVisible(byId(id), testGeometry)).toBe(false);
  });

  it("treats a zero-size element as invisible with the real geometry (jsdom has no layout)", () => {
    loadFixture("hidden-fields.html");
    expect(isVisible(byId("u"))).toBe(false);
  });
});
