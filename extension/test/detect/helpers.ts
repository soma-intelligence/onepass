import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Geometry } from "../../src/content/detect/visibility";

const FIXTURES = join(__dirname, "..", "fixtures", "forms");

/** Loads a fixture into the global jsdom document and returns it. */
export function loadFixture(name: string): Document {
  const html = readFileSync(join(FIXTURES, name), "utf8");
  document.documentElement.innerHTML = html.replace(/<!doctype[^>]*>/i, "");
  return document;
}

/**
 * Test-only layout stub: jsdom has no layout engine. Elements are laid out at
 * 200x30 inside a 1024x768 viewport unless `data-test-rect="x,y,w,h"` says
 * otherwise. Production code never reads this attribute.
 */
export const testGeometry: Geometry = (el) => {
  const raw = el.getAttribute("data-test-rect");
  const [x, y, width, height] = raw ? raw.split(",").map(Number) : [0, 0, 200, 30];
  return {
    rect: { left: x ?? 0, top: y ?? 0, width: width ?? 0, height: height ?? 0 },
    viewport: { width: 1024, height: 768 },
  };
};

export function byId(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el;
}
