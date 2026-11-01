// Replays the lab's country/state fixtures (lab/fixtures/country-state) in
// jsdom: each page with its own script, filled as the content script would,
// checked once every later write settled.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import { createFiller } from "../../src/content/filler";
import type { FieldRole } from "../../src/shared/messages";
import { testGeometry } from "../detect/helpers";

const DIR = join(__dirname, "..", "..", "lab", "fixtures", "country-state");

interface Case {
  name: string;
  page: string;
  values: Partial<Record<FieldRole, string>>;
  expect: Record<string, string>;
}

const { cases } = JSON.parse(readFileSync(join(DIR, "cases.json"), "utf8")) as { cases: Case[] };

/** Loads `page` into the global document and runs its scripts. */
function load(page: string): void {
  const html = readFileSync(join(DIR, page), "utf8");
  document.documentElement.lang = /<html[^>]*\blang="([^"]*)"/i.exec(html)?.[1] ?? "";
  document.documentElement.innerHTML = html.replace(/<!doctype[^>]*>/i, "");
  for (const s of Array.from(document.querySelectorAll("script"))) {
    const code = s.textContent ?? "";
    s.remove();
    new Function(code)();
  }
}

function read(selector: string): string {
  const el = document.querySelector(selector);
  if (!el) throw new Error(`missing ${selector}`);
  if (el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement) return el.value;
  return (el.textContent ?? "").trim();
}

afterEach(() => {
  document.documentElement.lang = "";
  document.body.innerHTML = "";
});

describe("country/state lab fixtures", () => {
  it("has the four checkout families", () => {
    const pages = new Set(cases.map((c) => c.page));
    for (const p of ["shopify-like.html", "stripe-like.html", "amazon-like.html", "fr-boutique.html"]) expect(pages).toContain(p);
  });

  for (const c of cases) {
    it(c.name, async () => {
      load(c.page);
      const refs = new RefRegistry();
      const analyze = () => analyzeDocument(document, refs, { url: `https://fixture.test/${c.page}`, geometry: testGeometry });
      const filler = createFiller({
        refs,
        geometry: testGeometry,
        analyze,
        resolve: (ref, a) => a.forms.find((f) => f.ref === ref) ?? null,
        lang: () => document.documentElement.lang,
      });
      const form = analyze().forms[0];
      expect(form, "the page's form is detected").toBeDefined();
      const r = filler.fill(form!.ref, c.values);
      expect((await r.done).length).toBeGreaterThan(0);
      const got = Object.fromEntries(Object.keys(c.expect).map((k) => [k, read(k)]));
      expect(got).toEqual(c.expect);
    }, 10_000);
  }
});
