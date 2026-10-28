import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { extractFeatures, FEATURE_VERSION, normalizeText } from "../../src/content/detect/features";

const FIXTURES = join(__dirname, "..", "fixtures", "lab");
const load = (name: string): Document =>
  new DOMParser().parseFromString(readFileSync(join(FIXTURES, name), "utf8"), "text/html");
const html = (s: string): Document => new DOMParser().parseFromString(s, "text/html");

describe("extractFeatures", () => {
  it("label, placeholder, aria and neighbours are read", () => {
    const p = extractFeatures(load("login-floating-label.html"));
    expect(p.forms[0]!.fields[0]).toMatchObject({ label: "email address", placeholder: "you@example", index: 0, autocomplete: "username", required: true });
    expect(p.forms[0]!.fields[1]).toMatchObject({ label: "password", ariaLabel: "your secret", maxlength: 64, hasPattern: true, index: 1 });
    expect(p.forms[0]!.fields[1]!.neighbourLabels).toContain("email address");
    expect(p.forms[0]!.fields[0]!.neighbourLabels).toContain("password");
    expect(p.forms[0]!.fields[0]!.pageTitle).toBe("sign in | example");
    expect(p.forms[0]!.buttons).toEqual(["sign in", "go"]);
    expect(p.forms[0]!.fields[0]!.formButtons).toEqual(["sign in", "go"]);
    expect(FEATURE_VERSION).toBe(1);
  });

  it("neighbour text is the nearest text before and after, never a script or a textarea", () => {
    const p = extractFeatures(load("orphans-shadow-iframe.html"));
    const [cc, country] = p.forms[0]!.fields;
    expect(cc).toMatchObject({ before: "card number", after: "hint", inputmode: "numeric" });
    expect(country!.before).toBe("hint");
    expect(JSON.stringify(p)).not.toMatch(/secret script|do not read me/);
    expect(p.forms[0]!.fields.map((f) => f.tag)).toEqual(["input", "select", "textarea"]);
  });

  it("at most 2 labels before and 2 after", () => {
    const inputs = [1, 2, 3, 4, 5].map((n) => `<input aria-label="f${n}">`).join("");
    const f = extractFeatures(html(`<form>${inputs}</form>`)).forms[0]!.fields[2]!;
    expect(f.neighbourLabels).toEqual(["f1", "f2", "f4", "f5"]);
  });

  it("5000 inputs are capped at 300 and flagged", () => {
    const body = Array.from({ length: 5000 }, (_, i) => `<input name="f${i}">`).join("");
    const p = extractFeatures(html(`<form>${body}</form>`));
    expect(p.forms.flatMap((f) => f.fields)).toHaveLength(300);
    expect(p.truncated).toBe(true);
    const few = html(`<form>${body.slice(0, 20 * 17)}</form>`);
    expect(extractFeatures(few, { maxFields: 20 }).truncated).toBe(false);
    expect(extractFeatures(few, { maxFields: 19 }).truncated).toBe(true);
  });

  it("non-Latin labels survive normalization", () => {
    expect(normalizeText("ｍｅｌｄｅｎ  Ａｎ")).toBe("melden an");
    expect(normalizeText("كلمة المرور")).toBe("كلمة المرور");
    expect(extractFeatures(load("login-ja.html")).forms[0]!.fields[1]!.label).toBe("パスワード");
  });

  it("the inner normalizer agrees with normalizeText", () => {
    for (const s of ["  Ａｂｃ\n\tDéF  ", "ＰＡＳＳＷＯＲＤ", "Ｍot de  passe", "كلمة  المرور", "ＳＩＧＮ　ＩＮ"]) {
      const f = extractFeatures(html(`<form><input aria-label="${s}"></form>`)).forms[0]!.fields[0]!;
      expect(f.ariaLabel).toBe(normalizeText(s));
    }
  });

  it("data-lab attributes never leak into features except lab, read only with labField", () => {
    expect(extractFeatures(load("dataset-marked.html")).forms[0]!.fields.every((f) => f.lab === undefined)).toBe(true);
    const p = extractFeatures(load("dataset-marked.html"), { labField: true });
    expect(JSON.stringify(p)).not.toMatch(/data-lab/);
    expect(p.forms[0]!.fields[0]!.lab).toBe("3");
    expect(p.forms[0]!.fields[1]!.lab).toBe("7");
    expect(extractFeatures(load("login-ja.html")).forms[0]!.fields[0]!.lab).toBeUndefined();
  });

  it("framework markers", () => {
    expect(extractFeatures(load("react-root.html")).framework).toBe("react");
    expect(extractFeatures(load("vue-root.html")).framework).toBe("vue");
    expect(extractFeatures(load("angular-root.html")).framework).toBe("angular");
    expect(extractFeatures(load("login-ja.html")).framework).toBe("other");
  });

  it("reports iframes and shadow fields", () => {
    const p = extractFeatures(load("orphans-shadow-iframe.html"));
    expect(p.iframes).toContainEqual({ origin: "https://pay.stripe.com", sameSite: false });
    expect(p.iframes).toHaveLength(2);
    document.body.innerHTML = `<div id="h"></div><iframe src="/local"></iframe>`;
    document.getElementById("h")!.attachShadow({ mode: "open" }).innerHTML = "<input><input>";
    const q = extractFeatures(document);
    expect(q.shadowFields).toBe(2);
    expect(q.iframes).toEqual([{ origin: location.origin, sameSite: true }]);
  });

  describe("visibility and geometry", () => {
    const orig = Element.prototype.getBoundingClientRect;
    afterEach(() => { Element.prototype.getBoundingClientRect = orig; });
    const rect = (w: number, h: number, l = 0, t = 0) => () => ({ width: w, height: h, left: l, top: t, right: l + w, bottom: t + h, x: l, y: t, toJSON() {} }) as DOMRect;

    it("classifies and measures", () => {
      Element.prototype.getBoundingClientRect = rect(200, 30);
      document.body.innerHTML = `<form><input id="a"><input id="b" style="display:none"><div style="opacity:0"><input id="c"></div><div style="visibility:hidden"><input id="d"></div></form>`;
      const v = extractFeatures(document).forms[0]!.fields.map((f) => f.visibility);
      expect(v).toEqual(["visible", "display_none", "opacity", "display_none"]);
      expect(extractFeatures(document).forms[0]!.fields[0]).toMatchObject({ width: 200, height: 30 });
      Element.prototype.getBoundingClientRect = rect(0, 0);
      expect(extractFeatures(document).forms[0]!.fields[0]!.visibility).toBe("zero_size");
      Element.prototype.getBoundingClientRect = rect(200, 30, -5000, 0);
      expect(extractFeatures(document).forms[0]!.fields[0]!.visibility).toBe("offscreen");
    });
  });

  it("is self-contained: the serialized source runs without module scope", () => {
    const rebuilt = new Function(`return (${extractFeatures.toString()})`)() as typeof extractFeatures;
    const doc = load("login-floating-label.html");
    expect(rebuilt(doc)).toEqual(extractFeatures(doc));
  });
});
