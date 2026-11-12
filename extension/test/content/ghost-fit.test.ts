// Spec 3.4: the ghost fits its field, or the menu opens instead, for the first reason that holds.
import { afterEach, describe, expect, it } from "vitest";
import { fitGhost, MIN_GHOST_WIDTH } from "../../src/content/ghost-fit";
import { DESIGN_TOKENS } from "../../src/shared/design-tokens";

function field(html: string, rect = { x: 10, y: 20, width: 240, height: 36 }): HTMLInputElement {
  document.body.innerHTML = html;
  const el = document.getElementById("f") as HTMLInputElement;
  el.getBoundingClientRect = () =>
    ({ ...rect, left: rect.x, top: rect.y, right: rect.x + rect.width, bottom: rect.y + rect.height, toJSON: () => rect }) as DOMRect;
  return el;
}

/** A window double: jsdom's styles, with the frame, width and pointer the test gives. */
function view(opts: { top?: unknown; width?: number; coarse?: boolean } = {}): Window {
  const v = {
    getComputedStyle: (el: Element) => window.getComputedStyle(el),
    innerWidth: opts.width ?? 1024,
    innerHeight: 768,
    location: window.location,
    navigator: { maxTouchPoints: opts.coarse ? 5 : 0, platform: "iPhone" },
    matchMedia: (q: string) => ({ matches: opts.coarse === true && q.includes("coarse") }),
  } as Record<string, unknown>;
  v.top = opts.top ?? v;
  return v as unknown as Window;
}

const never = () => false;

afterEach(() => {
  document.body.innerHTML = "";
  delete (document as { fonts?: unknown }).fonts;
});

describe("fitGhost", () => {
  it("fits a plain field", () => {
    const f = field(
      `<input id="f" type="password" style="font-size: 15px; line-height: 20px; padding-left: 10px; padding-right: 6px; border: 0; text-align: left; font-family: Georgia, serif">`,
    );
    expect(fitGhost(f, view(), never)).toEqual({
      ok: true,
      metrics: {
        fontSize: 15,
        lineHeight: 20,
        paddingLeft: 10,
        paddingRight: 6,
        textAlign: "left",
        fontFamily: "Georgia, serif",
        box: { x: 10, y: 20, width: 240, height: 36 },
      },
    });
  });

  it("a web font of the page is not the ghost's: the system font instead", () => {
    Object.defineProperty(document, "fonts", { configurable: true, value: new Set([{ family: '"Brand Sans"' }]) });
    const f = field(`<input id="f" type="password" style="font-size: 13px; font-family: 'Brand Sans', sans-serif">`);
    const r = fitGhost(f, view(), never);
    expect(r.ok && r.metrics.fontFamily).toBeNull();
  });

  it("start and end alignments follow the direction; normal line height from the font size", () => {
    const f = field(`<input id="f" style="direction: rtl; font-size: 10px; text-align: start">`);
    const r = fitGhost(f, view(), never);
    expect(r.ok && r.metrics.textAlign).toBe("right");
    expect(r.ok && r.metrics.lineHeight).toBe(12);
  });

  it("width 119 gives narrow", () => {
    expect(MIN_GHOST_WIDTH).toBe(120);
    const f = field(`<input id="f" type="password">`, { x: 0, y: 0, width: 119, height: 30 });
    expect(fitGhost(f, view(), never)).toEqual({ ok: false, reason: "narrow" });
  });

  it("a field that leaves too little room for the text beside the pill gives narrow (lab pass6 site 93)", () => {
    const pill = parseFloat(DESIGN_TOKENS.light["ghost-pill-max"]!);
    const gap = parseFloat(DESIGN_TOKENS.light["space-xs"]!);
    const minText = parseFloat(DESIGN_TOKENS.light["ghost-text-min"]!);
    expect([pill, gap, minText].every((n) => Number.isFinite(n) && n > 0)).toBe(true);
    // 125 px: past MIN_GHOST_WIDTH, but the pill covers nearly all of it.
    const f = field(`<input id="f" type="password" style="padding: 1px 2px; border: 1px solid">`, { x: 0, y: 0, width: 125, height: 30 });
    expect(fitGhost(f, view(), never)).toEqual({ ok: false, reason: "narrow" });
    // The insets count: exactly enough room fits, one px less does not.
    const html = `<input id="f" type="password" style="padding: 0 6px 0 10px; border: 0">`;
    const room = 16 + gap + pill + minText;
    expect(fitGhost(field(html, { x: 0, y: 0, width: room, height: 30 }), view(), never).ok).toBe(true);
    expect(fitGhost(field(html, { x: 0, y: 0, width: room - 1, height: 30 }), view(), never)).toEqual({ ok: false, reason: "narrow" });
    // A wide field keeps the ghost.
    expect(fitGhost(field(html, { x: 0, y: 0, width: 280, height: 36 }), view(), never).ok).toBe(true);
  });

  it("a rotation on an ancestor gives transform, a translation is fine", () => {
    let f = field(`<div style="transform: rotate(2deg)"><p><input id="f" type="password"></p></div>`);
    expect(fitGhost(f, view(), never)).toEqual({ ok: false, reason: "transform" });
    f = field(`<div style="transform: translateX(4px)"><input id="f" type="password"></div>`);
    expect(fitGhost(f, view(), never).ok).toBe(true);
    f = field(`<div style="transform: matrix(1, 0, 0, 1, 12, 4)"><input id="f" type="password"></div>`);
    expect(fitGhost(f, view(), never).ok).toBe(true);
    f = field(`<div style="transform: matrix(1.2, 0, 0, 1.2, 0, 0)"><input id="f" type="password"></div>`);
    expect(fitGhost(f, view(), never)).toEqual({ ok: false, reason: "transform" });
    f = field(`<input id="f" type="password" style="scale: 1.1">`);
    expect(fitGhost(f, view(), never)).toEqual({ ok: false, reason: "transform" });
  });

  it("text-indent: 10px gives indent", () => {
    const f = field(`<input id="f" type="password" style="text-indent: 10px">`);
    expect(fitGhost(f, view(), never)).toEqual({ ok: false, reason: "indent" });
  });

  it("occluded gives covered", () => {
    const f = field(`<input id="f" type="password">`);
    expect(fitGhost(f, view(), (el) => el === f)).toEqual({ ok: false, reason: "covered" });
  });

  it("a field in a cross-origin child frame gives cross_origin", () => {
    const f = field(`<input id="f" type="password">`);
    const foreign = {
      get location(): never {
        throw new DOMException("Blocked a frame", "SecurityError");
      },
    };
    expect(fitGhost(f, view({ top: foreign }), never)).toEqual({ ok: false, reason: "cross_origin" });
    // A same-origin child frame keeps the ghost.
    expect(fitGhost(f, view({ top: { location: window.location } }), never).ok).toBe(true);
  });

  it("a coarse pointer gives touch (the pill cannot be tapped through the pass-through)", () => {
    const f = field(`<input id="f" type="password">`);
    expect(fitGhost(f, view({ width: 1024, coarse: true }), never)).toEqual({ ok: false, reason: "touch" });
    // A 599 px touch layout (the sheet) is a touch layout first.
    expect(fitGhost(f, view({ width: 599, coarse: true }), never)).toEqual({ ok: false, reason: "touch" });
    expect(fitGhost(f, view({ width: 599 }), never).ok).toBe(true);
  });

  it("a scaled shadow host above the field gives transform", () => {
    document.body.innerHTML = `<div id="host" style="transform: scale(1.1)"></div>`;
    const host = document.getElementById("host")!;
    const sr = host.attachShadow({ mode: "open" });
    sr.innerHTML = `<span><input id="f" type="password"></span>`;
    const f = sr.getElementById("f") as HTMLInputElement;
    f.getBoundingClientRect = () => ({ x: 0, y: 0, left: 0, top: 0, width: 240, height: 36, right: 240, bottom: 36, toJSON: () => ({}) }) as DOMRect;
    expect(fitGhost(f, view(), never)).toEqual({ ok: false, reason: "transform" });
    host.style.transform = "translateY(2px)";
    expect(fitGhost(f, view(), never).ok).toBe(true);
  });

  it("the borders count in the text's start and end (the grey text starts at the caret)", () => {
    const f = field(`<input id="f" type="password" style="padding-left: 10px; border-left: 3px solid; padding-right: 6px; border-right: 2px solid">`);
    const r = fitGhost(f, view(), never);
    expect(r.ok && [r.metrics.paddingLeft, r.metrics.paddingRight]).toEqual([13, 8]);
  });

  it("checks the reasons in order: narrow, touch, transform, indent, covered, cross_origin, sheet", () => {
    const foreign = {
      get location(): never {
        throw new DOMException("Blocked a frame", "SecurityError");
      },
    };
    const html = `<div style="transform: rotate(2deg)"><input id="f" type="password" style="text-indent: 4px"></div>`;
    const narrow = { x: 0, y: 0, width: 80, height: 30 };
    const wide = { x: 0, y: 0, width: 240, height: 30 };
    // Every rule true: the first wins; then each rule dropped in turn hands over to the next.
    expect(fitGhost(field(html, narrow), view({ width: 599, coarse: true, top: foreign }), () => true)).toEqual({ ok: false, reason: "narrow" });
    expect(fitGhost(field(html, wide), view({ width: 599, coarse: true, top: foreign }), () => true)).toEqual({ ok: false, reason: "touch" });
    expect(fitGhost(field(html, wide), view({ top: foreign }), () => true)).toEqual({ ok: false, reason: "transform" });
    const flat = `<div><input id="f" type="password" style="text-indent: 4px"></div>`;
    expect(fitGhost(field(flat, wide), view({ top: foreign }), () => true)).toEqual({ ok: false, reason: "indent" });
    const plain = `<div><input id="f" type="password"></div>`;
    expect(fitGhost(field(plain, wide), view({ top: foreign }), () => true)).toEqual({ ok: false, reason: "covered" });
    expect(fitGhost(field(plain, wide), view({ top: foreign }), never)).toEqual({ ok: false, reason: "cross_origin" });
    // "sheet" is a touch layout, already caught by "touch": it stays last, for a layout that says sheet without touch.
    expect(fitGhost(field(plain, wide), view(), never).ok).toBe(true);
  });
});
