// Other password managers' UI in the corner and in the fields (founder,
// 2026-11-03): the save card stacks beside theirs, never under nor over.
import { afterEach, describe, expect, it } from "vitest";
import { cornerOccupants, knownOccupantsIn, overlaps, stackInCorner } from "../../src/content/occupants";

const VIEW = { w: 1100, h: 720 };
const SIZE = { width: 340, height: 120 };
const START = { left: VIEW.w - 12 - SIZE.width, top: 12 };

function box(el: HTMLElement, r: { left: number; top: number; width: number; height: number }): void {
  el.getBoundingClientRect = () =>
    ({ left: r.left, top: r.top, width: r.width, height: r.height, right: r.left + r.width, bottom: r.top + r.height, x: r.left, y: r.top, toJSON() {} }) as DOMRect;
}

afterEach(() => {
  document.body.replaceChildren();
});

describe("stackInCorner", () => {
  it("keeps the corner when nothing is there", () => {
    expect(stackInCorner(START, SIZE, [], VIEW, 8, 12)).toEqual(START);
  });

  it("goes under another manager's card, a small gap between", () => {
    const theirs = { left: VIEW.w - 12 - 330, top: 12, width: 330, height: 132 };
    const p = stackInCorner(START, SIZE, [theirs], VIEW, 8, 12);
    expect(p).toEqual({ left: START.left, top: 12 + 132 + 8 });
    expect(overlaps({ ...p, ...SIZE }, theirs, 0)).toBe(false);
  });

  it("goes to the left when there is no room below", () => {
    const tall = { left: VIEW.w - 12 - 330, top: 12, width: 330, height: 640 };
    const p = stackInCorner(START, SIZE, [tall], VIEW, 8, 12);
    expect(p.top).toBe(START.top);
    expect(p.left).toBe(tall.left - 8 - SIZE.width);
    expect(overlaps({ ...p, ...SIZE }, tall, 0)).toBe(false);
  });

  it("clears two stacked cards", () => {
    const a = { left: VIEW.w - 360, top: 12, width: 348, height: 100 };
    const b = { left: VIEW.w - 360, top: 120, width: 348, height: 100 };
    const p = stackInCorner(START, SIZE, [a, b], VIEW, 8, 12);
    expect(overlaps({ ...p, ...SIZE }, a, 0)).toBe(false);
    expect(overlaps({ ...p, ...SIZE }, b, 0)).toBe(false);
  });
});

describe("cornerOccupants", () => {
  const notOurs = { isOwn: () => false };

  it("finds a known manager's notification in the corner", () => {
    const el = document.createElement("com-1password-notification");
    document.body.append(el);
    box(el, { left: 758, top: 12, width: 330, height: 132 });
    Object.defineProperty(window, "innerWidth", { value: VIEW.w, configurable: true });
    expect(cornerOccupants(document, notOurs)).toEqual([{ left: 758, top: 12, width: 330, height: 132 }]);
  });

  it("finds a generic fixed popup with a high z-index, ignores the page's own low layers", () => {
    Object.defineProperty(window, "innerWidth", { value: VIEW.w, configurable: true });
    const popup = document.createElement("div");
    popup.style.position = "fixed";
    popup.style.zIndex = "2147483000";
    const banner = document.createElement("div");
    banner.style.position = "fixed";
    banner.style.zIndex = "10";
    document.body.append(popup, banner);
    box(popup, { left: 780, top: 20, width: 300, height: 100 });
    box(banner, { left: 780, top: 20, width: 300, height: 100 });
    expect(cornerOccupants(document, notOurs)).toHaveLength(1);
  });

  it("never counts our own host", () => {
    Object.defineProperty(window, "innerWidth", { value: VIEW.w, configurable: true });
    const own = document.createElement("com-1password-notification");
    document.body.append(own);
    box(own, { left: 758, top: 12, width: 330, height: 132 });
    expect(cornerOccupants(document, { isOwn: (n) => n === own })).toEqual([]);
  });

  it("ignores a manager's UI far from the corner", () => {
    Object.defineProperty(window, "innerWidth", { value: VIEW.w, configurable: true });
    const el = document.createElement("com-1password-button");
    document.body.append(el);
    box(el, { left: 40, top: 300, width: 24, height: 24 });
    expect(cornerOccupants(document, notOurs)).toEqual([]);
  });
});

describe("knownOccupantsIn", () => {
  it("returns another manager's in-field button inside our icon zone", () => {
    const el = document.createElement("com-1password-button");
    document.body.append(el);
    box(el, { left: 400, top: 210, width: 24, height: 24 });
    const zone = { left: 380, top: 200, width: 60, height: 44 };
    expect(knownOccupantsIn(document, zone, { isOwn: () => false })).toHaveLength(1);
    expect(knownOccupantsIn(document, { left: 0, top: 0, width: 10, height: 10 }, { isOwn: () => false })).toEqual([]);
  });
});
