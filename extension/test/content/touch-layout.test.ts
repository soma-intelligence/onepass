// Touch layout of the in-page UI (fix batch B, 2026-11-04): a live layout (IPAD-01), no menu on a
// bare tap into a field on a touch screen (IOSSAF-08), an icon on address-only and card-detail
// forms (IOSSAF-11, MS-07), and the worker's replay of a tap that met a locked vault (IOSSAF-02).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Layout } from "../../src/content/frames";
import type { PageAnalysis } from "../../src/shared/messages";
import { EXT_BASE, flush, input, setPage, start, type Started, TOKEN, userClick } from "./harness";

const ORIGIN = "https://atlas-cloud.test";
const SALT = "ab".repeat(32);
const LOGIN = `
<form id="login">
  <input id="u" name="username" autocomplete="username">
  <input id="p" type="password" autocomplete="current-password">
  <button id="go" type="submit">Sign in</button>
</form>`;

let s: Started | null = null;
beforeEach(() => {
  s = null;
});
afterEach(() => {
  s?.cs.stop();
});

const icons = (st: Started) => Array.from(st.cs.internals.root.querySelectorAll<HTMLElement>(".icon"));

function analysis(st: Started): PageAnalysis {
  const all = st.ext.ofType("page_analysis");
  return all[all.length - 1]?.analysis as PageAnalysis;
}

/** The ref of the field element `id` in the last analysis. */
function refOf(st: Started, id: string): string {
  for (const f of analysis(st).forms) {
    for (const x of f.fields) if ((st.cs.internals.refs.get(x.ref) as HTMLElement | null)?.id === id) return x.ref;
  }
  throw new Error(`no field #${id}`);
}

/** The worker: a salt, a plan outcome, a menu URL. */
function worker(st: Started, outcome: string) {
  st.ext.reply = (m) => {
    switch ((m as { type: string }).type) {
      case "fill_salt":
        return { ok: { salt: SALT } };
      case "plan_context":
        return { ok: { outcome } };
      case "open_menu":
        return { ok: { url: `${EXT_BASE}menu.html#${TOKEN}` } };
      default:
        return { ok: null };
    }
  };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 4; i++) {
    await flush();
    await new Promise((r) => setTimeout(r, 0));
  }
}

describe("touch layout", () => {
  it("IOSSAF-08: on a touch screen a tap into an empty field opens nothing; the icon is one tap to fill", async () => {
    setPage(LOGIN);
    s = start(undefined, { layout: () => ({ touch: true, sheet: true }) });
    worker(s, "filled");
    await settle();
    userClick(input("u"));
    await settle();
    expect(s.ext.ofType("open_menu")).toHaveLength(0);
    expect(s.cs.internals.root.querySelector("iframe")).toBeNull();
    userClick(icons(s)[0]!);
    await settle();
    expect(s.ext.ofType("plan_context")).toHaveLength(1);
    expect(s.ext.ofType("open_menu")).toHaveLength(0);
  });

  it("a mouse (desktop) keeps the menu on a click into an empty field", async () => {
    setPage(LOGIN);
    s = start(undefined, { layout: () => ({ touch: false, sheet: false }) });
    worker(s, "filled");
    await settle();
    userClick(input("u"));
    await settle();
    expect(s.ext.ofType("open_menu")).toEqual([expect.objectContaining({ auto: true })]);
  });

  it("IPAD-01: the icons follow a change of layout mid-page (finger-sized, label on focus)", async () => {
    setPage(LOGIN);
    let now: Layout = { touch: false, sheet: false };
    s = start(undefined, { layout: () => now });
    await settle();
    expect(icons(s).every((i) => !i.classList.contains("touch"))).toBe(true);
    expect(s.cs.internals.root.querySelector(".tip")).toBeNull();
    now = { touch: true, sheet: false };
    window.dispatchEvent(new Event("resize"));
    await settle();
    expect(icons(s).every((i) => i.classList.contains("touch"))).toBe(true);
    input("u").dispatchEvent(new FocusEvent("focusin", { bubbles: true }));
    const tip = s.cs.internals.root.querySelector<HTMLElement>(".tip");
    expect(tip?.hidden).toBe(false);
    now = { touch: false, sheet: false };
    window.dispatchEvent(new Event("resize"));
    await settle();
    expect(icons(s).every((i) => !i.classList.contains("touch"))).toBe(true);
    expect(tip?.hidden).toBe(true);
  });
});

describe("IOSSAF-11, MS-07: icons on address-only and card-detail forms", () => {
  it("an address step without a name or an email gets one icon, on its first address field", async () => {
    setPage(`
<form id="ship">
  <input id="a1" name="address" autocomplete="address-line1">
  <input id="city" name="city" autocomplete="address-level2">
  <input id="zip" name="zip" autocomplete="postal-code">
  <input id="tel" name="phone" type="tel" autocomplete="tel">
  <button type="submit">Continue</button>
</form>`);
    s = start();
    await settle();
    const all = icons(s);
    expect(all).toHaveLength(1);
    expect(s.cs.internals.refs.get(refOf(s, "a1"))).toBe(input("a1"));
  });

  it("a checkout whose number sits in the payment provider's frame gets its icon on the name on card", async () => {
    setPage(`
<form id="pay">
  <input id="cn" name="ccname" autocomplete="cc-name">
  <input id="ce" name="ccexp" autocomplete="cc-exp">
  <button type="submit">Pay</button>
</form>`);
    s = start();
    await settle();
    expect(icons(s)).toHaveLength(1);
  });

  it("a form with a main field keeps its icons only there", async () => {
    setPage(`
<form id="id">
  <input id="gn" name="fname" autocomplete="given-name">
  <input id="a1" name="address" autocomplete="address-line1">
  <input id="zip" name="zip" autocomplete="postal-code">
  <button type="submit">Continue</button>
</form>`);
    s = start();
    await settle();
    expect(icons(s)).toHaveLength(1);
  });
});

describe("IOSSAF-02: the worker replays the tap after an unlock", () => {
  it("smart_fill with the tapped field and its origin runs that field's plan", async () => {
    setPage(LOGIN);
    s = start();
    worker(s, "filled");
    await settle();
    const ref = refOf(s, "u");
    s.ext.deliver({ type: "smart_fill", fieldRef: ref, origin: ORIGIN });
    await settle();
    const plans = s.ext.ofType("plan_context");
    expect(plans).toHaveLength(1);
    expect(plans[0]).toMatchObject({ fieldRef: ref });
  });

  it("another origin, an unknown field or another sender: nothing", async () => {
    setPage(LOGIN);
    s = start();
    worker(s, "filled");
    await settle();
    const ref = refOf(s, "u");
    s.ext.deliver({ type: "smart_fill", fieldRef: ref, origin: "https://evil.test" });
    s.ext.deliver({ type: "smart_fill", fieldRef: ref });
    s.ext.deliver({ type: "smart_fill", fieldRef: "nope", origin: ORIGIN });
    s.ext.deliver({ type: "smart_fill", fieldRef: ref, origin: ORIGIN }, { id: "other-extension" });
    await settle();
    expect(s.ext.ofType("plan_context")).toHaveLength(0);
    expect(s.ext.ofType("fill_salt")).toHaveLength(0);
  });
});

// iOS 27 Safari, keyboard up and page scrolled: client coordinates (getBoundingClientRect) follow
// the visual viewport, while position: fixed follows the layout viewport, which then starts above
// the screen (seen in the simulator: field at client top 167, fixed layer at client top -330 with
// visualViewport.offsetTop 330). A fixed icon placed at the field's client top drew 330 px too high.
describe("icons on iOS with the keyboard up and the page scrolled", () => {
  /** The fixed layer's own box as the browser reports it (jsdom reports zeros). */
  function layerAt(st: Started, left: number, top: number): void {
    const layer = st.cs.internals.root.querySelector<HTMLElement>(".layer")!;
    layer.getBoundingClientRect = () => ({ left, top, right: left, bottom: top, width: 0, height: 0, x: left, y: top, toJSON: () => ({}) }) as DOMRect;
  }
  /** Where the icon sits on the page's client coordinates, as the user sees it. */
  const onScreen = (icon: HTMLElement, origin: { left: number; top: number }) => ({
    left: parseFloat(icon.style.left) + origin.left,
    top: parseFloat(icon.style.top) + origin.top,
  });

  it("every icon sits on its own field, and follows when the layout viewport moves", async () => {
    setPage(`
<form id="signup">
  <input id="n" name="name" autocomplete="name" data-test-rect="16,100,360,44">
  <input id="e" type="email" autocomplete="email" data-test-rect="16,160,360,44">
  <input id="p" type="password" autocomplete="new-password" data-test-rect="16,220,360,44">
  <button type="submit">Create account</button>
</form>`);
    s = start(undefined, { layout: () => ({ touch: true, sheet: true }) });
    await settle();
    // The keyboard comes up and iOS scrolls the page: the visual viewport resizes.
    let origin = { left: 0, top: -330 };
    layerAt(s, origin.left, origin.top);
    window.dispatchEvent(new Event("resize"));
    await settle();
    const fields = ["n", "e", "p"].map((id) => document.getElementById(id)!);
    const placed = icons(s).filter((i) => !i.hidden);
    expect(placed.length).toBeGreaterThanOrEqual(2);
    const check = () => {
      for (const icon of icons(s!).filter((i) => !i.hidden)) {
        const at = onScreen(icon, origin);
        const centre = at.top + 28 / 2;
        // On one field, vertically centred on it, inside its right edge.
        const on = fields.filter((f) => {
          const [, y, , h] = f.getAttribute("data-test-rect")!.split(",").map(Number);
          return Math.abs(centre - (y! + h! / 2)) <= 1;
        });
        expect(on).toHaveLength(1);
        expect(at.left).toBeGreaterThan(16);
        expect(at.left + 28).toBeLessThanOrEqual(16 + 360);
      }
    };
    check();
    // iOS pans the layout viewport (keyboard animation): the next layout pass follows.
    origin = { left: 0, top: -120 };
    layerAt(s, origin.left, origin.top);
    window.dispatchEvent(new Event("resize"));
    await settle();
    check();
  });

  it("the label beside the focused field's icon follows the icon", async () => {
    setPage(`
<form id="login">
  <input id="u" name="username" autocomplete="username" data-test-rect="16,100,360,44">
  <input id="p" type="password" autocomplete="current-password" data-test-rect="16,160,360,44">
</form>`);
    s = start(undefined, { layout: () => ({ touch: true, sheet: true }) });
    await settle();
    const origin = { left: 0, top: -330 };
    layerAt(s, origin.left, origin.top);
    window.dispatchEvent(new Event("resize"));
    await settle();
    input("u").dispatchEvent(new FocusEvent("focusin", { bubbles: true }));
    await settle();
    const tip = s.cs.internals.root.querySelector<HTMLElement>(".tip")!;
    expect(tip.hidden).toBe(false);
    // 30 px above the icon, which is centred on the 44 px field at client top 100.
    expect(parseFloat(tip.style.top) + origin.top).toBe(Math.round(100 + (44 - 28) / 2) - 30);
  });
});
