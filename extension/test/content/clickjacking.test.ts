// Anti-clickjacking of the in-page UI (security review H1, M1) and opaque origins (M2).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CLICK_GUARD_MS } from "../../src/shared/click-guard";
import { CLICK_GUARD_MS as UI_CLICK_GUARD_MS } from "../../src/ui/components";
import { MOVE_GUARD_MS } from "../../src/content/frames";
import { hostOnTop, rootHidden, topLayerOpen } from "../../src/content/occlusion";
import type { PageAnalysis } from "../../src/shared/messages";
import {
  EXT_BASE,
  flush,
  input,
  pastIconGuard,
  setPage,
  start,
  type Started,
  TOKEN,
  userClick,
  userClickIcon,
  userKey,
  useTimers,
} from "./harness";

const ORIGIN = "https://atlas-cloud.test";

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
  vi.useRealTimers();
  document.documentElement.style.removeProperty("opacity");
  delete (document as { fullscreenElement?: unknown }).fullscreenElement;
});

const icons = (st: Started) => Array.from(st.cs.internals.root.querySelectorAll<HTMLElement>(".icon"));
const host = () => document.querySelector("onepass-root") as HTMLElement;
const fills = (st: Started) => st.ext.ofType("fill_salt").length;

function analysis(st: Started): PageAnalysis {
  const all = st.ext.ofType("page_analysis");
  return all[all.length - 1]!.analysis as PageAnalysis;
}

/** Makes `el` the fullscreen element (top layer) of the document, as jsdom has no Fullscreen API. */
function fullscreen(el: Element | null): void {
  Object.defineProperty(document, "fullscreenElement", { value: el, configurable: true });
}

describe("field icon click guard (H1)", () => {
  it("shares the frames' delay", () => {
    expect(CLICK_GUARD_MS).toBe(UI_CLICK_GUARD_MS);
  });

  it("ignores a trusted click in the first CLICK_GUARD_MS after the icon appeared", async () => {
    setPage(LOGIN);
    s = start();
    userClick(icons(s)[0]!);
    await flush();
    expect(fills(s)).toBe(0);
    userClickIcon(icons(s)[0]!);
    await flush();
    expect(fills(s)).toBe(1);
  });

  it("re-arms the delay when the icon moves under the pointer", async () => {
    setPage(LOGIN);
    s = start();
    pastIconGuard();
    // The page moves the field (and so its icon) just before the click.
    input("u").setAttribute("data-test-rect", "300,400,200,30");
    window.dispatchEvent(new Event("resize"));
    await new Promise((r) => setTimeout(r, 5));
    userClick(icons(s)[0]!);
    await flush();
    expect(fills(s)).toBe(0);
    userClickIcon(icons(s)[0]!);
    await flush();
    expect(fills(s)).toBe(1);
  });

  it("refuses while a top-layer element is open (a popover or dialog can paint over any z-index)", async () => {
    setPage(`${LOGIN}<div id="cover">Continue</div>`);
    s = start();
    fullscreen(document.getElementById("cover"));
    userClickIcon(icons(s)[0]!);
    await flush();
    expect(fills(s)).toBe(0);
    fullscreen(null);
    userClickIcon(icons(s)[0]!);
    await flush();
    expect(fills(s)).toBe(1);
  });

  it("refuses only for a top-layer element over the icon, not one elsewhere on the page (review E3)", async () => {
    setPage(`${LOGIN}<div id="toast">Saved</div>`);
    s = start();
    const toast = document.getElementById("toast")!;
    const icon = icons(s)[0]!;
    icon.getBoundingClientRect = () => ({ left: 170, top: 5, width: 20, height: 20, right: 190, bottom: 25 }) as DOMRect;
    fullscreen(toast);
    // A toast in the far corner: the icon still works.
    toast.getBoundingClientRect = () => ({ left: 800, top: 700, width: 200, height: 50, right: 1000, bottom: 750 }) as DOMRect;
    userClickIcon(icon);
    await flush();
    expect(fills(s)).toBe(1);
    // The same element laid over the icon: refused.
    toast.getBoundingClientRect = () => ({ left: 150, top: 0, width: 100, height: 40, right: 250, bottom: 40 }) as DOMRect;
    userClickIcon(icon);
    await flush();
    expect(fills(s)).toBe(1);
  });

  it("refuses when the root element fades the page out (a decoy would show in the top layer)", async () => {
    setPage(LOGIN);
    s = start();
    document.documentElement.style.setProperty("opacity", "0.2");
    userClickIcon(icons(s)[0]!);
    await flush();
    expect(fills(s)).toBe(0);
  });

  it("refuses when the topmost element at the click point is not our host", async () => {
    setPage(`${LOGIN}<div id="cover"></div>`);
    let top: Element | null = null;
    s = start(undefined, { hitTest: () => top });
    top = document.getElementById("cover");
    userClickIcon(icons(s)[0]!);
    await flush();
    expect(fills(s)).toBe(0);
    top = host();
    userClickIcon(icons(s)[0]!);
    await flush();
    expect(fills(s)).toBe(1);
  });
});

describe("frame covers without IntersectionObserver v2 (M1)", () => {
  const showMenu = (st: Started) => {
    const field = analysis(st).forms[0]!.fields[0]!;
    st.ext.deliver({ type: "show_frame", kind: "menu", url: `${EXT_BASE}menu.html#${TOKEN}`, ref: field.ref });
    return st.cs.internals.root.querySelector("iframe") as HTMLIFrameElement;
  };

  it("makes a covered frame inert, and gives it back through the move guard once the cover is gone", () => {
    useTimers();
    setPage(`${LOGIN}<div id="cover"></div>`);
    s = start(undefined, { watchCovers: true });
    const frame = showMenu(s);
    expect(frame.hasAttribute("inert")).toBe(false);
    fullscreen(document.getElementById("cover"));
    document.dispatchEvent(new Event("toggle"));
    expect(frame.hasAttribute("inert")).toBe(true);
    expect(frame.style.getPropertyValue("pointer-events")).toBe("none");
    fullscreen(null);
    document.dispatchEvent(new Event("toggle"));
    expect(frame.hasAttribute("inert")).toBe(false);
    // Back as if it had just appeared: no pointer for MOVE_GUARD_MS.
    expect(frame.style.getPropertyValue("pointer-events")).toBe("none");
    vi.advanceTimersByTime(MOVE_GUARD_MS + 1);
    expect(frame.style.getPropertyValue("pointer-events")).toBe("");
  });

  it("blocks a frame the hit test finds covered when it takes the pointer again", () => {
    useTimers();
    setPage(`${LOGIN}<div id="cover"></div>`);
    let top: Element | null = null;
    s = start(undefined, { watchCovers: true, hitTest: () => top });
    const frame = showMenu(s);
    frame.getBoundingClientRect = () => ({ left: 10, top: 10, width: 300, height: 200 }) as DOMRect;
    s.ext.deliver({ type: "resize_frame", kind: "menu", height: 200 });
    top = document.getElementById("cover");
    vi.advanceTimersByTime(MOVE_GUARD_MS + 1);
    expect(frame.hasAttribute("inert")).toBe(true);
  });

  it("does not relay Return to a covered menu", async () => {
    setPage(`${LOGIN}<div id="cover"></div>`);
    s = start(undefined, { watchCovers: true });
    showMenu(s);
    userKey(input("u"), "ArrowDown");
    fullscreen(document.getElementById("cover"));
    userKey(input("u"), "Enter");
    await flush();
    expect(s.ext.ofType("menu_key").map((m) => m.key)).toEqual(["down"]);
    fullscreen(null);
    userKey(input("u"), "Enter");
    await flush();
    expect(s.ext.ofType("menu_key").map((m) => m.key)).toEqual(["down", "enter"]);
  });

  it("leaves frames alone where the frames have IOv2 (Chromium)", () => {
    setPage(`${LOGIN}<div id="cover"></div>`);
    s = start(undefined, { watchCovers: false });
    const frame = showMenu(s);
    fullscreen(document.getElementById("cover"));
    document.dispatchEvent(new Event("toggle"));
    expect(frame.hasAttribute("inert")).toBe(false);
  });
});

describe("occlusion helpers", () => {
  it("sees an open popover or modal dialog through the selectors, in the document or a readable root", () => {
    const el = document.createElement("div");
    const only = (want: string) => (sel: string) => (sel === want ? [el] : []);
    const doc = { fullscreenElement: null, querySelectorAll: only(":popover-open") } as unknown as Document;
    expect(topLayerOpen(doc)).toBe(true);
    const quiet = { fullscreenElement: null, querySelectorAll: () => [] } as unknown as Document;
    expect(topLayerOpen(quiet)).toBe(false);
    const root = { querySelectorAll: only(":modal") } as unknown as ParentNode;
    expect(topLayerOpen(quiet, () => [root])).toBe(true);
    // An engine that does not know the selector: nothing of that kind can be open.
    const old = { fullscreenElement: null, querySelectorAll: () => { throw new SyntaxError("unknown"); } } as unknown as Document;
    expect(topLayerOpen(old)).toBe(false);
  });

  it("with a box, counts only top-layer elements that overlap it", () => {
    const el = document.createElement("div");
    el.getBoundingClientRect = () => ({ left: 0, top: 0, width: 100, height: 100 }) as DOMRect;
    const doc = { fullscreenElement: null, querySelectorAll: (sel: string) => (sel === ":popover-open" ? [el] : []) } as unknown as Document;
    expect(topLayerOpen(doc, undefined, { left: 50, top: 50, width: 20, height: 20 })).toBe(true);
    expect(topLayerOpen(doc, undefined, { left: 200, top: 200, width: 20, height: 20 })).toBe(false);
  });

  it("flags a root element with opacity, filter, mask or clip-path", () => {
    expect(rootHidden(document)).toBe(false);
    document.documentElement.style.setProperty("opacity", "0.5");
    expect(rootHidden(document)).toBe(true);
    document.documentElement.style.removeProperty("opacity");
    document.documentElement.style.setProperty("filter", "opacity(0)");
    expect(rootHidden(document)).toBe(true);
    document.documentElement.style.removeProperty("filter");
  });

  it("trusts a hit test only when it names our host", () => {
    const own = document.createElement("onepass-root");
    const other = document.createElement("div");
    expect(hostOnTop(() => own, (e) => e === own, 5, 5)).toBe(true);
    expect(hostOnTop(() => other, (e) => e === own, 5, 5)).toBe(false);
    // No hit test in this engine, or a point off screen: nothing to tell.
    expect(hostOnTop(() => undefined, (e) => e === own, 5, 5)).toBe(true);
    expect(hostOnTop(() => null, (e) => e === own, 5, 5)).toBe(true);
  });
});

describe("opaque origin (M2)", () => {
  it("does not start in a document whose origin is opaque (sandboxed frame, CSP sandbox)", async () => {
    setPage(LOGIN);
    s = start(undefined, { opaqueOrigin: () => true });
    await flush();
    expect(host()).toBeNull();
    expect(s.ext.ofType("page_analysis")).toHaveLength(0);
    expect(s.ext.listeners).toHaveLength(0);
  });

  it("refuses a fill once the document became opaque", () => {
    setPage(LOGIN);
    let opaque = false;
    s = start(undefined, { opaqueOrigin: () => opaque });
    const form = analysis(s).forms[0]!;
    s.ext.deliver({ type: "fill", origin: ORIGIN, formRef: form.ref, values: { username: "ada" } });
    expect(input("u").value).toBe("ada");
    input("u").value = "";
    opaque = true;
    s.ext.deliver({ type: "fill", origin: ORIGIN, formRef: form.ref, values: { username: "ada", current_password: "pw" } });
    expect(input("u").value).toBe("");
    expect(input("p").value).toBe("");
  });
});
