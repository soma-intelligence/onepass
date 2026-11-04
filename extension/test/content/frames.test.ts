import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  checkFrameUrl,
  createFrames,
  createShell,
  FRAME_HEIGHT,
  FRAME_MIN_HEIGHT,
  MOVE_GUARD_MS,
  type Layout,
  readLayout,
  REVEAL_TIMEOUT_MS,
  SHEET_HEIGHT,
  SHEET_MAX_WIDTH,
  type Shell,
  watchLayout,
} from "../../src/content/frames";
import { testGeometry } from "../detect/helpers";
import { flush, setPage, start, type Started } from "./harness";

const TOKEN = "AAAAAAAAAAAAAAAAAAAAAA";
const CHROME = "chrome-extension://onepassextensionid/";
const MOZ = "moz-extension://4b0c2f8e-0000-4000-8000-000000000001/";
/** iPhone, Slide Over: the bottom sheet. iPad: the popover, finger-sized. */
const PHONE: Layout = { touch: true, sheet: true };
const IPAD: Layout = { touch: true, sheet: false };

/** Runs `fn` with a fake visual viewport. */
function withViewport(vv: { offsetTop: number; offsetLeft?: number; height: number }, fn: () => void): void {
  const desc = Object.getOwnPropertyDescriptor(window, "visualViewport");
  Object.defineProperty(window, "visualViewport", { configurable: true, get: () => vv });
  try {
    fn();
  } finally {
    if (desc) Object.defineProperty(window, "visualViewport", desc);
    else delete (window as { visualViewport?: unknown }).visualViewport;
  }
}

describe("checkFrameUrl", () => {
  it("accepts our own extension pages", () => {
    expect(checkFrameUrl(`${CHROME}menu.html#${TOKEN}`, "menu", CHROME, false)).toBe(`${CHROME}menu.html#${TOKEN}`);
    expect(checkFrameUrl(`${MOZ}save.html#${TOKEN}`, "save", MOZ, false)).toBe(`${MOZ}save.html#${TOKEN}`);
  });

  it("refuses a foreign extension URL", () => {
    // Another scheme than ours, even vouched.
    expect(checkFrameUrl(`moz-extension://evil/menu.html#${TOKEN}`, "menu", CHROME, true)).toBeNull();
    expect(checkFrameUrl(`safari-web-extension://evil/menu.html#${TOKEN}`, "menu", CHROME, true)).toBeNull();
    // Another host without a dynamic URL scheme (Firefox), even vouched.
    expect(checkFrameUrl(`moz-extension://evil/menu.html#${TOKEN}`, "menu", MOZ, true)).toBeNull();
    // Chromium: another host only when it is the very URL the worker returned.
    expect(checkFrameUrl(`chrome-extension://otherextension/menu.html#${TOKEN}`, "menu", CHROME, false)).toBeNull();
    expect(checkFrameUrl(`chrome-extension://dynamicguid/menu.html#${TOKEN}`, "menu", CHROME, true)).toBe(
      `chrome-extension://dynamicguid/menu.html#${TOKEN}`,
    );
  });

  it("refuses wrong pages, queries, credentials and fragments", () => {
    for (const url of [
      `${CHROME}save.html#${TOKEN}`,
      `${CHROME}menu.html?x=1#${TOKEN}`,
      `${CHROME}menu.html#short`,
      `${CHROME}menu.html`,
      `chrome-extension://u:p@onepassextensionid/menu.html#${TOKEN}`,
    ]) {
      expect(checkFrameUrl(url, "menu", CHROME, true)).toBeNull();
    }
  });
});

describe("shell placement", () => {
  let shell: Shell | null = null;
  let st: Started | null = null;

  beforeEach(() => {
    setPage(`<div id="box"></div>`);
  });

  afterEach(() => {
    shell?.destroy();
    shell = null;
    st?.cs.stop();
    st = null;
    vi.useRealTimers();
  });

  const host = () => document.documentElement.querySelector("onepass-root");

  it("moves a re-parented host back under <html>", () => {
    shell = createShell(document);
    document.getElementById("box")!.appendChild(host()!);
    expect(shell.ensureAttached()).toBe(true);
    expect(host()!.parentElement).toBe(document.documentElement);
    expect(shell.ensureAttached()).toBe(false);
  });

  it("re-appends itself after a later sibling", () => {
    shell = createShell(document);
    document.documentElement.appendChild(document.createElement("div"));
    expect(document.documentElement.lastElementChild).not.toBe(host());
    shell.ensureAttached();
    expect(document.documentElement.lastElementChild).toBe(host());
  });

  it("restores itself through the page observer", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    st = start();
    document.getElementById("box")!.appendChild(host()!);
    await flush();
    expect(host()!.parentElement).toBe(document.documentElement);
    const cover = document.createElement("div");
    document.documentElement.appendChild(cover);
    await flush();
    expect(document.documentElement.lastElementChild).toBe(host());
  });

  it("frames follow the system appearance, whatever the page declares, and carry no tooltip", () => {
    setPage(`<meta name="color-scheme" content="light"><input id="f" data-test-rect="10,10,200,30">`);
    shell = createShell(document);
    const frames = createFrames({ shell, doc: document, geometry: testGeometry });
    frames.showFrame("menu", `${CHROME}menu.html#${TOKEN}`, document.getElementById("f"));
    const iframe = shell.root.querySelector("iframe")!;
    // A frame of "normal" scheme takes the page's (a page that says "light" turned the menu
    // light on a dark Mac, and painted an opaque white backdrop under the dark pill).
    const css = shell.root.querySelector("style")!.textContent!;
    const rule = /iframe \{[^}]*\}/.exec(css)?.[0] ?? "";
    expect(rule).toMatch(/color-scheme:\s*light dark/);
    // A `title` shows as a "OnePass" tooltip over the frame's corner: named for assistive tech only.
    expect(iframe.hasAttribute("title")).toBe(false);
    expect(iframe.getAttribute("aria-label")).toBe("OnePass");
    frames.destroy();
  });

  it("narrow touch screen: the menu is a bottom sheet, centered and capped in width, tall enough for the unlock sheet", () => {
    setPage(`<input id="f" data-test-rect="10,10,200,30">`);
    shell = createShell(document);
    const frames = createFrames({ shell, doc: document, geometry: testGeometry, layout: () => PHONE });
    frames.showFrame("menu", `${CHROME}menu.html#${TOKEN}`, document.getElementById("f"));
    const iframe = shell.root.querySelector("iframe")!;
    frames.resize("menu", 500);
    expect(iframe.classList.contains("sheet")).toBe(true);
    const width = Math.min(window.innerWidth, SHEET_MAX_WIDTH);
    expect(iframe.style.width).toBe(`${width}px`);
    expect(iframe.style.left).toBe(`${Math.round((window.innerWidth - width) / 2)}px`);
    expect(iframe.style.height).toBe(`${Math.min(500, SHEET_HEIGHT)}px`);
    expect(iframe.style.top).toBe(`${Math.max(0, window.innerHeight - 500)}px`);
    // The save prompt and the overlay keep their places.
    frames.showFrame("save", `${CHROME}save.html#${TOKEN}`);
    expect(shell.root.querySelectorAll("iframe.sheet")).toHaveLength(1);
    frames.destroy();
  });

  it("touch screen: the sheet sits on top of the keyboard (the visual viewport), not under it", () => {
    setPage(`<input id="f" data-test-rect="10,10,200,30">`);
    const vv = { offsetTop: 40, height: 400 };
    const desc = Object.getOwnPropertyDescriptor(window, "visualViewport");
    Object.defineProperty(window, "visualViewport", { configurable: true, get: () => vv });
    try {
      shell = createShell(document);
      const frames = createFrames({ shell, doc: document, geometry: testGeometry, layout: () => PHONE });
      frames.showFrame("menu", `${CHROME}menu.html#${TOKEN}`, document.getElementById("f"));
      const iframe = shell.root.querySelector("iframe")!;
      frames.resize("menu", 300);
      expect(iframe.style.top).toBe("140px");
      expect(iframe.style.height).toBe("300px");
      // Taller than what is visible (the field scrolled out of sight above): capped to the visible part.
      frames.resize("menu", 500);
      expect(iframe.style.top).toBe("40px");
      expect(iframe.style.height).toBe("400px");
      // The keyboard goes away: the sheet follows on reposition.
      vv.offsetTop = 0;
      vv.height = 700;
      frames.reposition();
      expect(iframe.style.top).toBe("200px");
      expect(iframe.style.height).toBe("500px");
      frames.destroy();
    } finally {
      if (desc) Object.defineProperty(window, "visualViewport", desc);
      else delete (window as { visualViewport?: unknown }).visualViewport;
    }
  });

  it("touch screen: the save card sits centered at the top of the visible part of the page", () => {
    const vv = { offsetTop: 120, height: 400 };
    const desc = Object.getOwnPropertyDescriptor(window, "visualViewport");
    Object.defineProperty(window, "visualViewport", { configurable: true, get: () => vv });
    try {
      shell = createShell(document);
      const frames = createFrames({ shell, doc: document, geometry: testGeometry, layout: () => PHONE, occupants: () => [] });
      frames.showFrame("save", `${CHROME}save.html#${TOKEN}`);
      const iframe = shell.root.querySelector("iframe")!;
      const width = Math.min(340, window.innerWidth - 24);
      expect(iframe.style.top).toBe("132px");
      expect(iframe.style.width).toBe(`${width}px`);
      expect(iframe.style.left).toBe(`${Math.max(12, Math.round((window.innerWidth - width) / 2))}px`);
      expect(iframe.classList.contains("sheet")).toBe(false);
      // The page scrolled (or the keyboard went away): the card follows the visible top.
      vv.offsetTop = 0;
      frames.reposition();
      expect(iframe.style.top).toBe("12px");
      frames.destroy();
    } finally {
      if (desc) Object.defineProperty(window, "visualViewport", desc);
      else delete (window as { visualViewport?: unknown }).visualViewport;
    }
  });

  it("IPAD-02: the sheet never covers its field; a field sitting low gets the menu above it", () => {
    setPage(`<input id="f" data-test-rect="10,100,200,30">`);
    withViewport({ offsetTop: 0, height: 400 }, () => {
      shell = createShell(document);
      const frames = createFrames({ shell, doc: document, geometry: testGeometry, layout: () => PHONE });
      const field = document.getElementById("f")!;
      frames.showFrame("menu", `${CHROME}menu.html#${TOKEN}`, field);
      const iframe = shell.root.querySelector("iframe")!;
      // The unlock sheet asks 500 px; 266 px are left under the field: the sheet stops there.
      frames.resize("menu", 500);
      expect(iframe.classList.contains("sheet")).toBe(true);
      expect(iframe.style.top).toBe("134px");
      expect(iframe.style.height).toBe("266px");
      expect(parseFloat(iframe.style.top)).toBeGreaterThanOrEqual(130);
      // iPad mini in landscape, keyboard up: the field just above the keyboard. Above it, then.
      field.setAttribute("data-test-rect", "10,330,200,30");
      frames.reposition();
      expect(iframe.classList.contains("sheet")).toBe(false);
      expect(iframe.style.height).toBe("326px");
      expect(iframe.style.top).toBe("0px");
      expect(parseFloat(iframe.style.top) + parseFloat(iframe.style.height)).toBeLessThanOrEqual(330);
      // A field filling what is visible: the smallest sheet rather than none.
      field.setAttribute("data-test-rect", "10,0,200,400");
      frames.reposition();
      expect(iframe.style.height).toBe(`${FRAME_MIN_HEIGHT}px`);
      // Content shorter than the room under the field: a sheet of its own height, on the keyboard.
      field.setAttribute("data-test-rect", "10,100,200,30");
      frames.resize("menu", 150);
      expect(iframe.classList.contains("sheet")).toBe(true);
      expect(iframe.style.top).toBe("250px");
      frames.destroy();
    });
  });

  it("IPAD-01: a wide touch screen gets the popover under its field, finger-sized, never a full-width sheet", () => {
    setPage(`<input id="f" data-test-rect="40,100,300,30">`);
    shell = createShell(document);
    const frames = createFrames({ shell, doc: document, geometry: testGeometry, layout: () => IPAD });
    frames.showFrame("menu", `${CHROME}menu.html#${TOKEN}`, document.getElementById("f"));
    const iframe = shell.root.querySelector("iframe")!;
    frames.resize("menu", 200);
    expect(iframe.classList.contains("sheet")).toBe(false);
    expect(iframe.style.width).toBe("380px");
    expect(iframe.style.left).toBe("40px");
    expect(iframe.style.top).toBe("134px");
    frames.destroy();
  });

  it("IPAD-01, IPAD-04: the iPad popover stays inside what the user sees, above the field when the keyboard leaves no room below", () => {
    setPage(`<input id="f" data-test-rect="40,300,300,30">`);
    withViewport({ offsetTop: 0, height: 400 }, () => {
      shell = createShell(document);
      const frames = createFrames({ shell, doc: document, geometry: testGeometry, layout: () => IPAD });
      frames.showFrame("menu", `${CHROME}menu.html#${TOKEN}`, document.getElementById("f"));
      const iframe = shell.root.querySelector("iframe")!;
      frames.resize("menu", 200);
      // 54 px below the field, 284 above: above it, whole.
      expect(iframe.style.top).toBe("96px");
      expect(iframe.style.height).toBe("200px");
      // Taller than either side: the larger side, capped; the field stays uncovered.
      frames.resize("menu", 400);
      expect(iframe.style.height).toBe("284px");
      expect(parseFloat(iframe.style.top) + parseFloat(iframe.style.height)).toBeLessThanOrEqual(300);
      frames.destroy();
    });
  });

  it("IPAD-01: the layout is read live; a trackpad or Slide Over changes it mid-page", () => {
    setPage(`<input id="f" data-test-rect="40,100,300,30">`);
    shell = createShell(document);
    let now: Layout = IPAD;
    const frames = createFrames({ shell, doc: document, geometry: testGeometry, layout: () => now });
    frames.showFrame("menu", `${CHROME}menu.html#${TOKEN}`, document.getElementById("f"));
    const iframe = shell.root.querySelector("iframe")!;
    frames.resize("menu", 200);
    expect(iframe.classList.contains("sheet")).toBe(false);
    // Slide Over: narrow, the sheet, as tall as the unlock sheet asks.
    now = PHONE;
    frames.resize("menu", 520);
    expect(iframe.classList.contains("sheet")).toBe(true);
    expect(iframe.style.height).toBe("520px");
    // Wide again: the popover's own largest height.
    now = IPAD;
    frames.reposition();
    expect(iframe.style.height).toBe(`${FRAME_HEIGHT.menu}px`);
    // A mouse layout: the desktop dropdown again.
    now = { touch: false, sheet: false };
    frames.resize("menu", 200);
    expect(iframe.classList.contains("sheet")).toBe(false);
    expect(iframe.style.top).toBe("134px");
    frames.destroy();
  });

  it("readLayout and watchLayout: touch from a coarse pointer (any pointer on an iPad), the sheet only on a narrow window", () => {
    const listeners = new Map<string, () => void>();
    let coarse = { primary: true, any: true };
    let width = 375;
    const nav = { maxTouchPoints: 5, platform: "MacIntel" };
    const view = {
      navigator: nav,
      get innerWidth() {
        return width;
      },
      matchMedia: (q: string) => ({
        matches: q === "(pointer: coarse)" ? coarse.primary : q === "(any-pointer: coarse)" ? coarse.any : !coarse.primary,
        addEventListener: (_t: string, cb: () => void) => void listeners.set(q, cb),
        removeEventListener: () => void listeners.delete(q),
      }),
      addEventListener: (t: string, cb: () => void) => void listeners.set(`window:${t}`, cb),
      removeEventListener: (t: string) => void listeners.delete(`window:${t}`),
    } as unknown as Window;
    expect(readLayout(view)).toEqual({ touch: true, sheet: true });
    const w = watchLayout(view);
    let changes = 0;
    w.onChange(() => changes++);
    // iPad width: popover, still touch.
    width = 1024;
    listeners.get("window:resize")!();
    expect(w.current()).toEqual({ touch: true, sheet: false });
    // A trackpad on the iPad: the primary pointer turns fine, the touch screen stays.
    coarse = { primary: false, any: true };
    listeners.get("(pointer: coarse)")!();
    expect(w.current()).toEqual({ touch: true, sheet: false });
    // The same media on a Windows touch laptop, mouse first: the desktop layout.
    nav.platform = "Win32";
    expect(readLayout(view)).toEqual({ touch: false, sheet: false });
    nav.platform = "MacIntel";
    // A Mac: no coarse pointer at all.
    coarse = { primary: false, any: false };
    listeners.get("(any-pointer: coarse)")!();
    expect(w.current()).toEqual({ touch: false, sheet: false });
    expect(changes).toBe(2);
    w.destroy();
    expect(listeners.size).toBe(0);
    expect(readLayout(null)).toEqual({ touch: false, sheet: false });
  });

  it("IOSSAF-12: on a touch screen the overlay sits at the top of what the user sees", () => {
    setPage(`<input id="f" data-test-rect="40,500,200,30">`);
    withViewport({ offsetTop: 300, height: 400 }, () => {
      shell = createShell(document);
      const frames = createFrames({ shell, doc: document, geometry: testGeometry, layout: () => PHONE });
      frames.showFrame("overlay", `${CHROME}overlay.html#${TOKEN}`, document.getElementById("f"));
      const iframe = shell.root.querySelector("iframe")!;
      frames.resize("overlay", 120);
      expect(iframe.style.top).toBe("312px");
      frames.destroy();
    });
  });

  it("IOSSAF-09: a sheet that keeps its place on the screen while the visual viewport pans is not guarded again; a move on the screen is", () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    // The field scrolled away below: the sheet takes the visible bottom.
    setPage(`<input id="f" data-test-rect="10,2000,200,30">`);
    const vv = { offsetTop: 0, height: 400 };
    withViewport(vv, () => {
      shell = createShell(document);
      const frames = createFrames({ shell, doc: document, geometry: testGeometry, layout: () => PHONE });
      frames.showFrame("menu", `${CHROME}menu.html#${TOKEN}`, document.getElementById("f"));
      const iframe = shell.root.querySelector("iframe")!;
      frames.resize("menu", 200);
      expect(iframe.style.pointerEvents).toBe("none");
      vi.advanceTimersByTime(MOVE_GUARD_MS);
      expect(iframe.style.pointerEvents).toBe("");
      // iOS pans the page under the keyboard, a few pixels a frame: same place on the screen, no guard.
      for (const y of [12, 24, 36, 48, 60]) {
        vv.offsetTop = y;
        frames.reposition();
      }
      expect(iframe.style.top).toBe("260px");
      expect(iframe.style.pointerEvents).toBe("");
      // A page jumping the visual viewport: the frame drifted on the screen before its placement.
      vv.offsetTop = 160;
      frames.reposition();
      expect(iframe.style.top).toBe("360px");
      expect(iframe.style.pointerEvents).toBe("none");
      vi.advanceTimersByTime(MOVE_GUARD_MS);
      // A zoom: guarded too.
      (vv as { scale?: number }).scale = 1.5;
      frames.reposition();
      expect(iframe.style.pointerEvents).toBe("none");
      vi.advanceTimersByTime(MOVE_GUARD_MS);
      // The keyboard goes (a page can blur its field): the sheet slides on the screen, guarded.
      vv.height = 700;
      frames.reposition();
      expect(iframe.style.pointerEvents).toBe("none");
      frames.destroy();
    });
  });

  it("ignores clicks into a frame for 300 ms after it moves or the host comes back", () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    setPage(`<input id="f" data-test-rect="10,10,200,30">`);
    shell = createShell(document);
    const frames = createFrames({ shell, doc: document, geometry: testGeometry });
    const field = document.getElementById("f")!;
    frames.showFrame("menu", `${CHROME}menu.html#${TOKEN}`, field);
    const iframe = shell.root.querySelector("iframe")!;
    expect(iframe.style.pointerEvents).toBe("");
    // Shown once its page reported its height: appearing counts as a move.
    frames.resize("menu", 140);
    expect(iframe.style.pointerEvents).toBe("none");
    vi.advanceTimersByTime(MOVE_GUARD_MS);
    expect(iframe.style.pointerEvents).toBe("");

    // Nothing moved: no guard.
    frames.reposition();
    expect(iframe.style.pointerEvents).toBe("");

    field.setAttribute("data-test-rect", "10,200,200,30");
    frames.reposition();
    expect(iframe.style.pointerEvents).toBe("none");
    vi.advanceTimersByTime(MOVE_GUARD_MS - 1);
    expect(iframe.style.pointerEvents).toBe("none");
    vi.advanceTimersByTime(1);
    expect(iframe.style.pointerEvents).toBe("");

    document.documentElement.appendChild(document.createElement("div"));
    shell.ensureAttached();
    expect(iframe.style.pointerEvents).toBe("none");
    vi.advanceTimersByTime(MOVE_GUARD_MS);
    expect(iframe.style.pointerEvents).toBe("");

    frames.destroy();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("sizes a frame to its page's content, between bounds; shows it then, or after a delay", () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    setPage(`<input id="f" data-test-rect="10,10,200,30">`);
    shell = createShell(document);
    const frames = createFrames({ shell, doc: document, geometry: testGeometry });
    const field = document.getElementById("f")!;
    frames.showFrame("menu", `${CHROME}menu.html#${TOKEN}`, field);
    const iframe = shell.root.querySelector("iframe")!;
    // Transparent at its largest size until the page says how tall it is.
    expect(iframe.classList.contains("shown")).toBe(false);
    expect(iframe.style.height).toBe(`${FRAME_HEIGHT.menu}px`);
    frames.resize("menu", 152.4);
    expect(iframe.classList.contains("shown")).toBe(true);
    expect(iframe.style.height).toBe("152px");
    expect(iframe.style.top).toBe("44px");
    frames.resize("menu", 5);
    expect(iframe.style.height).toBe(`${FRAME_MIN_HEIGHT}px`);
    frames.resize("menu", 99_999);
    expect(iframe.style.height).toBe(`${FRAME_HEIGHT.menu}px`);
    vi.advanceTimersByTime(MOVE_GUARD_MS);
    // Smaller: nothing new under the pointer, no guard. Larger: guarded.
    frames.resize("menu", 200);
    expect(iframe.style.pointerEvents).toBe("");
    frames.resize("menu", 260);
    expect(iframe.style.pointerEvents).toBe("none");

    // A page that never reports still shows, at the fallback delay.
    frames.showFrame("overlay", `${CHROME}overlay.html#${TOKEN}`);
    const overlay = [...shell.root.querySelectorAll("iframe")].find((f) => f.src.includes("overlay"))!;
    expect(overlay.classList.contains("shown")).toBe(false);
    vi.advanceTimersByTime(REVEAL_TIMEOUT_MS);
    expect(overlay.classList.contains("shown")).toBe(true);
    frames.destroy();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("the overlay sits centered at the top of the page, whatever field started it", () => {
    setPage(`<input id="f" data-test-rect="40,500,200,30">`);
    shell = createShell(document);
    const frames = createFrames({ shell, doc: document, geometry: testGeometry });
    const field = document.getElementById("f")!;
    frames.showFrame("overlay", `${CHROME}overlay.html#${TOKEN}`, field);
    const iframe = shell.root.querySelector("iframe")!;
    frames.resize("overlay", 120);
    // jsdom's viewport is 1024 wide: centered, at the top edge.
    const width = parseFloat(iframe.style.width);
    expect(iframe.style.left).toBe(`${Math.round((1024 - width) / 2)}px`);
    expect(iframe.style.top).toBe("12px");
    expect(iframe.classList.contains("top-center")).toBe(true);
    expect(iframe.classList.contains("corner")).toBe(false);
    // The field went away: the overlay stays where it is.
    field.remove();
    frames.reposition();
    expect(shell.root.querySelector("iframe")).toBe(iframe);
    expect(iframe.style.top).toBe("12px");
    frames.destroy();
  });

  it("closing the menu while the focus is in it gives the focus back to its field", () => {
    setPage(`<input id="f" data-test-rect="10,10,200,30"><input id="g">`);
    shell = createShell(document);
    const frames = createFrames({ shell, doc: document, geometry: testGeometry });
    const field = document.getElementById("f") as HTMLInputElement;
    frames.showFrame("menu", `${CHROME}menu.html#${TOKEN}`, field);
    frames.focus("menu");
    expect(shell.root.activeElement).toBe(shell.root.querySelector("iframe"));
    frames.removeFrame("menu");
    expect(document.activeElement).toBe(field);
    // Focus elsewhere in the page: left alone.
    frames.showFrame("menu", `${CHROME}menu.html#${TOKEN}`, field);
    const other = document.getElementById("g") as HTMLInputElement;
    other.focus();
    frames.removeFrame("menu");
    expect(document.activeElement).toBe(other);
    frames.destroy();
  });
});
