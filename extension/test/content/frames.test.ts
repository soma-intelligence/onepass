import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  checkFrameUrl,
  createFrames,
  createShell,
  FRAME_HEIGHT,
  FRAME_MIN_HEIGHT,
  MOVE_GUARD_MS,
  REVEAL_TIMEOUT_MS,
  type Shell,
} from "../../src/content/frames";
import { testGeometry } from "../detect/helpers";
import { flush, setPage, start, type Started } from "./harness";

const TOKEN = "AAAAAAAAAAAAAAAAAAAAAA";
const CHROME = "chrome-extension://onepassextensionid/";
const MOZ = "moz-extension://4b0c2f8e-0000-4000-8000-000000000001/";

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

  it("the overlay goes under the field it was started from, else to the top right; above when no room below", () => {
    setPage(`<input id="f" data-test-rect="40,500,200,30">`);
    shell = createShell(document);
    const frames = createFrames({ shell, doc: document, geometry: testGeometry });
    const field = document.getElementById("f")!;
    frames.showFrame("overlay", `${CHROME}overlay.html#${TOKEN}`, field);
    const iframe = shell.root.querySelector("iframe")!;
    frames.resize("overlay", 120);
    // jsdom's viewport is 1024 x 768: 500 + 30 + 4 + 120 fits below.
    expect([iframe.style.left, iframe.style.top]).toEqual(["40px", "534px"]);
    frames.resize("overlay", 300);
    expect(iframe.style.top).toBe(`${500 - 4 - 300}px`);
    // The field went away (the page changed): the progress moves to the corner.
    field.remove();
    frames.reposition();
    expect(shell.root.querySelector("iframe")).toBe(iframe);
    expect(iframe.style.top).toBe("12px");
    expect(iframe.classList.contains("corner")).toBe(true);
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
