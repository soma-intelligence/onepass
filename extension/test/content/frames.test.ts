import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkFrameUrl, createFrames, createShell, MOVE_GUARD_MS, type Shell } from "../../src/content/frames";
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
});
