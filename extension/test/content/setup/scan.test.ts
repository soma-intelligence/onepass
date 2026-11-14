import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type Listener = (m: unknown, s: { id?: string }, r: (v: unknown) => void) => boolean | undefined;

const addListener = vi.fn();
const sendMessage = vi.fn(() => Promise.resolve());
vi.mock("../../../src/shared/browser", () => ({
  ext: { runtime: { id: "me", sendMessage, onMessage: { addListener } } },
}));

const RealMO = globalThis.MutationObserver;
let observers: { disconnected: boolean }[] = [];

class TrackedMO extends RealMO {
  disconnected = false;
  constructor(cb: MutationCallback) {
    super(cb);
    observers.push(this);
  }
  override disconnect(): void {
    this.disconnected = true;
    super.disconnect();
  }
}

const codesHtml = () =>
  `<h2>Recovery codes</h2><ul>${Array.from({ length: 8 }, (_, i) => `<li>ab${i}cd-ef${i}gh</li>`).join("")}</ul>`;

async function load(): Promise<Listener> {
  vi.resetModules();
  addListener.mockClear();
  await import("../../../src/content/setup/scan");
  return addListener.mock.calls[0]![0] as Listener;
}

beforeEach(() => {
  vi.useFakeTimers();
  observers = [];
  sendMessage.mockClear();
  globalThis.MutationObserver = TrackedMO as unknown as typeof MutationObserver;
  delete (window as unknown as Record<string, unknown>).__onepass_setup_scan__;
  document.title = "";
  document.body.innerHTML = "";
});
afterEach(() => {
  for (const o of observers) (o as unknown as MutationObserver).disconnect();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  globalThis.MutationObserver = RealMO;
});

describe("scan.ts", () => {
  it("importing twice registers the listener once", async () => {
    await load();
    await import("../../../src/content/setup/scan");
    vi.resetModules();
    await import("../../../src/content/setup/scan");
    expect(addListener).toHaveBeenCalledTimes(1);
    expect(Object.keys(window)).not.toContain("__onepass_setup_scan__");
  });

  it("a foreign sender.id gets no response", async () => {
    const l = await load();
    const respond = vi.fn();
    expect(l({ type: "setup_watch_codes", ms: 1000 }, { id: "evil" }, respond)).toBeUndefined();
    expect(l({ type: "setup_scan_dom" }, {}, respond)).toBeUndefined();
    expect(respond).not.toHaveBeenCalled();
    expect(observers).toHaveLength(0);
  });

  it("the watcher sends exactly one message and disconnects after a match", async () => {
    document.body.innerHTML = codesHtml();
    const l = await load();
    const respond = vi.fn();
    l({ type: "setup_watch_codes", ms: 10_000 }, { id: "me" }, respond);
    expect(respond).toHaveBeenCalledWith({ ok: true });
    await vi.advanceTimersByTimeAsync(600);
    document.body.appendChild(document.createElement("p"));
    await vi.advanceTimersByTimeAsync(5000);
    expect(sendMessage).toHaveBeenCalledTimes(1);
    const arg = (sendMessage.mock.calls[0] as unknown[])[0] as { type: string; codes: string[] };
    expect(arg.type).toBe("setup_codes_found");
    expect(arg.codes).toHaveLength(8);
    expect(observers[0]!.disconnected).toBe(true);
  });

  it("the watcher disconnects at ms with no message", async () => {
    document.body.innerHTML = "<p>nothing here</p>";
    const l = await load();
    l({ type: "setup_watch_codes", ms: 3000 }, { id: "me" }, vi.fn());
    await vi.advanceTimersByTimeAsync(3100);
    expect(observers[0]!.disconnected).toBe(true);
    document.body.innerHTML = codesHtml();
    await vi.advanceTimersByTimeAsync(2000);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("a second watch call leaves one observer", async () => {
    const l = await load();
    l({ type: "setup_watch_codes", ms: 5000 }, { id: "me" }, vi.fn());
    l({ type: "setup_watch_codes", ms: 5000 }, { id: "me" }, vi.fn());
    expect(observers.filter((o) => !o.disconnected)).toHaveLength(1);
  });

  it("a page that never settles is still checked within the max wait", async () => {
    document.body.innerHTML = "<p>x</p>";
    const l = await load();
    l({ type: "setup_watch_codes", ms: 60_000 }, { id: "me" }, vi.fn());
    await vi.advanceTimersByTimeAsync(600); // first check: nothing
    document.body.innerHTML = codesHtml();
    for (let i = 0; i < 12; i++) {
      document.body.appendChild(document.createElement("i"));
      await vi.advanceTimersByTimeAsync(300);
    }
    expect(sendMessage).toHaveBeenCalledTimes(1);
  });

  it("a CSS background that is not data: or blob: is never loaded, a data: one is", async () => {
    const srcs: string[] = [];
    class FakeImage {
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      naturalWidth = 0;
      complete = false;
      set src(v: string) {
        srcs.push(v);
        setTimeout(() => this.onerror?.(), 0);
      }
    }
    vi.stubGlobal("Image", FakeImage);
    const inline = "data:image/png;base64,iVBORw0KGgo=";
    document.body.innerHTML = `<div id="a" style="background-image:url(/qr.png)"></div><div id="b" style="background-image:url(https://x.test/qr.png)"></div><div id="c" style="background-image:url(${inline})"></div>`;
    for (const id of ["a", "b", "c"]) {
      document.getElementById(id)!.getBoundingClientRect = () =>
        ({ x: 0, y: 0, left: 0, top: 0, right: 200, bottom: 200, width: 200, height: 200, toJSON: () => ({}) }) as DOMRect;
    }
    const l = await load();
    const respond = vi.fn();
    expect(l({ type: "setup_scan_dom" }, { id: "me" }, respond)).toBe(true);
    await vi.advanceTimersByTimeAsync(100);
    expect(respond).toHaveBeenCalledWith({ found: [] });
    // Only the inline one (the positive control: the background path does load images).
    expect(srcs).toEqual([inline]);
  });

  it("a frame that cannot read the top origin does not answer setup_scan_dom", async () => {
    const l = await load();
    const spy = vi.spyOn(window, "top", "get").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    const respond = vi.fn();
    expect(l({ type: "setup_scan_dom" }, { id: "me" }, respond)).toBe(false);
    await vi.advanceTimersByTimeAsync(100);
    expect(respond).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});
