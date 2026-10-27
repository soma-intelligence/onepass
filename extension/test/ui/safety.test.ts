// Page-level invariants of every extension page (spec 8.3, S1): no
// `message` listener, no access to the embedding page, no HTML parsing.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mountMenu } from "../../src/ui/menu";
import { mountOverlay } from "../../src/ui/overlay";
import { mountPopup } from "../../src/ui/popup";
import { mountSave } from "../../src/ui/save";
import { FakeWorker, HASH, root } from "./helpers";

const UI_DIR = join(__dirname, "../../src/ui");
/** Page sources, comments removed (they may name what the code avoids). */
const sources = () =>
  readdirSync(UI_DIR)
    .filter((f) => f.endsWith(".ts") || f.endsWith(".html"))
    .map((f) => {
      const raw = readFileSync(join(UI_DIR, f), "utf8");
      const code = raw.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "").replace(/\s\/\/ .*$/gm, "");
      return [f, code, raw] as const;
    });

type Mount = (r: HTMLElement, deps: Parameters<typeof mountMenu>[1]) => { ready: Promise<void> };
export const PAGES: [string, Mount][] = [
  ["menu", mountMenu],
  ["overlay", mountOverlay],
  ["save", mountSave],
  ["popup", (r, d) => mountPopup(r, { send: d.send })],
];

afterEach(() => vi.restoreAllMocks());

describe("extension pages", () => {
  it("no_message_listener_on_window", async () => {
    const spies = [vi.spyOn(window, "addEventListener"), vi.spyOn(document, "addEventListener")];
    for (const [, mount] of PAGES) {
      const worker = new FakeWorker(() => ({ err: "locked" }));
      await mount(root(), { send: worker.send, hash: HASH, observe: () => undefined }).ready;
    }
    for (const spy of spies) {
      expect(spy.mock.calls.map((c) => c[0])).not.toContain("message");
    }
    expect(window.onmessage).toBeNull();
  });

  it("no source reads the parent page or listens to postMessage", () => {
    for (const [file, src] of sources()) {
      expect(src, file).not.toMatch(/window\.parent|\bparent\.|window\.top|\btop\.|window\.opener/);
      expect(src, file).not.toMatch(/addEventListener\(\s*["'`]message|onmessage|postMessage|onMessage/);
    }
  });

  it("no innerHTML with data: no HTML parsing API anywhere in the pages", () => {
    for (const [file, src] of sources()) {
      expect(src, file).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|DOMParser|createContextualFragment/);
    }
  });

  it("no em dash in the UI sources", () => {
    for (const [file, , raw] of sources()) expect(raw.includes("\u2014"), file).toBe(false);
    expect(readFileSync(join(UI_DIR, "theme.css"), "utf8").includes("\u2014")).toBe(false);
  });
});
