// Test harness for the content script: a fake `ext` (runtime messaging only),
// trusted-event helpers (jsdom cannot mint `isTrusted` events) and a page loader.
import { vi } from "vitest";
import { testGeometry } from "../detect/helpers";
import { type ContentExt, type ContentScript, createContentScript } from "../../src/content/index";

export const EXT_ID = "onepassextensionid";
export const EXT_BASE = `chrome-extension://${EXT_ID}/`;
export const PAGE = "https://atlas-cloud.test/login";
export const TOKEN = "AAAAAAAAAAAAAAAAAAAAAA";

type Listener = Parameters<ContentExt["runtime"]["onMessage"]["addListener"]>[0];

export class FakeExt implements ContentExt {
  readonly sent: unknown[] = [];
  readonly listeners: Listener[] = [];
  /** Reply returned for each sent message (router envelope). */
  reply: (m: unknown) => unknown = () => ({ ok: null });
  readonly runtime: ContentExt["runtime"] = {
    id: EXT_ID,
    getURL: (p: string) => EXT_BASE + p,
    sendMessage: async (m: unknown) => {
      this.sent.push(structuredClone(m));
      return this.reply(m);
    },
    onMessage: { addListener: (l: Listener) => void this.listeners.push(l) },
  };

  /** Delivers a message as the service worker would (`tabs.sendMessage`). */
  deliver(message: unknown, sender: { id?: string } = { id: EXT_ID }): unknown {
    let out: unknown;
    for (const l of this.listeners) l(message, sender, (r) => (out = r));
    return out;
  }

  ofType(type: string): Record<string, unknown>[] {
    return this.sent.filter((m) => (m as { type: string }).type === type) as Record<string, unknown>[];
  }
}

const trusted = new WeakSet<Event>();

/** Dispatches `e` as if the user produced it. */
export function asUser<E extends Event>(target: EventTarget, e: E): E {
  trusted.add(e);
  target.dispatchEvent(e);
  return e;
}

export const userClick = (el: Element) =>
  asUser(el, new MouseEvent("click", { bubbles: true, composed: true, cancelable: true }));

export const userKey = (el: Element, key: string) =>
  asUser(el, new KeyboardEvent("keydown", { key, bubbles: true, composed: true, cancelable: true }));

export interface Started {
  ext: FakeExt;
  cs: ContentScript;
}

export function setPage(html: string): void {
  document.documentElement.innerHTML = `<head></head><body>${html}</body>`;
}

export function start(href = PAGE): Started {
  const ext = new FakeExt();
  const cs = createContentScript({
    doc: document,
    ext,
    href: () => href,
    geometry: testGeometry,
    isTrusted: (e) => e.isTrusted || trusted.has(e),
    raf: (cb) => setTimeout(cb, 0),
  });
  cs.start();
  return { ext, cs };
}

export async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

export function input(id: string): HTMLInputElement {
  const el = document.getElementById(id);
  if (!(el instanceof HTMLInputElement)) throw new Error(`missing input #${id}`);
  return el;
}

export function useTimers(): void {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
}
