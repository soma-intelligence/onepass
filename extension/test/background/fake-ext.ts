// In-memory WebExtension API for background tests: runtime messaging,
// native ports, tabs, webNavigation and storage areas.
import type { BgExt, FrameDetails, FrameNode, MessageListener, NativePort, Sender, StorageArea } from "../../src/background/ext";

export const EXT_ID = "onepassextensionid";
export const EXT_ORIGIN = `chrome-extension://${EXT_ID}/`;

class Emitter<F extends (...args: never[]) => unknown> {
  readonly listeners: F[] = [];
  addListener(cb: F): void {
    this.listeners.push(cb);
  }
  emit(...args: Parameters<F>): void {
    for (const l of this.listeners) l(...args);
  }
}

export class FakeArea implements StorageArea {
  readonly data = new Map<string, unknown>();
  readonly accessLevels: string[] = [];
  async setAccessLevel(o: { accessLevel: "TRUSTED_CONTEXTS" | "TRUSTED_AND_UNTRUSTED_CONTEXTS" }): Promise<void> {
    this.accessLevels.push(o.accessLevel);
  }
  async get(keys: string | string[] | null): Promise<Record<string, unknown>> {
    const out: Record<string, unknown> = {};
    const wanted = keys === null ? [...this.data.keys()] : typeof keys === "string" ? [keys] : keys;
    for (const k of wanted) {
      if (this.data.has(k)) out[k] = structuredClone(this.data.get(k));
    }
    return out;
  }
  async set(items: Record<string, unknown>): Promise<void> {
    for (const [k, v] of Object.entries(items)) this.data.set(k, structuredClone(v));
  }
  async remove(keys: string | string[]): Promise<void> {
    for (const k of typeof keys === "string" ? [keys] : keys) this.data.delete(k);
  }
}

export class FakePort implements NativePort {
  readonly sent: unknown[] = [];
  readonly onMessage = new Emitter<(m: unknown) => void>();
  readonly onDisconnect = new Emitter<(p: NativePort) => void>();
  disconnected = false;
  error: { message?: string } | null = null;
  postMessage(m: unknown): void {
    if (this.disconnected) throw new Error("Attempting to use a disconnected port object");
    this.sent.push(m);
  }
  disconnect(): void {
    this.disconnected = true;
  }
  /** The host side goes away. */
  hostDisconnect(message?: string): void {
    this.disconnected = true;
    if (message) this.error = { message };
    this.onDisconnect.emit(this);
  }
}

export interface SentToTab {
  tabId: number;
  message: unknown;
  options: { frameId?: number; documentId?: string };
}

export class FakeExt implements BgExt {
  readonly onMessage = new Emitter<MessageListener>();
  readonly ports: FakePort[] = [];
  connectNativeError: Error | undefined;
  readonly frames = new Map<string, FrameDetails>();
  /** Parent of a child frame (`tabId:frameId`); 0 when not set. */
  readonly parents = new Map<string, number>();
  readonly sentToTabs: SentToTab[] = [];
  readonly onRemoved = new Emitter<(tabId: number) => void>();
  readonly onCommitted = new Emitter<(d: { tabId: number; frameId: number; url: string }) => void>();
  readonly onCompleted = new Emitter<(d: { tabId: number; frameId: number; url: string }) => void>();
  readonly local = new FakeArea();
  readonly session = new FakeArea();

  readonly runtime: BgExt["runtime"] = {
    id: EXT_ID,
    getURL: (path: string) => EXT_ORIGIN + path.replace(/^\//, ""),
    onMessage: this.onMessage,
    connectNative: (name: string) => {
      if (this.connectNativeError) throw this.connectNativeError;
      void name;
      const p = new FakePort();
      this.ports.push(p);
      return p;
    },
    lastError: undefined,
  };

  readonly tabs: BgExt["tabs"] = {
    sendMessage: async (tabId, message, options) => {
      this.sentToTabs.push({ tabId, message: structuredClone(message), options });
      return undefined;
    },
    onRemoved: this.onRemoved,
    query: async () => (this.activeTab ? [{ ...this.activeTab }] : []),
  };

  /** What `tabs.query({active, currentWindow})` returns. */
  activeTab: { id?: number; url?: string } | null = null;

  readonly webNavigation: BgExt["webNavigation"] = {
    getFrame: async ({ tabId, frameId }) => {
      const f = this.frames.get(`${tabId}:${frameId}`);
      return f ? { ...f } : null;
    },
    getAllFrames: async ({ tabId }) => {
      const out: FrameNode[] = [];
      for (const [k, f] of this.frames) {
        const [t, id] = k.split(":").map(Number) as [number, number];
        if (t !== tabId) continue;
        out.push({ ...f, frameId: id, parentFrameId: id === 0 ? -1 : (this.parents.get(k) ?? 0) });
      }
      return out;
    },
    onCommitted: this.onCommitted,
    onCompleted: this.onCompleted,
  };

  readonly storage: BgExt["storage"] = { local: this.local, session: this.session };

  setFrame(tabId: number, frameId: number, url: string, documentId?: string): void {
    this.frames.set(`${tabId}:${frameId}`, documentId === undefined ? { url } : { url, documentId });
  }

  /** A navigation: new URL and a new document in that frame. */
  navigate(tabId: number, frameId: number, url: string, documentId?: string): void {
    this.setFrame(tabId, frameId, url, documentId);
    this.onCommitted.emit({ tabId, frameId, url });
  }

  /** The document of a frame finished loading. */
  complete(tabId: number, frameId: number): void {
    const f = this.frames.get(`${tabId}:${frameId}`);
    this.onCompleted.emit({ tabId, frameId, url: f?.url ?? "" });
  }

  /** Deliver a runtime message; resolves with the reply, or "no-reply". */
  send(message: unknown, sender: Sender): Promise<unknown> {
    return new Promise((resolve) => {
      let async = false;
      let replied = false;
      for (const l of this.onMessage.listeners) {
        const r = l(message, sender, (resp) => {
          replied = true;
          resolve(resp);
        });
        if (r === true) async = true;
      }
      if (!async && !replied) resolve(NO_REPLY);
    });
  }
}

export const NO_REPLY = Symbol("no-reply");

/** Sender of a content script in a web page frame. */
export function csSender(url: string, tabId = 7, frameId = 0, extra: Partial<Sender> = {}): Sender {
  return { id: EXT_ID, url, origin: new URL(url).origin, frameId, tab: { id: tabId }, ...extra };
}

/** Sender of an extension page (`page` like "menu.html#token"); `tabId` for an embedded frame. */
export function uiSender(page: string, tabId?: number, extra: Partial<Sender> = {}): Sender {
  const s: Sender = { id: EXT_ID, url: EXT_ORIGIN + page, origin: EXT_ORIGIN.replace(/\/$/, ""), ...extra };
  if (tabId !== undefined) {
    s.tab = { id: tabId };
    s.frameId = 3;
  }
  return s;
}
