// The slice of the WebExtension API the service worker uses. Production
// passes the real `chrome` / `browser` object (shared/browser.ts); tests pass
// an in-memory fake. Keeping the surface explicit keeps every background
// module importable without browser globals.

export interface Event<F extends (...args: never[]) => unknown> {
  addListener(cb: F): void;
}

export interface StorageArea {
  /** `null` reads every key. */
  get(keys: string | string[] | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
  /** Chromium 102+: restrict the area to trusted extension contexts. */
  setAccessLevel?(options: { accessLevel: "TRUSTED_CONTEXTS" | "TRUSTED_AND_UNTRUSTED_CONTEXTS" }): Promise<void>;
}

/** What the browser says about the sender of a runtime message. */
export interface Sender {
  id?: string;
  url?: string;
  origin?: string;
  frameId?: number;
  documentId?: string;
  tab?: { id?: number };
}

export type MessageListener = (
  message: unknown,
  sender: Sender,
  sendResponse: (response?: unknown) => void,
) => boolean | undefined;

export interface NativePort {
  postMessage(message: unknown): void;
  onMessage: Event<(message: unknown) => void>;
  onDisconnect: Event<(port: NativePort) => void>;
  disconnect(): void;
  /** Firefox reports the disconnect reason here. */
  error?: { message?: string } | null;
}

export interface FrameDetails {
  url: string;
  documentId?: string;
}

export interface FrameNode extends FrameDetails {
  frameId: number;
  parentFrameId: number;
}

export interface BgExt {
  runtime: {
    id: string;
    getURL(path: string): string;
    onMessage: Event<MessageListener>;
    connectNative(application: string): NativePort;
    lastError?: { message?: string } | undefined;
  };
  tabs: {
    sendMessage(
      tabId: number,
      message: unknown,
      options: { frameId?: number; documentId?: string },
    ): Promise<unknown>;
    onRemoved: Event<(tabId: number) => void>;
    /** The popup's active tab (url readable through activeTab / host permissions). */
    query(q: { active: true; currentWindow: true }): Promise<{ id?: number; url?: string }[]>;
  };
  webNavigation: {
    getFrame(details: { tabId: number; frameId: number }): Promise<FrameDetails | null>;
    /** Every frame of a tab, with its parent (-1 for the top frame). */
    getAllFrames(details: { tabId: number }): Promise<FrameNode[] | null>;
    onCommitted: Event<(details: { tabId: number; frameId: number; url: string }) => void>;
    /** The document of a frame finished loading. */
    onCompleted: Event<(details: { tabId: number; frameId: number; url: string }) => void>;
  };
  storage: {
    local: StorageArea;
    session: StorageArea;
  };
}
