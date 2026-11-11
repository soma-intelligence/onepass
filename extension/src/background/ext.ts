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

/** A tab as `windows.getLastFocused({populate: true})` lists it (url and title through host permissions). */
export interface WindowTab {
  id?: number;
  active: boolean;
  title?: string;
  url?: string;
}

export interface BgExt {
  runtime: {
    id: string;
    getURL(path: string): string;
    onMessage: Event<MessageListener>;
    /** The extension was installed or updated (absent in some test fakes). */
    onInstalled?: Event<() => void>;
    /** The browser profile started. */
    onStartup?: Event<() => void>;
    connectNative(application: string): NativePort;
    /** Safari: one request to the app extension's handler, one reply. */
    sendNativeMessage?(application: string, message: unknown): Promise<unknown>;
    lastError?: { message?: string } | undefined;
  };
  tabs: {
    sendMessage(
      tabId: number,
      message: unknown,
      options: { frameId?: number; documentId?: string },
    ): Promise<unknown>;
    onRemoved: Event<(tabId: number) => void>;
    /** A tab opened (a popup window's too); `openerTabId` is the tab whose page opened it. No `tabs` permission needed for these two. */
    onCreated?: Event<(tab: { id?: number; openerTabId?: number }) => void>;
    /** The popup's active tab (url readable through activeTab / host permissions). */
    query(q: { active: true; currentWindow: true }): Promise<{ id?: number; url?: string }[]>;
    /** Is the tab the active one of its window, and which window (no permission needed for these two). */
    get?(tabId: number): Promise<{ active?: boolean; windowId?: number } | undefined>;
  };
  webNavigation: {
    getFrame(details: { tabId: number; frameId: number }): Promise<FrameDetails | null>;
    /** Every frame of a tab, with its parent (-1 for the top frame). */
    getAllFrames(details: { tabId: number }): Promise<FrameNode[] | null>;
    onCommitted: Event<(details: { tabId: number; frameId: number; url: string }) => void>;
    /** The document of a frame finished loading. */
    onCompleted: Event<(details: { tabId: number; frameId: number; url: string }) => void>;
    /** A tab or window was created to host a navigation, and by which frame of which tab (absent in Safari). */
    onCreatedNavigationTarget?: Event<(details: { tabId: number; sourceTabId: number; sourceFrameId: number; url: string }) => void>;
  };
  storage: {
    local: StorageArea;
    session: StorageArea;
  };
  /** The front window and its tabs (the agent channel's probe, agent.ts). */
  windows?: {
    getLastFocused(q: { populate: true; windowTypes?: ("normal" | "popup")[] }): Promise<{ id?: number; tabs?: WindowTab[] }>;
    /** Does the window have the focus (absent where the browser has no windows API). */
    get?(windowId: number): Promise<{ focused?: boolean } | undefined>;
    /** A small window for the popup page when the browser cannot open the toolbar popup (menu_pair). */
    create?(o: { url: string; type: "popup"; width: number; height: number; focused?: boolean }): Promise<unknown>;
  };
  /** The toolbar button: `openPopup` shows the popup from the worker (absent or failing in some browsers). */
  action?: {
    openPopup?(): Promise<void>;
  };
  /** Wakes of the service worker (the agent channel reopens its port). Chromium returns a promise, Firefox nothing. */
  alarms?: {
    create(name: string, info: { periodInMinutes: number }): Promise<void> | void;
    clear?(name: string): Promise<boolean> | void;
    onAlarm: Event<(alarm: { name: string }) => void>;
  };
  /** Keyboard shortcuts of the manifest's `commands` (absent where the browser has none). */
  commands?: {
    onCommand: Event<(command: string) => void>;
  };
}
