// Last page analysis of each tab's top frame (no secret: refs, kinds and
// roles). The popup's "Remplir" fills a form of the active tab from it, and
// the chain driver (Task 17) subscribes with `onAnalysis`. Mirrored in
// `storage.session` for worker restarts; dropped on navigation and tab close.
//
// Also kept, for the chain and its overlay (spec C1): the last analysis of
// each child frame that shows forms, with the origin and document the
// browser reported in `sender`, not when it has another origin than the top
// frame's last analysis (so other-origin frames cannot crowd the cap). Whether
// such a frame may be acted on (exactly the top frame's origin up to frame 0,
// still that document) is decided by the reader against `webNavigation`,
// never here. Changes of a tab are serialized: two analyses read and write
// the stored list one after the other, also after a worker restart.
import type { PageAnalysis } from "../shared/messages";
import type { BgExt, StorageArea } from "./ext";
import type { CsContext } from "./frames";

const PREFIX = "page:";
const FRAMES_PREFIX = "frames:";
/** Child frames kept per tab, at most (a page cannot grow the store at will). */
const MAX_FRAMES = 16;

export interface TopAnalysis {
  tabId: number;
  origin: string;
  documentId?: string;
  analysis: PageAnalysis;
}

export interface FrameAnalysis {
  frameId: number;
  /** From `sender`. */
  origin: string;
  documentId?: string;
  analysis: PageAnalysis;
}

function parseFrames(raw: unknown): FrameAnalysis[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter(
    (x): x is FrameAnalysis =>
      typeof x === "object" &&
      x !== null &&
      Number.isSafeInteger((x as FrameAnalysis).frameId) &&
      (x as FrameAnalysis).frameId > 0 &&
      typeof (x as FrameAnalysis).origin === "string" &&
      typeof (x as FrameAnalysis).analysis === "object" &&
      Array.isArray((x as FrameAnalysis).analysis?.forms),
  );
}

export class PageAnalyses {
  private readonly mem = new Map<number, TopAnalysis>();
  private readonly kids = new Map<number, FrameAnalysis[]>();
  private readonly queues = new Map<number, Promise<unknown>>();
  private readonly listeners = new Set<(a: PageAnalysis, from: CsContext) => void>();

  constructor(private readonly area: StorageArea) {}

  install(ext: Pick<BgExt, "webNavigation" | "tabs">): void {
    ext.webNavigation.onCommitted.addListener((d) => {
      if (d.frameId === 0) void this.drop(d.tabId);
      else void this.serial(d.tabId, () => this.dropFrame(d.tabId, d.frameId));
    });
    ext.tabs.onRemoved.addListener((tabId) => void this.drop(tabId));
  }

  onAnalysis(cb: (a: PageAnalysis, from: CsContext) => void): void {
    this.listeners.add(cb);
  }

  async record(a: PageAnalysis, from: CsContext): Promise<void> {
    await this.serial(from.tabId, async () => {
      if (from.frameId === 0) {
        const top: TopAnalysis = { tabId: from.tabId, origin: from.origin, analysis: a };
        if (from.documentId !== undefined) top.documentId = from.documentId;
        this.mem.set(from.tabId, top);
        await this.area.set({ [PREFIX + from.tabId]: top });
        // Children recorded before the top frame's analysis, of another origin: dropped.
        const list = await this.load(from.tabId);
        if (list.some((x) => x.origin !== from.origin)) await this.saveFrames(from.tabId, list.filter((x) => x.origin === from.origin));
        return;
      }
      const list = (await this.load(from.tabId)).filter((x) => x.frameId !== from.frameId);
      const topOrigin = (await this.top(from.tabId))?.origin;
      const ofTop = topOrigin === undefined || topOrigin === from.origin;
      if (a.forms.length > 0 && ofTop && list.length < MAX_FRAMES) {
        const f: FrameAnalysis = { frameId: from.frameId, origin: from.origin, analysis: a };
        if (from.documentId !== undefined) f.documentId = from.documentId;
        list.push(f);
      }
      await this.saveFrames(from.tabId, list);
    });
    for (const l of this.listeners) l(a, from);
  }

  async top(tabId: number): Promise<TopAnalysis | null> {
    const m = this.mem.get(tabId);
    if (m) return m;
    const raw = (await this.area.get(PREFIX + tabId))[PREFIX + tabId] as Partial<TopAnalysis> | undefined;
    if (!raw || raw.tabId !== tabId || typeof raw.origin !== "string" || typeof raw.analysis !== "object") return null;
    return raw as TopAnalysis;
  }

  /** The child frames of a tab that last showed forms, in frame order. */
  async children(tabId: number): Promise<FrameAnalysis[]> {
    return this.serial(tabId, () => this.load(tabId));
  }

  private async load(tabId: number): Promise<FrameAnalysis[]> {
    const m = this.kids.get(tabId);
    if (m) return [...m];
    const list = parseFrames((await this.area.get(FRAMES_PREFIX + tabId))[FRAMES_PREFIX + tabId]);
    if (!this.kids.has(tabId)) this.kids.set(tabId, list);
    return [...(this.kids.get(tabId) ?? list)];
  }

  async drop(tabId: number): Promise<void> {
    await this.serial(tabId, async () => {
      this.mem.delete(tabId);
      this.kids.delete(tabId);
      await this.area.remove([PREFIX + tabId, FRAMES_PREFIX + tabId]);
    });
  }

  private async dropFrame(tabId: number, frameId: number): Promise<void> {
    const list = await this.load(tabId);
    if (list.some((x) => x.frameId === frameId)) await this.saveFrames(tabId, list.filter((x) => x.frameId !== frameId));
  }

  private serial<T>(tabId: number, fn: () => Promise<T>): Promise<T> {
    const prev = this.queues.get(tabId) ?? Promise.resolve();
    const next = prev.then(fn, fn);
    const settled = next.catch(() => undefined);
    this.queues.set(tabId, settled);
    void settled.then(() => {
      if (this.queues.get(tabId) === settled) this.queues.delete(tabId);
    });
    return next;
  }

  private async saveFrames(tabId: number, list: FrameAnalysis[]): Promise<void> {
    list.sort((x, y) => x.frameId - y.frameId);
    this.kids.set(tabId, list);
    if (list.length === 0) await this.area.remove(FRAMES_PREFIX + tabId);
    else await this.area.set({ [FRAMES_PREFIX + tabId]: list });
  }
}
