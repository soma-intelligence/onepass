// Last page analysis of each tab's top frame (no secret: refs, kinds and
// roles). The popup's "Remplir" fills a form of the active tab from it, and
// the chain driver (Task 17) subscribes with `onAnalysis`. Mirrored in
// `storage.session` for worker restarts; dropped on navigation and tab close.
import type { PageAnalysis } from "../shared/messages";
import type { BgExt, StorageArea } from "./ext";
import type { CsContext } from "./frames";

const PREFIX = "page:";

export interface TopAnalysis {
  tabId: number;
  origin: string;
  documentId?: string;
  analysis: PageAnalysis;
}

export class PageAnalyses {
  private readonly mem = new Map<number, TopAnalysis>();
  private readonly listeners = new Set<(a: PageAnalysis, from: CsContext) => void>();

  constructor(private readonly area: StorageArea) {}

  install(ext: Pick<BgExt, "webNavigation" | "tabs">): void {
    ext.webNavigation.onCommitted.addListener((d) => {
      if (d.frameId === 0) void this.drop(d.tabId);
    });
    ext.tabs.onRemoved.addListener((tabId) => void this.drop(tabId));
  }

  onAnalysis(cb: (a: PageAnalysis, from: CsContext) => void): void {
    this.listeners.add(cb);
  }

  async record(a: PageAnalysis, from: CsContext): Promise<void> {
    if (from.frameId === 0) {
      const top: TopAnalysis = { tabId: from.tabId, origin: from.origin, analysis: a };
      if (from.documentId !== undefined) top.documentId = from.documentId;
      this.mem.set(from.tabId, top);
      await this.area.set({ [PREFIX + from.tabId]: top });
    }
    for (const l of this.listeners) l(a, from);
  }

  async top(tabId: number): Promise<TopAnalysis | null> {
    const m = this.mem.get(tabId);
    if (m) return m;
    const raw = (await this.area.get(PREFIX + tabId))[PREFIX + tabId] as Partial<TopAnalysis> | undefined;
    if (!raw || raw.tabId !== tabId || typeof raw.origin !== "string" || typeof raw.analysis !== "object") return null;
    return raw as TopAnalysis;
  }

  async drop(tabId: number): Promise<void> {
    this.mem.delete(tabId);
    await this.area.remove(PREFIX + tabId);
  }
}
