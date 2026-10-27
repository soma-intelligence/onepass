// Who is talking, and which frame a fill may reach.
//
// The origin of a content script is always the one the browser reports in
// `sender` (`sender.origin`, else the origin of `sender.url`): a compromised
// renderer controls every message field, never `sender` (spec 3). Before
// every fill the target frame is read again from `webNavigation` (spec 8.4).
import { parseOrigin, sameSite } from "../shared/domain";
import type { BgExt, FrameDetails, FrameNode, Sender } from "./ext";

/** A content script sender, as vouched for by the browser. */
export interface CsContext {
  tabId: number;
  frameId: number;
  /** Normalized origin of the frame (`parseOrigin`). */
  origin: string;
  /** Chromium 106+: the exact document, to detect same-origin navigations. */
  documentId?: string;
}

/** An extension page sender (popup, or menu / overlay / save frame). */
export interface UiContext {
  /** Path of the page inside the extension, e.g. "menu.html". */
  page: string;
  /** The tab hosting the frame; absent for the popup. */
  tabId?: number;
}

type RuntimeId = Pick<BgExt["runtime"], "id" | "getURL">;

/** The extension page that sent `sender`, or null if it is not one of ours. */
export function extensionSender(runtime: RuntimeId, sender: Sender): UiContext | null {
  if (sender.id !== runtime.id || typeof sender.url !== "string") return null;
  const base = runtime.getURL("");
  if (!sender.url.startsWith(base)) return null;
  const rest = sender.url.slice(base.length);
  const page = rest.split(/[?#]/, 1)[0] ?? "";
  const ctx: UiContext = { page };
  const tabId = sender.tab?.id;
  if (typeof tabId === "number" && Number.isSafeInteger(tabId) && tabId >= 0) ctx.tabId = tabId;
  return ctx;
}

/** The content script frame that sent `sender`, or null. */
export function contentSender(runtime: RuntimeId, sender: Sender): CsContext | null {
  if (sender.id !== runtime.id || typeof sender.url !== "string") return null;
  if (sender.url.startsWith(runtime.getURL(""))) return null;
  const tabId = sender.tab?.id;
  const frameId = sender.frameId;
  if (typeof tabId !== "number" || !Number.isSafeInteger(tabId) || tabId < 0) return null;
  if (typeof frameId !== "number" || !Number.isSafeInteger(frameId) || frameId < 0) return null;
  let raw: string;
  if (typeof sender.origin === "string") {
    // An opaque origin ("null", sandboxed frame) does not parse: rejected.
    raw = sender.origin;
  } else {
    try {
      raw = new URL(sender.url).origin;
    } catch {
      return null;
    }
  }
  const parsed = parseOrigin(raw);
  if (!parsed) return null;
  const ctx: CsContext = { tabId, frameId, origin: parsed.origin };
  if (typeof sender.documentId === "string" && sender.documentId !== "") ctx.documentId = sender.documentId;
  return ctx;
}

export type FillRefusal = "insecure_origin" | "origin_mismatch" | "cross_site_frame";
export type FillCheck = { ok: true } | { ok: false; code: FillRefusal };

export class Frames {
  constructor(private readonly nav: Pick<BgExt["webNavigation"], "getFrame" | "getAllFrames">) {}

  private async frame(tabId: number, frameId: number): Promise<FrameDetails | null> {
    try {
      const f = await this.nav.getFrame({ tabId, frameId });
      return f && typeof f.url === "string" ? f : null;
    } catch {
      // Tab or frame gone.
      return null;
    }
  }

  /** A frame as the browser reports it now (URL, documentId where supported), or null. */
  async details(tabId: number, frameId: number): Promise<FrameDetails | null> {
    return this.frame(tabId, frameId);
  }

  /**
   * Spec C1: every frame from `frameId` up to the top frame, as the browser
   * reports them now, has exactly `origin`. A frame of the site nested in a
   * third-party frame does not pass. Unknown frames or a loop: false.
   */
  async ancestorsOfOrigin(tabId: number, frameId: number, origin: string): Promise<boolean> {
    let all: FrameNode[] | null;
    try {
      all = await this.nav.getAllFrames({ tabId });
    } catch {
      return false;
    }
    if (!all) return false;
    const byId = new Map(all.map((f) => [f.frameId, f]));
    let id = frameId;
    for (let hops = 0; hops <= all.length; hops++) {
      const f = byId.get(id);
      if (!f || parseOrigin(f.url)?.origin !== origin) return false;
      if (id === 0) return true;
      id = f.parentFrameId;
    }
    return false;
  }

  /** Current origin of a frame, or null (gone, about:, data:, ...). */
  async frameOrigin(tabId: number, frameId: number): Promise<string | null> {
    const f = await this.frame(tabId, frameId);
    return f ? (parseOrigin(f.url)?.origin ?? null) : null;
  }

  /**
   * Spec 8.4 step 2: HTTPS, still the origin (and document, when known)
   * bound when the gesture started, and the top frame or a frame of the
   * same registrable domain as the top frame. No exception (R-10).
   *
   * `scope` "same_origin" (the chain, spec C1) narrows a child frame to
   * exactly the top frame's origin: a subdomain of the same site may be
   * another service.
   */
  async checkFillTarget(
    tabId: number,
    frameId: number,
    expectedOrigin: string,
    expectedDocumentId?: string,
    scope: "same_site" | "same_origin" = "same_site",
  ): Promise<FillCheck> {
    const expected = parseOrigin(expectedOrigin);
    if (!expected?.https) return { ok: false, code: "insecure_origin" };
    const f = await this.frame(tabId, frameId);
    const current = f ? parseOrigin(f.url) : null;
    if (!f || !current) return { ok: false, code: "origin_mismatch" };
    if (!current.https) return { ok: false, code: "insecure_origin" };
    if (current.origin !== expected.origin) return { ok: false, code: "origin_mismatch" };
    if (expectedDocumentId !== undefined && f.documentId !== undefined && f.documentId !== expectedDocumentId) {
      return { ok: false, code: "origin_mismatch" };
    }
    if (frameId !== 0) {
      const top = await this.frame(tabId, 0);
      if (!top || !sameSite(top.url, f.url)) return { ok: false, code: "cross_site_frame" };
      // A secure frame inside a plain HTTP page is refused as well.
      if (parseOrigin(top.url)?.https !== true) return { ok: false, code: "insecure_origin" };
      if (scope === "same_origin" && parseOrigin(top.url)?.origin !== current.origin) return { ok: false, code: "origin_mismatch" };
    }
    return { ok: true };
  }
}
