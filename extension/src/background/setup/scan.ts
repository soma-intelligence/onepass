// "Scan 2FA QR code" in the popup (spec section 1). Only the popup starts it (router: from
// popup.html only), never a page. The active tab of the popup's window must be an https page (or
// loopback http) in a normal window. The scanner (`setup-scan.js`) is injected in every frame of
// that tab and each frame is asked on its own (`frameId`): a frame that cannot read the top
// origin does not answer. Nothing decoded in the page: one capture of the visible tab, decoded
// by the top frame's scanner (the capture needs the toolbar click's `activeTab` grant; any
// failure counts as nothing found). Then the card shows, in mode `paste` when nothing was read.
// No network request is made; replies are rebuilt from their URI alone.
import { parseOrigin } from "../../shared/domain";
import type { BgToScan, SetupScanResult } from "../../shared/messages";
import { type OtpauthShallow, shallowOtpauth } from "../../setup/otpauth";
import type { BgExt } from "../ext";
import { SCANNER_FILE, type SetupCards } from "./card";

/** Longest wait for one frame's answer (image loads time out at 3 s each in the page). */
export const SCAN_FRAME_TIMEOUT_MS = 10_000;
/** Most URIs taken from one frame's answer. */
const MAX_FOUND = 3;

export interface SetupScanDeps {
  ext: Pick<BgExt, "tabs" | "webNavigation" | "scripting">;
  cards: Pick<SetupCards, "open">;
  timeoutMs?: number;
}

const UNAVAILABLE: SetupScanResult = { status: "unavailable" };

/** The URIs of a scanner's answer, each checked again here; the page's issuer and account are ignored. */
function foundIn(reply: unknown): OtpauthShallow[] {
  if (typeof reply !== "object" || reply === null) return [];
  const list = (reply as { found?: unknown }).found;
  if (!Array.isArray(list)) return [];
  const out: OtpauthShallow[] = [];
  for (const f of list.slice(0, MAX_FOUND)) {
    const uri = typeof f === "object" && f !== null ? (f as { uri?: unknown }).uri : undefined;
    const hit = typeof uri === "string" ? shallowOtpauth(uri) : null;
    if (hit) out.push(hit);
  }
  return out;
}

export class SetupScan {
  constructor(private readonly deps: SetupScanDeps) {}

  private ask(tabId: number, frameId: number, msg: BgToScan): Promise<OtpauthShallow[]> {
    const ms = this.deps.timeoutMs ?? SCAN_FRAME_TIMEOUT_MS;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<OtpauthShallow[]>((resolve) => {
      timer = setTimeout(() => resolve([]), ms);
    });
    const reply = this.deps.ext.tabs.sendMessage(tabId, msg, { frameId }).then(foundIn, () => []);
    return Promise.race([reply, late]).finally(() => clearTimeout(timer));
  }

  /** What the page itself shows: the top document's first code, else the first a frame found. */
  private async pageScan(tabId: number, origin: string): Promise<OtpauthShallow | null> {
    const scripting = this.deps.ext.scripting;
    if (!scripting) return null;
    await scripting.executeScript({ target: { tabId, allFrames: true }, files: [SCANNER_FILE] });
    const all = (await this.deps.ext.webNavigation.getAllFrames({ tabId }).catch(() => null)) ?? [];
    // The top frame and frames of exactly its origin (the scanner checks it again in the page).
    const ids = [0, ...all.filter((f) => f.frameId !== 0 && parseOrigin(f.url)?.origin === origin).map((f) => f.frameId).sort((a, b) => a - b)];
    const answers = await Promise.all(ids.map((id) => this.ask(tabId, id, { type: "setup_scan_dom" })));
    for (const a of answers) if (a[0]) return a[0];
    return null;
  }

  /** One capture of the visible tab, decoded by the top frame's scanner. */
  private async captureScan(tabId: number, windowId: number | undefined): Promise<OtpauthShallow | null> {
    const capture = this.deps.ext.tabs.captureVisibleTab;
    if (!capture) return null;
    let dataUrl: string;
    try {
      dataUrl = await capture.call(this.deps.ext.tabs, windowId, { format: "png" });
    } catch {
      return null;
    }
    if (typeof dataUrl !== "string" || !dataUrl.startsWith("data:image/png")) return null;
    const found = await this.ask(tabId, 0, { type: "setup_scan_capture", dataUrl });
    return found[0] ?? null;
  }

  async scan(): Promise<SetupScanResult> {
    const [tab] = await this.deps.ext.tabs.query({ active: true, currentWindow: true });
    if (!tab || typeof tab.id !== "number" || typeof tab.url !== "string") return UNAVAILABLE;
    const tabId = tab.id;
    const info = await this.deps.ext.tabs.get?.(tabId).catch(() => undefined);
    // A private window: nothing scanned there.
    if (tab.incognito === true || info?.incognito === true) return UNAVAILABLE;
    const o = parseOrigin(tab.url);
    if (!o?.page) return UNAVAILABLE;
    const top = await this.deps.ext.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null);
    if (!top || parseOrigin(top.url)?.origin !== o.origin) return UNAVAILABLE;
    const documentId = top.documentId;
    let found = await this.pageScan(tabId, o.origin).catch(() => null);
    found ??= await this.captureScan(tabId, tab.windowId ?? info?.windowId).catch(() => null);
    // The page must still be the one scanned.
    const after = await this.deps.ext.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null);
    if (!after || parseOrigin(after.url)?.origin !== o.origin) return UNAVAILABLE;
    if (documentId !== undefined && after.documentId !== undefined && after.documentId !== documentId) return UNAVAILABLE;
    await this.deps.cards.open({ tabId, origin: o.origin, ...(documentId !== undefined ? { documentId } : {}), found });
    return { status: found ? "card" : "none" };
  }
}
