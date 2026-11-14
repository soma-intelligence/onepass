// On-demand page scanner for two-factor setup QR codes and recovery codes. It is its own
// bundle (`setup-scan.js`), injected by the popup into the current tab, never part of the
// always-on content script (it carries the QR decoder).
//
// It answers three runtime messages and nothing else:
//   setup_scan_dom     -> { found }   what the page itself shows (img, canvas, svg, CSS
//                                     background, otpauth link)
//   setup_scan_capture -> { found }   a tab capture the worker hands over as a data: URL
//   setup_watch_codes  -> later one `setup_codes_found` message to the worker
// No network request is made. A cross-origin image or a tainted canvas is skipped (the
// capture path covers it). Nothing decoded is logged.
import { ext } from "../../shared/browser";
import { type OtpauthShallow, shallowOtpauth } from "../../setup/otpauth";
import { decodeQr } from "../../setup/qr-decode";
import { type Candidate, findCandidates } from "./candidates";
import { findRecoveryCodes } from "./recovery";

/** Sent to the worker; Task 8 adds it to `CsToBg` and the router. */
interface SetupCodesFound {
  type: "setup_codes_found";
  codes: string[];
}

const MAX_FOUND = 3;
const MAX_PIXELS = 2_000_000;
const FULL_CAPTURE_PIXELS = 4_000_000;
const WATCH_DEBOUNCE_MS = 500;
const MAX_WATCH_MS = 300_000;
const IMAGE_TIMEOUT_MS = 3000;
const WATCH_MAX_WAIT_MS = 2000;
const GUARD = "__onepass_setup_scan__";

type Pixels = { data: Uint8ClampedArray; width: number; height: number };
type Drawable = HTMLImageElement | HTMLCanvasElement;

/** The pixels of `src` drawn at `scale` (and never over 2 megapixels); null when tainted. */
function readPixels(src: Drawable, sw: number, sh: number, scale = 1, cap = true): Pixels | null {
  if (sw <= 0 || sh <= 0) return null;
  let k = scale;
  if (cap && sw * k * sh * k > MAX_PIXELS) k = Math.sqrt(MAX_PIXELS / (sw * sh));
  const width = Math.max(1, Math.floor(sw * k));
  const height = Math.max(1, Math.floor(sh * k));
  const canvas = document.createElement("canvas");
  try {
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) return null;
    ctx.fillStyle = "#fff"; // a transparent QR on a dark page still has a quiet zone
    ctx.fillRect(0, 0, width, height);
    ctx.drawImage(src, 0, 0, width, height);
    const d = ctx.getImageData(0, 0, width, height);
    return { data: d.data, width, height };
  } catch {
    return null; // SecurityError (tainted) or an undecodable image
  } finally {
    canvas.width = 0; // release the bitmap
    canvas.height = 0;
  }
}

function decodeOne(src: Drawable, sw: number, sh: number, scale = 1, cap = true): OtpauthShallow | null {
  const px = readPixels(src, sw, sh, scale, cap);
  if (!px) return null;
  const text = decodeQr(px);
  return text === null ? null : shallowOtpauth(text);
}

function loadImage(url: string): Promise<HTMLImageElement | null> {
  return new Promise((resolve) => {
    const img = new Image();
    const timer = setTimeout(() => resolve(null), IMAGE_TIMEOUT_MS);
    img.onload = () => {
      clearTimeout(timer);
      resolve(img);
    };
    img.onerror = () => {
      clearTimeout(timer);
      resolve(null);
    };
    img.src = url;
  });
}

/** No network request: only inline images (data:, blob:) are loaded for a CSS background. */
function inlineUrl(url: string): boolean {
  return url.startsWith("data:") || url.startsWith("blob:");
}

function backgroundUrls(el: Element): string[] {
  const bg = getComputedStyle(el).backgroundImage;
  const out: string[] = [];
  for (const m of bg.matchAll(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*?))\s*\)/g)) {
    const u = (m[1] ?? m[2] ?? m[3] ?? "").trim();
    if (u) out.push(u);
  }
  return out;
}

async function decodeCandidate(c: Candidate): Promise<OtpauthShallow | null> {
  if (c.kind === "link") return shallowOtpauth(c.el.getAttribute("href") ?? "");
  if (c.kind === "canvas") {
    const cv = c.el as HTMLCanvasElement;
    return decodeOne(cv, cv.width, cv.height);
  }
  if (c.kind === "img") {
    const img = c.el as HTMLImageElement;
    if (!img.complete || img.naturalWidth === 0) return null;
    return decodeOne(img, img.naturalWidth, img.naturalHeight);
  }
  if (c.kind === "svg") {
    const svg = c.el.cloneNode(true) as SVGElement;
    if (!svg.getAttribute("xmlns")) svg.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    const r = c.el.getBoundingClientRect();
    svg.setAttribute("width", String(Math.round(r.width)));
    svg.setAttribute("height", String(Math.round(r.height)));
    const markup = new XMLSerializer().serializeToString(svg);
    const img = await loadImage(`data:image/svg+xml;charset=utf-8,${encodeURIComponent(markup)}`);
    return img ? decodeOne(img, Math.round(r.width), Math.round(r.height)) : null;
  }
  for (const url of backgroundUrls(c.el)) {
    if (!inlineUrl(url)) continue;
    const img = await loadImage(url);
    const hit = img && img.naturalWidth > 0 ? decodeOne(img, img.naturalWidth, img.naturalHeight) : null;
    if (hit) return hit;
  }
  return null;
}

function topReadable(): boolean {
  try {
    void window.top?.location.origin;
    return window.top !== null;
  } catch {
    return false;
  }
}

function addUnique(found: OtpauthShallow[], hit: OtpauthShallow | null): void {
  if (hit && found.length < MAX_FOUND && !found.some((f) => f.uri === hit.uri)) found.push(hit);
}

async function scanDom(): Promise<OtpauthShallow[]> {
  if (!topReadable()) return [];
  const found: OtpauthShallow[] = [];
  for (const c of findCandidates(document)) {
    addUnique(found, await decodeCandidate(c));
    if (found.length >= MAX_FOUND) break;
  }
  return found;
}

async function scanCapture(dataUrl: string): Promise<OtpauthShallow[]> {
  if (!dataUrl.startsWith("data:image/")) return [];
  const img = await loadImage(dataUrl);
  if (!img || img.naturalWidth === 0) return [];
  const w = img.naturalWidth;
  const h = img.naturalHeight;
  const scales = w * h < FULL_CAPTURE_PIXELS ? [1, 1 / 2, 1 / 3] : [1 / 2, 1 / 3];
  const found: OtpauthShallow[] = [];
  for (const s of scales) {
    addUnique(found, decodeOne(img, w, h, s, false)); // the 2 MP cap is for page images
    if (found.length > 0) break;
  }
  return found;
}

let stopWatch: (() => void) | null = null;

/** One observer, 500 ms debounce (2 s at most on a page that never settles), reports once,
 *  disconnects after `ms`. */
function watchCodes(ms: number): void {
  stopWatch?.();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let maxTimer: ReturnType<typeof setTimeout> | undefined;
  let done = false;
  const finish = (): void => {
    done = true;
    clearTimeout(timer);
    clearTimeout(maxTimer);
    clearTimeout(expiry);
    observer.disconnect();
    stopWatch = null;
  };
  const check = (): void => {
    clearTimeout(timer);
    clearTimeout(maxTimer);
    maxTimer = undefined;
    if (done) return;
    const codes = findRecoveryCodes(document);
    if (!codes) return;
    finish();
    const msg: SetupCodesFound = { type: "setup_codes_found", codes };
    try {
      void Promise.resolve(ext.runtime.sendMessage(msg)).catch(() => undefined);
    } catch {
      // extension context invalidated
    }
  };
  const observer = new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(check, WATCH_DEBOUNCE_MS);
    maxTimer ??= setTimeout(check, WATCH_MAX_WAIT_MS);
  });
  const expiry = setTimeout(finish, Math.min(Math.max(ms, 1), MAX_WATCH_MS));
  observer.observe(document, { childList: true, subtree: true, characterData: true });
  stopWatch = finish;
  timer = setTimeout(check, WATCH_DEBOUNCE_MS); // codes already on screen
}

function onMessage(message: unknown, sender: { id?: string }, sendResponse: (r: unknown) => void): boolean | undefined {
  if (sender.id !== ext.runtime.id) return undefined;
  const m = message as { type?: unknown; dataUrl?: unknown; ms?: unknown } | null;
  if (!m || typeof m !== "object") return undefined;
  if (m.type === "setup_scan_dom") {
    if (!topReadable()) return false; // a frame that cannot read the top origin does not answer
    void scanDom().then((found) => sendResponse({ found }), () => sendResponse({ found: [] }));
    return true;
  }
  if (m.type === "setup_scan_capture" && typeof m.dataUrl === "string") {
    void scanCapture(m.dataUrl).then((found) => sendResponse({ found }), () => sendResponse({ found: [] }));
    return true;
  }
  if (m.type === "setup_watch_codes" && typeof m.ms === "number" && Number.isFinite(m.ms)) {
    watchCodes(m.ms);
    sendResponse({ ok: true });
    return undefined;
  }
  return undefined;
}

// A second injection into the same document must not register a second listener.
if (!Object.prototype.hasOwnProperty.call(window, GUARD)) {
  Object.defineProperty(window, GUARD, { value: true, enumerable: false, configurable: true });
  ext.runtime.onMessage.addListener(onMessage);
}
