// Content script entry (spec 4, 8.2 to 8.5). The page is hostile: nothing it
// supplies is trusted, every gesture must be `isTrusted`, and every value the
// service worker sends is pinned to the origin it verified.
//
// `createContentScript` builds the script against any document and any
// runtime (tests use jsdom and a fake); the bottom of this file starts it for
// real. Nothing is exposed on `window` or `document`.
//
// Smart fill: a trusted click on a field's icon, and the worker's
// `smart_fill` (popup Fill, `fill-smart` command), build the page context
// here (no value in it, the typed username only as a salted hash), and send
// it as `plan_context`; the worker plans and fills. These are the only
// senders of `fill_salt` and `plan_context`: never a focus, a click into a
// field (`auto`), a page load or a mutation. When the worker answers "menu",
// fails or does not answer, the menu opens instead (never a blind fill).
//
// Shadow roots (spec D1, D2): each analysis walks the page for the shadow
// roots of its web components and reads their forms as the document's.
// Open roots through `el.shadowRoot`; closed ones through
// `chrome.dom.openOrClosedShadowRoot` where the browser gives it to content
// scripts (Chromium; feature-detected). Limit: without that API (Safari) a
// closed root stays out of reach. The walk is bounded (3000 elements, roots
// nested 8 deep, `detect/shadow.ts`): a form past the bound is not seen. Our
// own closed root is never walked. Every root found is observed as the
// document is, and gets the document's listeners: an event from a root is
// read from its real target, not the host it is retargeted to, so trusted
// gestures, the menu keys and submissions work across the boundary. A root
// attached without any mutation the observer can see is found on the next
// trusted focus or ArrowDown into its host.
import { ext as browserExt, openOrClosedShadowRoot } from "../shared/browser";
import { hasVisibilityV2 } from "../shared/click-guard";
import { parseOrigin } from "../shared/domain";
import type { BgToCs, CsToBg, FieldRole, FillHints, FrameKind, PageAnalysis } from "../shared/messages";
import { NEW_PASSWORD_FORMS } from "../shared/messages";
import { buildPageContext, findTypedUsername, withTypedUsernameHash } from "./context";
import { classifierFor, createModelHook, type ModelHook, remoteSession } from "./detect/classifier";
import { analyzeDocument } from "./detect/forms";
import { FormLineage, RefRegistry } from "./detect/refs";
import {
  collectShadowRoots,
  composedContains,
  deepActiveElement,
  openShadowRoot,
  type ShadowRootOf,
  TreeListeners,
  WatchedRoots,
} from "./detect/shadow";
import { domFieldHitTest, domGeometry, type FieldHitTest, type Geometry, hitIsField } from "./detect/visibility";
import { createFiller, SETTLE_MS } from "./filler";
import { collectPasswordContext, patternMatches } from "./password-context";
import { usernameFits } from "./username-fit";
import { checkFrameUrl, createFrames, createShell, type Layout, type Shell, watchLayout } from "./frames";
import { fitGhost } from "./ghost-fit";
import { createIcons, type IconTarget } from "./icon";
import { createObserver, OBSERVER_DELAY_MS } from "./observer";
import { domHitTest, type HitTest } from "./occlusion";
import { createSubmitWatcher } from "./submit";
import { cornerOccupants, knownOccupantsIn } from "./occupants";

/** While the save card shows, other managers' corner UI is looked at this often. */
const OCCUPANT_POLL_MS = 750;
import type { RecorderHooks } from "../dev/recorder-content";

type Sender = { id?: string };

/** The slice of the WebExtension API the content script uses. */
export interface ContentExt {
  runtime: {
    id: string;
    getURL(path: string): string;
    sendMessage(message: unknown): Promise<unknown>;
    onMessage: {
      addListener(cb: (message: unknown, sender: Sender, sendResponse: (r: unknown) => void) => boolean | undefined | void): void;
    };
  };
}

export interface ContentOptions {
  doc: Document;
  ext: ContentExt;
  /** Current URL of the frame (`location.href`), read at every check. */
  href: () => string;
  geometry?: Geometry;
  /** Gesture check; `event.isTrusted` in production. */
  isTrusted?: (e: Event) => boolean;
  /** Frame scheduler for repositioning; `requestAnimationFrame` by default. */
  raf?: (cb: () => void) => void;
  /**
   * The shadow root of a page element the script may read: open and closed
   * roots through `chrome.dom.openOrClosedShadowRoot` where the browser has
   * it, else open roots only.
   */
  shadowRootOf?: ShadowRootOf;
  /** The in-page layout (touch, bottom sheet); a live `watchLayout` of the window by default. */
  layout?: () => Layout;
  /** Clock of the icons' click guard; `performance.now` by default. */
  now?: () => number;
  /** Topmost element at a viewport point; `document.elementFromPoint` by default. */
  hitTest?: HitTest;
  /** Topmost element at a point, seen from a field's own root (personal data fills); `elementFromPoint` there by default. */
  fieldHitTest?: FieldHitTest;
  /**
   * Whether the content script watches its frames for covers (occlusion.ts). By default only where
   * the frames lack IntersectionObserver v2 (Firefox, Safari); Chromium's frames guard themselves.
   */
  watchCovers?: boolean;
  /**
   * Whether the document's origin is opaque (a sandboxed frame without `allow-same-origin`, a
   * document served with `CSP: sandbox`): `self.origin === "null"` by default.
   */
  opaqueOrigin?: () => boolean;
}

export interface ContentScript {
  start(): void;
  stop(): void;
  /** For this script's tests only; never reachable from the page. */
  readonly internals: { readonly root: ShadowRoot; readonly refs: RefRegistry };
}

const FRAME_KINDS: ReadonlySet<string> = new Set<FrameKind>(["menu", "overlay", "save", "ghost"]);
const MAX_VALUE = 4096;

function str(v: unknown): v is string {
  return typeof v === "string" && v.length <= MAX_VALUE;
}

/** Values of a `fill` message: string values only, nothing inherited. */
function fillValues(v: unknown): Partial<Record<FieldRole, string>> | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const out: Partial<Record<FieldRole, string>> = {};
  for (const [k, x] of Object.entries(v)) if (str(x)) out[k as FieldRole] = x;
  return out;
}

/** The hints of a fill message: known keys of the right type only. */
function fillHints(v: unknown): FillHints {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return {};
  const h = v as Record<string, unknown>;
  const out: FillHints = {};
  if (typeof h.sex === "string" && /^[fmx]$/.test(h.sex)) out.sex = h.sex;
  if (h.civility_from_sex === true) out.civility_from_sex = true;
  if (str(h.work_tel)) out.work_tel = h.work_tel;
  return out;
}

const isControl = (t: EventTarget | null): boolean =>
  t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement;

/** Field `k` of a reply's `ok` payload (`{ok: {k}}`), or undefined (error envelope, no reply). */
function okField(r: unknown, k: string): unknown {
  const ok = (r as { ok?: unknown } | null)?.ok;
  return typeof ok === "object" && ok !== null ? (ok as Record<string, unknown>)[k] : undefined;
}

/** The URL in an `open_menu` reply (`{ok: {url}}`), or null. */
function replyUrl(r: unknown): string | null {
  const ok = (r as { ok?: unknown } | null)?.ok;
  const url = (ok as { url?: unknown } | null | undefined)?.url;
  return typeof url === "string" ? url : null;
}

/** Longest wait of a fill reply for later writes (region list reload, combobox pick). */
export const REPLY_MAX_MS = SETTLE_MS + 500;

/**
 * attachShadow makes no mutation record: a page with custom elements is looked at again this
 * long after start for a shadow root (a closed one included) no analysis has seen yet.
 */
export const LATE_ROOT_CHECKS_MS: readonly number[] = [500, 1_500, 3_000, 6_000, 10_000];

/** A focus opens the ghost only this soon after a trusted gesture of the user (spec 3.5). */
export const GHOST_GESTURE_MS = 1000;


export function createContentScript(o: ContentOptions): ContentScript {
  const { doc, ext } = o;
  const geometry = o.geometry ?? domGeometry;
  const isTrusted = o.isTrusted ?? ((e: Event) => e.isTrusted);
  const view = doc.defaultView;
  const raf = o.raf ?? ((cb: () => void) => (view ? view.requestAnimationFrame(() => cb()) : setTimeout(cb, 16)));
  const refs = new RefRegistry();
  const lineage = new FormLineage(refs);
  const shadowRootOf: ShadowRootOf = o.shadowRootOf ?? openOrClosedShadowRoot ?? openShadowRoot;
  const watched = new WatchedRoots();
  const tree = new TreeListeners(watched);
  let shell: Shell | null = null;
  /** Our own host: its closed root is never walked nor read. */
  const isOwnHost = (el: Element): boolean => shell?.isHost(el) === true;
  /** The readable shadow root of `t`, or null (never ours; the API may throw on odd nodes). */
  const rootOf = (t: EventTarget | null): ShadowRoot | null => {
    if (!(t instanceof Element) || isOwnHost(t)) return null;
    try {
      return shadowRootOf(t);
    } catch {
      return null;
    }
  };
  let stopped = false;
  const cleanups: (() => void)[] = [];
  // Dev-only form flow recorder: loaded only when the build defines it.
  let recorder: RecorderHooks | null = null;

  /**
   * An opaque origin (sandboxed frame, `CSP: sandbox`): the document is NOT its URL's origin. Its
   * scripts are the isolated content a site serves from its own URL space, so it never gets that
   * origin's logins. Firefox does not stamp `sender.origin` on messages, so the worker would take
   * the URL's origin: the content script refuses here, as the passkey router does there.
   */
  const opaque = o.opaqueOrigin ?? (() => (view as (Window & { origin?: string }) | null)?.origin === "null");

  /** Normalized origin of the frame right now (null when not a page to fill: HTTPS or loopback http; or when the document's origin is opaque). */
  const currentOrigin = (): string | null => {
    if (opaque()) return null;
    const p = parseOrigin(o.href());
    return p?.page ? p.origin : null;
  };

  const send = (m: CsToBg): Promise<unknown> => ext.runtime.sendMessage(m).catch(() => null);

  // Model builds only (Task 15): set once the service worker's model answered the handshake.
  let model: ModelHook | undefined;

  const analyze = (): PageAnalysis => {
    refs.prune();
    const shadowRoots = collectShadowRoots(doc, { shadowRootOf, skip: isOwnHost });
    // New roots get the observer and the listeners at once.
    watched.add(shadowRoots);
    const base = { url: o.href(), geometry, shadowRoots };
    const a = analyzeDocument(doc, refs, model ? { ...base, model } : base);
    lineage.record(a);
    return a;
  };

  // Lazily built in start(): nothing touches the page on a non-HTTPS frame.
  let parts: {
    shell: Shell;
    frames: ReturnType<typeof createFrames>;
    icons: ReturnType<typeof createIcons>;
    observer: ReturnType<typeof createObserver>;
    filler: ReturnType<typeof createFiller>;
    submit: ReturnType<typeof createSubmitWatcher>;
  } | null = null;

  /** Set in start(): drops an open ghost when the layout turned to touch (resize, rotation). */
  let ghostLayoutCheck = (): void => undefined;
  /** Set in start(): the frames removed the ghost of `field` on their own. */
  let ghostRemovedByFrames = (_field: Element): void => undefined;
  let layoutQueued = false;
  const queueLayout = () => {
    if (layoutQueued || stopped) return;
    layoutQueued = true;
    raf(() => {
      layoutQueued = false;
      if (!parts || stopped) return;
      ghostLayoutCheck();
      parts.icons.reposition();
      const ghostAt = parts.frames.has("ghost") ? parts.frames.anchorOf("ghost") : null;
      parts.frames.reposition();
      if (ghostAt && !parts.frames.has("ghost")) ghostRemovedByFrames(ghostAt);
    });
  };

  let menuSeq = 0;
  let lastKeyAnalysis = Number.NEGATIVE_INFINITY;
  /** An arrow key moved the menu's highlight: Return now picks it (and not the page's form). */
  let menuArmed = false;
  const closeMenu = (notify: boolean) => {
    menuArmed = false;
    if (!parts?.frames.has("menu")) return;
    parts.frames.removeFrame("menu");
    if (notify) void send({ type: "close_menu" });
  };

  /**
   * `auto`: opened by a click into the field, not asked for by the icon or a
   * key; the worker opens it only when it has something to offer there.
   */
  const openMenu = async (t: IconTarget, auto = false) => {
    const seq = ++menuSeq;
    menuArmed = false;
    const req: CsToBg = { type: "open_menu", fieldRef: t.fieldRef, formRef: t.form.ref, formKind: t.form.kind };
    if (auto) req.auto = true;
    const reply = await send(req);
    if (seq !== menuSeq || !parts || stopped || !t.el.isConnected) return;
    const raw = replyUrl(reply);
    // The very URL the worker returned for this request: vouched.
    const url = raw === null ? null : checkFrameUrl(raw, "menu", ext.runtime.getURL(""), true);
    if (url === null) return;
    parts.frames.showFrame("menu", url, t.el);
  };

  let smartSeq = 0;
  /** Where the menu opens for a gesture without a field (popup, command): the focused field, else the first one. */
  const fallbackTarget = (): IconTarget | null => {
    if (!parts) return null;
    const focused = parts.icons.targetOf(deepActiveElement(doc, shadowRootOf, isOwnHost));
    if (focused) return focused;
    return parts.icons.all().find((x) => x.el.isConnected) ?? null;
  };

  /**
   * Smart fill, from a trusted gesture only: `t` is the field whose icon was
   * clicked, null for the popup's Fill and the `fill-smart` command.
   */
  const smartFill = async (t: IconTarget | null) => {
    const origin = currentOrigin();
    if (!parts || stopped || origin === null) return;
    const seq = ++smartSeq;
    const a = parts.observer.refresh();
    const salt = okField(await send({ type: "fill_salt" }), "salt");
    if (seq !== smartSeq || !parts || stopped) return;
    let ctx = buildPageContext(doc, refs, a, { origin, topOrigin: origin, frame: "top" }, geometry);
    // No salt (bridge down): no hash; the plan just does without the typed username.
    if (typeof salt === "string") ctx = await withTypedUsernameHash(ctx, salt, findTypedUsername(a, refs));
    const msg: CsToBg = { type: "plan_context", context: { forms: ctx.forms, typed_username_hash: ctx.typed_username_hash } };
    if (t) {
      msg.formRef = t.form.ref;
      msg.fieldRef = t.fieldRef;
    } else if (fallbackTarget() === null) {
      // No field here to open the menu under: a locked vault gets a card of the page to wait in.
      msg.bare = true;
    }
    const outcome = okField(await send(msg), "outcome");
    if (seq !== smartSeq || !parts || stopped) return;
    if (outcome === "filled" || outcome === "chain") return;
    // Nothing to do for a gesture without a field (an ignored page).
    if (outcome === "nothing" && !t) return;
    // "menu", an error (bridge down, invalid context, origin mismatch) or no answer: the menu.
    const target = t?.el.isConnected ? t : fallbackTarget();
    if (target) await openMenu(target);
  };

  const pinned = (origin: unknown): boolean => {
    const here = currentOrigin();
    return typeof origin === "string" && here !== null && origin === here;
  };

  /** The form of `formRef` and its `new_password` / `confirm_password` fields; null when none. */
  const newPasswordFields = (formRef: string): { container: Element; fields: Element[] } | null => {
    if (!parts) return null;
    const form = lineage.resolve(formRef, parts.observer.refresh());
    const container = form ? refs.get(form.ref) : null;
    if (!form || !container) return null;
    const fields: Element[] = [];
    for (const f of form.fields) {
      if (f.role !== "new_password" && f.role !== "confirm_password") continue;
      const el = refs.get(f.ref);
      if (el) fields.push(el);
    }
    return fields.length > 0 ? { container, fields } : null;
  };

  const onMessage = (message: unknown, sender: Sender, sendResponse: (r: unknown) => void): true | undefined => {
    if (!parts || stopped || sender?.id !== ext.runtime.id) return undefined;
    if (typeof message !== "object" || message === null) return undefined;
    const m = message as Partial<BgToCs> & Record<string, unknown>;
    let ok = false;
    switch (m.type) {
      case "fill": {
        const values = fillValues(m.values);
        if (pinned(m.origin) && typeof m.formRef === "string" && values) {
          const r = parts.filler.fill(m.formRef, values, fillHints(m.hints));
          const reply = (filled: FieldRole[]) => {
            const done = filled.length > 0;
            if (done && parts && !stopped) closeMenu(true);
            sendResponse({ ok: done, filled });
          };
          // A region that waits for its list, a combobox pick: the reply
          // waits too (bounded), so it names what the page really holds.
          if (r.pending) {
            let sent = false;
            const once = (filled: FieldRole[]) => {
              if (sent) return;
              sent = true;
              clearTimeout(cap);
              reply(filled);
            };
            // Later writes may chain (combobox, then region): the reply never waits past the cap.
            const cap = setTimeout(() => once(r.soFar()), REPLY_MAX_MS);
            void r.done.then(once, () => once(r.filled));
            return true;
          }
          reply(r.filled);
          return undefined;
        }
        break;
      }
      case "click":
        if (pinned(m.origin) && typeof m.ref === "string") ok = parts.submit.clickRef(m.ref);
        break;
      case "click_passkey":
        // The user's choice in the signup menu; only in the top frame it was made for.
        if (pinned(m.origin) && typeof m.ref === "string" && window === window.top) ok = parts.submit.clickPasskey(m.ref);
        break;
      case "click_passkey_signin":
        // A gesture of the user on a page with no form; the top frame only.
        if (pinned(m.origin) && window === window.top) ok = parts.submit.clickPasskeySignIn();
        break;
      case "submit":
        if (pinned(m.origin) && typeof m.ref === "string") ok = parts.submit.submitForm(m.ref, m.planned === true);
        break;
      case "smart_fill": {
        // Our worker, on a click in the popup or the command's key: a gesture of the user.
        if (m.fieldRef === undefined) {
          // A resume after an unlock names the origin its card waited on: here still, or nothing.
          if (m.origin !== undefined && !pinned(m.origin)) break;
          void smartFill(null);
          ok = true;
          break;
        }
        // The field of a menu the user unlocked from (the sheet, or the app): that very field
        // again, at the origin its menu opened on, or nothing.
        if (typeof m.fieldRef !== "string" || !pinned(m.origin)) break;
        const el = refs.get(m.fieldRef);
        let t = el ? parts.icons.targetOf(el) : undefined;
        if ((!t || !t.el.isConnected) && typeof m.formRef === "string") {
          // The page redrew the form while the unlock was pending (the field's ref died with it):
          // the one copy of that very form takes the fill, from its first field.
          const form = lineage.resolve(m.formRef, parts.observer.refresh());
          const all = parts.icons;
          t = form ? all.all().find((x) => x.form.ref === form.ref && x.el.isConnected) : undefined;
        }
        if (!t || !t.el.isConnected) break;
        void smartFill(t);
        ok = true;
        break;
      }
      case "plan_request": {
        // A context to plan with (popup line, chain replan): no hash, nothing typed leaves.
        const origin = currentOrigin();
        if (origin === null) break;
        const ctx = buildPageContext(doc, refs, parts.observer.refresh(), { origin, topOrigin: origin, frame: "top" }, geometry);
        sendResponse({ ok: true, context: { forms: ctx.forms, typed_username_hash: null } });
        return undefined;
      }
      case "password_context": {
        // The page's rules for its new password fields: attributes and nearby text, never a value.
        if (!pinned(m.origin) || typeof m.formRef !== "string") break;
        const found = newPasswordFields(m.formRef);
        if (!found) break;
        const { context, pattern } = collectPasswordContext(found.container, found.fields);
        sendResponse({ ok: true, context, has_pattern: pattern !== null });
        return undefined;
      }
      case "pattern_check": {
        // A candidate against the field's own pattern, read here again (the worker never runs it).
        if (!pinned(m.origin) || typeof m.formRef !== "string" || typeof m.candidate !== "string") break;
        const found = newPasswordFields(m.formRef);
        if (!found) break;
        const { pattern } = collectPasswordContext(found.container, found.fields);
        sendResponse({ ok: true, matches: patternMatches(pattern, m.candidate) });
        return undefined;
      }
      case "username_check": {
        // A sign-up identifier against the username field's own attributes (MS-06).
        if (!pinned(m.origin) || typeof m.formRef !== "string" || typeof m.candidate !== "string" || !parts) break;
        const form = lineage.resolve(m.formRef, parts.observer.refresh());
        const fi = form?.fields.find((x) => x.role === "username");
        const el = fi ? refs.get(fi.ref) : null;
        if (!el) break;
        const fit = usernameFits(el, m.candidate);
        sendResponse(fit.maxLength !== undefined ? { ok: true, matches: fit.matches, max_length: fit.maxLength } : { ok: true, matches: fit.matches });
        return undefined;
      }
      case "show_frame": {
        if (typeof m.kind !== "string" || !FRAME_KINDS.has(m.kind) || typeof m.url !== "string") break;
        // An origin pin (delivery by frameId only) must match this document.
        if (m.origin !== undefined && !pinned(m.origin)) break;
        const kind = m.kind as FrameKind;
        // Sent by our service worker (sender checked above): vouched.
        const url = checkFrameUrl(m.url, kind, ext.runtime.getURL(""), true);
        if (url === null) break;
        const anchor = typeof m.ref === "string" ? refs.get(m.ref) : null;
        // The menu and the ghost belong to a field: no field, no frame.
        if ((kind === "menu" || kind === "ghost") && !anchor) break;
        parts.frames.showFrame(kind, url, anchor);
        ok = true;
        break;
      }
      case "remove_frame":
        if (typeof m.kind === "string" && FRAME_KINDS.has(m.kind)) {
          parts.frames.removeFrame(m.kind as FrameKind);
          ok = true;
        }
        break;
      case "resize_frame":
        if (typeof m.kind === "string" && FRAME_KINDS.has(m.kind) && typeof m.height === "number") {
          parts.frames.resize(m.kind as FrameKind, m.height, typeof m.width === "number" ? m.width : undefined);
          ok = true;
        }
        break;
      case "ghost_pill": {
        // The ghost page's pill box (frame-local), vouched by the worker: the pointer pass-through.
        const r = m.rect as Partial<Record<"x" | "y" | "width" | "height", unknown>> | null;
        const n = (v: unknown) => typeof v === "number" && Number.isFinite(v);
        if (!r || typeof r !== "object" || !n(r.x) || !n(r.y) || !n(r.width) || !n(r.height) || typeof m.over !== "boolean") break;
        parts.frames.ghostPill({ x: r.x as number, y: r.y as number, width: r.width as number, height: r.height as number }, m.over);
        ok = true;
        break;
      }
      case "chain_highlight":
        if (m.ref === null) parts.frames.highlight(null);
        else if (typeof m.ref === "string") parts.frames.highlight(refs.get(m.ref));
        ok = true;
        break;
      default:
        return undefined;
    }
    sendResponse({ ok });
    return undefined;
  };

  /** Listens on `target` and on every watched shadow root (an event once, from its real target). */
  const listen = (target: EventTarget, type: string, fn: (e: Event) => void, options: AddEventListenerOptions, filter = true) => {
    cleanups.push(tree.listen(target, type, fn, options, filter));
  };

  /** A host whose shadow root no analysis has seen yet (attached without a mutation, say). */
  const unseenRoot = (t: EventTarget | null): boolean => {
    const r = rootOf(t);
    return r !== null && !watched.has(r);
  };
  let lastRootAnalysis = Number.NEGATIVE_INFINITY;

  return {
    get internals() {
      if (!shell) shell = createShell(doc);
      return { root: shell.root, refs };
    },
    start() {
      if (parts || stopped || currentOrigin() === null) return;
      shell ??= createShell(doc);
      const sh = shell;
      // Other password managers' UI: our card and icons go beside it, never under or over.
      const own = { isOwn: (n: Node) => sh.isHost(n) };
      // Touch or not, sheet or popover: live (a trackpad, a rotation, Slide Over change it).
      let layout = o.layout;
      if (!layout) {
        const watch = watchLayout(view);
        watch.onChange(queueLayout);
        cleanups.push(() => watch.destroy());
        layout = () => watch.current();
      }
      const currentLayout = layout;
      const hitTest = o.hitTest ?? domHitTest(doc);
      const scopes = () => watched.roots();
      const covers = (o.watchCovers ?? !hasVisibilityV2()) ? { hitTest, scopes } : undefined;
      const frames = createFrames({
        shell: sh,
        doc,
        geometry,
        layout: currentLayout,
        occupants: () => cornerOccupants(doc, own),
        ...(covers ? { covers } : {}),
      });
      const icons = createIcons({
        hitTest,
        scopes,
        ...(o.now ? { now: o.now } : {}),
        shell: sh,
        doc,
        refs,
        geometry,
        layout: currentLayout,
        isTrusted,
        onOpen: (t) => void smartFill(t),
        onLayout: queueLayout,
        avoid: (zone) => knownOccupantsIn(doc, zone, own),
      });
      // They come, move and go: what is added to or removed from the top of the document, and,
      // while our save card shows, a cheap look every OCCUPANT_POLL_MS (theirs may move inside a shadow root).
      const MO = view?.MutationObserver;
      if (MO) {
        const mo = new MO(() => queueLayout());
        if (doc.documentElement) mo.observe(doc.documentElement, { childList: true });
        if (doc.body) mo.observe(doc.body, { childList: true });
        cleanups.push(() => mo.disconnect());
      }
      const poll = setInterval(() => {
        if (parts?.frames.has("save")) queueLayout();
      }, OCCUPANT_POLL_MS);
      cleanups.push(() => clearInterval(poll));
      const observer = createObserver({
        doc,
        analyze,
        isOwn: (n) => sh.isHost(n),
        onMutation: () => sh.ensureAttached(),
        onChange: (a) => {
          icons.attachIcons(a);
          void send({ type: "page_analysis", analysis: a });
        },
      });
      if (__CLASSIFIER__ !== "heuristic") {
        const kind = __CLASSIFIER__;
        void classifierFor(kind, { load: () => remoteSession((m) => ext.runtime.sendMessage(m), kind) }).then((c) => {
          if (c.kind === "heuristic" || stopped || !parts) return;
          const refresh = () => {
            if (parts && !stopped) parts.observer.refresh();
          };
          model = createModelHook({ classifier: c, onUpdate: refresh });
          refresh();
        });
      }
      if (__LAB_RECORDER__) {
        void import("../dev/recorder-content").then((m) => {
          if (!stopped) recorder = m.default({ doc, send: (msg) => ext.runtime.sendMessage(msg), isTrusted });
        });
      }
      const filler = createFiller({
        refs,
        geometry,
        analyze: () => observer.refresh(),
        resolve: (ref, a) => lineage.resolve(ref, a),
        onFill: (el, role) => recorder?.noteFilled(el, role),
        activeElement: () => deepActiveElement(doc, shadowRootOf, isOwnHost),
        lang: () => doc.documentElement?.lang ?? null,
        isOwn: (el) => sh.isHost(el),
        ...(o.fieldHitTest ? { hitTest: o.fieldHitTest } : {}),
      });
      const submit = createSubmitWatcher({
        doc,
        refs,
        geometry,
        isTrusted,
        latest: () => observer.latest(),
        analyze: () => observer.refresh(),
        resolve: (ref, a) => lineage.resolve(ref, a),
        onCredentials: (c) => void send(c),
        onIdentifier: (c) => void send(c),
        onForm: (c) => void send(c),
        onStep: (c) => recorder?.step(c),
        listen: (t, type, fn, options) => tree.listen(t, type, fn, options),
      });
      parts = { shell: sh, frames, icons, observer, filler, submit };

      // ---- the ghost (spec 3.1, 3.3 to 3.5) ----
      // The suggested password lives in the worker and the ghost page only: this script asks for
      // the ghost (`ghost_open`, metrics only) and reads the user's keys while it shows; it never
      // sees the password.
      /** Last trusted gesture of the user (pointer, key, click), `Date.now()`. */
      let lastGesture = Number.NEGATIVE_INFINITY;
      /** Fields whose ghost the user dismissed (typing, Escape); a new URL clears them. */
      let dismissed = new WeakSet<Element>();
      let dismissedHref = o.href();
      const isDismissed = (el: Element): boolean => {
        const href = o.href();
        if (href !== dismissedHref) {
          dismissed = new WeakSet();
          dismissedHref = href;
        }
        return dismissed.has(el);
      };
      /** The field offered something (ghost or menu) during its current focus: once per visit. */
      let offered: Element | null = null;
      /** The field a `ghost_open` is on its way for. */
      let ghostPending: Element | null = null;
      let ghostSeq = 0;
      const ghostField = (): Element | null => (frames.has("ghost") ? frames.anchorOf("ghost") : null);
      const ghostFocused = (): boolean => {
        const a = sh.root.activeElement;
        return a instanceof HTMLIFrameElement && a.classList.contains("ghost");
      };
      const focusedField = () => deepActiveElement(doc, shadowRootOf, isOwnHost);
      /** The ghost goes (not dismissed: the field gets it again on the next focus). */
      const dropGhost = () => {
        ghostSeq++;
        ghostPending = null;
        frames.removeFrame("ghost");
      };
      ghostLayoutCheck = () => {
        if (currentLayout().touch && (frames.has("ghost") || ghostPending)) dropGhost();
      };
      ghostRemovedByFrames = (field) => {
        // Its field left the viewport (frames.reposition): a trusted click back into the field,
        // focused still, may offer again.
        if (offered === field) offered = null;
      };
      /** A new-password field of a signup or change-password form, empty, not dismissed. */
      const ghostEligible = (t: IconTarget): t is IconTarget & { el: HTMLInputElement } =>
        t.el instanceof HTMLInputElement &&
        t.el.value === "" &&
        !t.el.disabled &&
        !t.el.readOnly &&
        NEW_PASSWORD_FORMS.has(t.form.kind) &&
        t.form.fields.some((f) => f.ref === t.fieldRef && f.role === "new_password") &&
        !isDismissed(t.el);
      /**
       * Partly covered (spec 3.4): the hit test of the field's own root (a shadow root answers with
       * its own elements) at its center and inset corners finds something else than the field, an
       * element inside it or our host. No hit testing in this engine: not covered.
       */
      const fieldHitTest = o.fieldHitTest ?? domFieldHitTest;
      const fieldCovered = (el: Element): boolean => {
        const r = el.getBoundingClientRect();
        const inset = 2;
        const points: [number, number][] = [
          [r.left + r.width / 2, r.top + r.height / 2],
          [r.left + inset, r.top + inset],
          [r.right - inset, r.top + inset],
          [r.left + inset, r.bottom - inset],
          [r.right - inset, r.bottom - inset],
        ];
        for (const [x, y] of points) {
          const hit = fieldHitTest(el, x, y);
          if (hit === null || hit === undefined) continue;
          if (hitIsField(el, hit, (h) => sh.isHost(h))) continue;
          return true;
        }
        return false;
      };
      /**
       * A trusted focus (or a tap on touch) into `t`: the ghost when it fits, else the menu on its
       * suggestion row (spec 3.4; touch layouts always, ruling of Task 6). Once per focus visit.
       */
      const offerGhost = async (t: IconTarget) => {
        if (stopped || !parts || !ghostEligible(t)) return;
        if (Date.now() - lastGesture > GHOST_GESTURE_MS) return;
        if (offered === t.el || ghostField() === t.el || ghostPending === t.el) return;
        if (frames.has("menu") && frames.anchorOf("menu") === t.el) return;
        offered = t.el;
        if (currentLayout().touch || !view) {
          void openMenu(t, true);
          return;
        }
        const fit = fitGhost(t.el, view, fieldCovered);
        if (!fit.ok) {
          void openMenu(t, true);
          return;
        }
        if (frames.has("ghost")) dropGhost();
        const seq = ++ghostSeq;
        ghostPending = t.el;
        const reply = await send({ type: "ghost_open", fieldRef: t.fieldRef, formRef: t.form.ref, formKind: t.form.kind, metrics: fit.metrics });
        if (seq !== ghostSeq) return;
        ghostPending = null;
        if (!parts || stopped || !t.el.isConnected || !ghostEligible(t) || focusedField() !== t.el) return;
        const raw = replyUrl(reply);
        // The very URL the worker returned for this request: vouched.
        const url = raw === null ? null : checkFrameUrl(raw, "ghost", ext.runtime.getURL(""), true);
        // No ghost from the worker (a cross-origin frame, a page refusing every draw): the menu.
        if (url === null) {
          void openMenu(t, true);
          return;
        }
        frames.showFrame("ghost", url, t.el);
      };
      /** Tab, Enter: the worker fills its held password; the ghost has nothing left to show. */
      const acceptGhost = () => {
        dropGhost();
        void send({ type: "ghost_accept" });
      };
      /** A printable key, Escape, typing: the ghost goes and stays away from this field. */
      const dismissGhost = (el: Element) => {
        isDismissed(el);
        dismissed.add(el);
        dropGhost();
        void send({ type: "ghost_dismiss" });
      };
      /** Arrow Down: the ghost goes, the menu opens at its field on the same suggestion. */
      const ghostToMenu = async (el: Element) => {
        dropGhost();
        const seq = ++menuSeq;
        menuArmed = false;
        const reply = await send({ type: "ghost_menu" });
        if (seq !== menuSeq || !parts || stopped || !el.isConnected) return;
        const raw = replyUrl(reply);
        const url = raw === null ? null : checkFrameUrl(raw, "menu", ext.runtime.getURL(""), true);
        if (url !== null) frames.showFrame("menu", url, el);
      };
      /** The keyup still to come of an accepted Tab or Enter, on its field. */
      let swallowKeyup: { el: Element; key: string } | null = null;
      /** The keys of the field under the ghost (trusted, read here only while it shows). True: handled. */
      const ghostKey = (e: KeyboardEvent, field: Element): boolean => {
        if (currentLayout().touch) {
          dropGhost();
          return false;
        }
        if (e.ctrlKey || e.metaKey || e.altKey) return false;
        if ((e.key === "Tab" || e.key === "Enter") && !e.shiftKey) {
          e.preventDefault();
          e.stopImmediatePropagation();
          // Its keyup is ours too: a page that submits on keyup Enter never sees it.
          swallowKeyup = { el: field, key: e.key };
          acceptGhost();
          return true;
        }
        if (e.key === "Escape") {
          dismissGhost(field);
          return true;
        }
        if (e.key === "ArrowDown" && !e.shiftKey) {
          e.preventDefault();
          void ghostToMenu(field);
          return true;
        }
        // A printable key (one character): it reaches the field as typed.
        if ([...e.key].length === 1) {
          dismissGhost(field);
          return true;
        }
        return false;
      };
      const gesture = (e: Event) => {
        if (isTrusted(e)) lastGesture = Date.now();
      };
      for (const type of ["pointerdown", "mousedown", "touchstart", "keydown", "click"]) {
        listen(doc, type, gesture, { capture: true, passive: true });
      }

      ext.runtime.onMessage.addListener(onMessage);
      const target: EventTarget = view ?? doc;
      // Unfiltered: a scroll of a host itself is not seen inside its root.
      listen(target, "scroll", queueLayout, { capture: true, passive: true }, false);
      listen(target, "resize", queueLayout, { passive: true });
      // iOS: the keyboard moves the visual viewport only (the touch sheet sits on it).
      const vv = view?.visualViewport;
      if (vv) {
        listen(vv, "resize", queueLayout, { passive: true }, false);
        listen(vv, "scroll", queueLayout, { passive: true }, false);
      }
      listen(
        doc,
        "keydown",
        (e) => {
          if (!isTrusted(e) || !(e instanceof KeyboardEvent)) return;
          if (swallowKeyup && swallowKeyup.key !== e.key) swallowKeyup = null;
          // The ghost shows over this very field: its keys first (spec 3.3).
          const g = ghostField();
          if (g !== null && e.target === g && ghostKey(e, g)) return;
          if (e.key === "Escape") {
            closeMenu(true);
            return;
          }
          if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
          // Menu open under this field: the arrows move its highlight and
          // Return picks it, with the focus kept in the page (spec 8.3).
          if (parts?.frames.has("menu") && parts.frames.anchorOf("menu") === e.target) {
            if (e.key === "ArrowDown" || e.key === "ArrowUp") {
              e.preventDefault();
              menuArmed = true;
              void send({ type: "menu_key", key: e.key === "ArrowDown" ? "down" : "up" });
            } else if (e.key === "Enter" && menuArmed) {
              e.preventDefault();
              e.stopPropagation();
              // A menu something covers (no IOv2 there to tell the frame): the key picks nothing.
              if (!parts.frames.covered("menu")) void send({ type: "menu_key", key: "enter" });
            }
            return;
          }
          if (e.key !== "ArrowDown") return;
          // A field the page added since the last analysis (it runs 150 ms
          // after a mutation burst): analyse now rather than miss the key.
          // At most one such analysis per observer delay: a held key does not
          // analyse the page on every repeat.
          // A host whose root is not known yet: the analysis finds it, and
          // the root's own listener (attached now) reads this very key.
          let t = icons.targetOf(e.target);
          const now = Date.now();
          if (!t && (isControl(e.target) || unseenRoot(e.target)) && now - lastKeyAnalysis >= OBSERVER_DELAY_MS) {
            lastKeyAnalysis = now;
            observer.refresh();
            t = icons.targetOf(e.target);
          }
          if (!t || parts?.frames.has("menu")) return;
          e.preventDefault();
          void openMenu(t);
        },
        { capture: true },
      );
      listen(
        doc,
        "click",
        (e) => {
          // Spec 8.7: a trusted click on a provider button of a site, or on an
          // account of a provider's chooser, is reported (refs only, plus the
          // email the chooser shows; the worker checks hosts from `sender`).
          if (!isTrusted(e) || !(e.target instanceof Node) || sh.isHost(e.target)) return;
          const a = observer.latest();
          if (!a) return;
          // A button's own shadow root (its label, say) is inside the button.
          const hit = (ref: string) => {
            const el = refs.get(ref);
            return el !== null && composedContains(el, e.target as Node);
          };
          const b = a.providerButtons.find((x) => hit(x.ref));
          if (b) {
            void send({ type: "provider_click", provider: b.provider, ref: b.ref });
            return;
          }
          const acc = a.accountChooser.find((x) => hit(x.ref));
          if (acc) void send({ type: "account_click", email: acc.email, ref: acc.ref });
        },
        { capture: true },
      );
      listen(
        doc,
        "click",
        (e) => {
          // A click into an empty field offers its logins, as the browser's
          // own autofill does; only when the worker has something for it.
          // Not on a touch screen (IOSSAF-08, IPAD-01): the tap raises the keyboard and iOS
          // scrolls the field above it, where a sheet would sit; the field's icon (one tap, the
          // fill itself) and the keyboard's own bar offer the same there.
          if (!isTrusted(e) || parts?.frames.has("menu") || currentLayout().touch) return;
          const t = icons.targetOf(e.target);
          if (!t || !(t.el instanceof HTMLInputElement) || t.el.value !== "") return;
          // A new-password field of a signup or change-password form: the ghost instead (spec
          // 3.1), or the menu its fallback opens; once per focus visit, from the focus or here.
          if (ghostEligible(t)) {
            void offerGhost(t);
            return;
          }
          void openMenu(t, true);
        },
        { capture: false },
      );
      listen(
        doc,
        "input",
        (e) => {
          // Typing in the field: the user does it by hand, the menu steps aside.
          if (isTrusted(e) && parts?.frames.anchorOf("menu") === e.target) closeMenu(true);
          // Text that came without a key the ghost read (a paste, an input method): dismissed.
          const g = ghostField() ?? ghostPending;
          if (isTrusted(e) && g !== null && g === e.target) dismissGhost(g);
        },
        { capture: true },
      );
      listen(
        doc,
        "pointerdown",
        (e) => {
          // A click anywhere on the page but our host (or the menu's own field) closes the menu.
          if (isTrusted(e) && !sh.isHost(e.target) && parts?.frames.anchorOf("menu") !== e.target) closeMenu(true);
          // Touch (ruling of Task 6): a tap into the field, focused already or not, opens the menu
          // on its suggestion row; never a ghost a finger could not reach past.
          if (!isTrusted(e) || !currentLayout().touch) return;
          const t = icons.targetOf(e.target);
          if (t && ghostEligible(t)) void offerGhost(t);
        },
        { capture: true },
      );
      listen(
        doc,
        "focusin",
        (e) => {
          if (!isTrusted(e)) return;
          // The focus went somewhere else on the page (the ghost frame had it): the ghost goes.
          const g = ghostField() ?? ghostPending;
          if (g !== null && e.target !== g && !sh.isHost(e.target)) dropGhost();
          // A trusted focus into a field the user just pointed at or tabbed to: the ghost.
          const t = icons.targetOf(e.target);
          if (t && ghostEligible(t)) void offerGhost(t);
          // attachShadow makes no mutation record: a trusted focus into a
          // root no analysis has seen analyses now, at most once per
          // observer delay.
          if (!unseenRoot(e.target)) return;
          const now = Date.now();
          if (now - lastRootAnalysis < OBSERVER_DELAY_MS) return;
          lastRootAnalysis = now;
          observer.refresh();
        },
        { capture: true },
      );
      listen(
        doc,
        "focusout",
        (e) => {
          // The field loses the focus: once it has settled (the active element is the body while
          // the blur runs), the ghost goes unless the focus went into the ghost's own frame (a
          // click on its pill). Not dismissed: the next focus brings it back. From any blur, page
          // script's included: removing the ghost gives nothing away.
          const el = e.target;
          // The ghost's frame had the focus (a click on its pill) and lost it: unless it went
          // back to the field, the ghost goes (the body, a part of the page that takes no focus).
          if (el instanceof Element && sh.isHost(el)) {
            const g = ghostField();
            if (g === null) return;
            setTimeout(() => {
              if (stopped || !parts || ghostField() !== g || ghostFocused() || focusedField() === g) return;
              if (offered === g) offered = null;
              dropGhost();
            }, 0);
            return;
          }
          if (!(el instanceof Element) || (el !== offered && el !== ghostField() && el !== ghostPending)) return;
          setTimeout(() => {
            if (stopped || !parts || focusedField() === el || ghostFocused()) return;
            if (offered === el) offered = null;
            if (ghostField() === el || ghostPending === el) dropGhost();
          }, 0);
        },
        { capture: true },
      );
      listen(
        doc,
        "keyup",
        (e) => {
          // The keyup of an accepted Tab or Enter: neither the page nor its other listeners get it.
          if (!isTrusted(e) || !(e instanceof KeyboardEvent) || !swallowKeyup) return;
          if (e.target !== swallowKeyup.el || e.key !== swallowKeyup.key) return;
          swallowKeyup = null;
          e.preventDefault();
          e.stopImmediatePropagation();
        },
        { capture: true },
      );
      // A root attached late with no focus into it (delayed components): a few checks after start,
      // only while the page has custom elements (the hosts such roots hang from).
      const lateRoots = () => {
        if (stopped || !parts) return;
        const hosts = Array.from(doc.getElementsByTagName("*")).some((el) => el.localName.includes("-") && !isOwnHost(el));
        if (!hosts) return;
        if (collectShadowRoots(doc, { shadowRootOf, skip: isOwnHost }).some((r) => !watched.has(r))) observer.refresh();
      };
      for (const ms of LATE_ROOT_CHECKS_MS) {
        const id = setTimeout(lateRoots, ms);
        cleanups.push(() => clearTimeout(id));
      }
      submit.start();
      observer.start();
      // After start: the observer observes the roots the first analysis found.
      watched.use(observer);
      watched.use(tree);
    },
    stop() {
      stopped = true;
      for (const c of cleanups.splice(0)) c();
      if (parts) {
        parts.observer.stop();
        parts.submit.stop();
        parts.icons.destroy();
        parts.frames.destroy();
      }
      recorder?.stop();
      watched.clear();
      shell?.destroy();
      parts = null;
    },
  };
}

// ---- real start (not in tests: no extension runtime there) ----

const g = globalThis as { __onepassContent?: boolean };
if (browserExt?.runtime?.id && typeof document !== "undefined" && !g.__onepassContent) {
  // Set in the isolated world: invisible to page scripts. Guards a second
  // injection of the same script into the same frame.
  g.__onepassContent = true;
  const runtime = browserExt.runtime;
  createContentScript({
    doc: document,
    ext: {
      runtime: {
        id: runtime.id,
        getURL: (p) => runtime.getURL(p),
        sendMessage: (m) => runtime.sendMessage(m) as Promise<unknown>,
        onMessage: runtime.onMessage as unknown as ContentExt["runtime"]["onMessage"],
      },
    },
    href: () => location.href,
  }).start();
}
