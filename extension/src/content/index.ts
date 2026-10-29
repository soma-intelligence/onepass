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
// Limit: fields inside the page's own shadow roots are not detected (the
// analysis queries the document tree only). Closed roots are never attempted;
// open roots are left for later, since walking every element for `shadowRoot`
// on each mutation burst is not cheap on large pages.
import { ext as browserExt } from "../shared/browser";
import { parseOrigin } from "../shared/domain";
import type { BgToCs, CsToBg, FieldRole, FrameKind, PageAnalysis } from "../shared/messages";
import { buildPageContext, findTypedUsername, withTypedUsernameHash } from "./context";
import { analyzeDocument } from "./detect/forms";
import { FormLineage, RefRegistry } from "./detect/refs";
import { domGeometry, type Geometry } from "./detect/visibility";
import { createFiller } from "./filler";
import { checkFrameUrl, createFrames, createShell, type Shell } from "./frames";
import { createIcons, type IconTarget } from "./icon";
import { createObserver, OBSERVER_DELAY_MS } from "./observer";
import { createSubmitWatcher } from "./submit";

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
}

export interface ContentScript {
  start(): void;
  stop(): void;
  /** For this script's tests only; never reachable from the page. */
  readonly internals: { readonly root: ShadowRoot; readonly refs: RefRegistry };
}

const FRAME_KINDS: ReadonlySet<string> = new Set<FrameKind>(["menu", "overlay", "save"]);
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

export function createContentScript(o: ContentOptions): ContentScript {
  const { doc, ext } = o;
  const geometry = o.geometry ?? domGeometry;
  const isTrusted = o.isTrusted ?? ((e: Event) => e.isTrusted);
  const view = doc.defaultView;
  const raf = o.raf ?? ((cb: () => void) => (view ? view.requestAnimationFrame(() => cb()) : setTimeout(cb, 16)));
  const refs = new RefRegistry();
  const lineage = new FormLineage(refs);
  let shell: Shell | null = null;
  let stopped = false;
  const cleanups: (() => void)[] = [];

  /** Normalized origin of the frame right now (null when not HTTPS). */
  const currentOrigin = (): string | null => {
    const p = parseOrigin(o.href());
    return p?.https ? p.origin : null;
  };

  const send = (m: CsToBg): Promise<unknown> => ext.runtime.sendMessage(m).catch(() => null);

  const analyze = (): PageAnalysis => {
    refs.prune();
    const a = analyzeDocument(doc, refs, { url: o.href(), geometry });
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

  let layoutQueued = false;
  const queueLayout = () => {
    if (layoutQueued || stopped) return;
    layoutQueued = true;
    raf(() => {
      layoutQueued = false;
      if (!parts || stopped) return;
      parts.icons.reposition();
      parts.frames.reposition();
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
    const focused = parts.icons.targetOf(doc.activeElement);
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

  const onMessage = (message: unknown, sender: Sender, sendResponse: (r: unknown) => void): undefined => {
    if (!parts || stopped || sender?.id !== ext.runtime.id) return undefined;
    if (typeof message !== "object" || message === null) return undefined;
    const m = message as Partial<BgToCs> & Record<string, unknown>;
    let ok = false;
    switch (m.type) {
      case "fill": {
        const values = fillValues(m.values);
        if (pinned(m.origin) && typeof m.formRef === "string" && values) {
          ok = parts.filler.fillForm(m.formRef, values) > 0;
          if (ok) closeMenu(true);
        }
        break;
      }
      case "click":
        if (pinned(m.origin) && typeof m.ref === "string") ok = parts.submit.clickRef(m.ref);
        break;
      case "submit":
        if (pinned(m.origin) && typeof m.ref === "string") ok = parts.submit.submitForm(m.ref, m.planned === true);
        break;
      case "smart_fill":
        // Our worker, on a click in the popup or the command's key: a gesture of the user.
        void smartFill(null);
        ok = true;
        break;
      case "plan_request": {
        // A context to plan with (popup line, chain replan): no hash, nothing typed leaves.
        const origin = currentOrigin();
        if (origin === null) break;
        const ctx = buildPageContext(doc, refs, parts.observer.refresh(), { origin, topOrigin: origin, frame: "top" }, geometry);
        sendResponse({ ok: true, context: { forms: ctx.forms, typed_username_hash: null } });
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
        if (kind === "menu" && !anchor) break;
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
          parts.frames.resize(m.kind as FrameKind, m.height);
          ok = true;
        }
        break;
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

  const listen = (target: EventTarget, type: string, fn: (e: Event) => void, options: AddEventListenerOptions) => {
    target.addEventListener(type, fn, options);
    cleanups.push(() => target.removeEventListener(type, fn, options));
  };

  return {
    get internals() {
      if (!shell) shell = createShell(doc);
      return { root: shell.root, refs };
    },
    start() {
      if (parts || stopped || currentOrigin() === null) return;
      shell ??= createShell(doc);
      const sh = shell;
      const frames = createFrames({ shell: sh, doc, geometry });
      const icons = createIcons({
        shell: sh,
        doc,
        refs,
        geometry,
        isTrusted,
        onOpen: (t) => void smartFill(t),
        onLayout: queueLayout,
      });
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
      const filler = createFiller({ refs, geometry, analyze: () => observer.refresh(), resolve: (ref, a) => lineage.resolve(ref, a) });
      const submit = createSubmitWatcher({
        doc,
        refs,
        geometry,
        isTrusted,
        latest: () => observer.latest(),
        analyze: () => observer.refresh(),
        resolve: (ref, a) => lineage.resolve(ref, a),
        onCredentials: (c) => void send(c),
      });
      parts = { shell: sh, frames, icons, observer, filler, submit };

      ext.runtime.onMessage.addListener(onMessage);
      const target: EventTarget = view ?? doc;
      listen(target, "scroll", queueLayout, { capture: true, passive: true });
      listen(target, "resize", queueLayout, { passive: true });
      listen(
        doc,
        "keydown",
        (e) => {
          if (!isTrusted(e) || !(e instanceof KeyboardEvent)) return;
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
              void send({ type: "menu_key", key: "enter" });
            }
            return;
          }
          if (e.key !== "ArrowDown") return;
          // A field the page added since the last analysis (it runs 150 ms
          // after a mutation burst): analyse now rather than miss the key.
          // At most one such analysis per observer delay: a held key does not
          // analyse the page on every repeat.
          let t = icons.targetOf(e.target);
          const now = Date.now();
          if (!t && isControl(e.target) && now - lastKeyAnalysis >= OBSERVER_DELAY_MS) {
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
          const hit = (ref: string) => refs.get(ref)?.contains(e.target as Node) === true;
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
          if (!isTrusted(e) || parts?.frames.has("menu")) return;
          const t = icons.targetOf(e.target);
          if (!t || !(t.el instanceof HTMLInputElement) || t.el.value !== "") return;
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
        },
        { capture: true },
      );
      listen(
        doc,
        "pointerdown",
        (e) => {
          // A click anywhere on the page but our host (or the menu's own field) closes the menu.
          if (isTrusted(e) && !sh.isHost(e.target) && parts?.frames.anchorOf("menu") !== e.target) closeMenu(true);
        },
        { capture: true },
      );
      submit.start();
      observer.start();
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
