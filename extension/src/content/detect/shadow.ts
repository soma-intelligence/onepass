// Shadow roots of the page (spec D1, D2). Forms may live in a web component's
// shadow root: the analysis walks the page for shadow hosts and queries every
// root it found as well as the document.
//
// Open roots are read through `el.shadowRoot`. Closed roots are reachable only
// through `chrome.dom.openOrClosedShadowRoot`, which Chromium gives to content
// scripts; elsewhere they stay out of reach (documented limit). Our own UI
// lives in a closed root too: the caller skips our host.
//
// Bounds per walk (hostile pages may nest components without end): at most
// 3000 elements inspected and roots nested at most 8 deep.

/** Most elements inspected for a shadow root per walk. */
export const MAX_SHADOW_ELEMENTS = 3000;
/** Deepest shadow root nesting walked (a root of the document is at depth 1). */
export const MAX_SHADOW_DEPTH = 8;

/** The shadow root of `el` the content script may read, or null. */
export type ShadowRootOf = (el: Element) => ShadowRoot | null;

/** Open roots only: what any script of the page can see. */
export const openShadowRoot: ShadowRootOf = (el) => el.shadowRoot;

export interface ShadowWalkOptions {
  shadowRootOf?: ShadowRootOf;
  /** Hosts never entered (our own UI). */
  skip?: (el: Element) => boolean;
  maxElements?: number;
  maxDepth?: number;
}

/**
 * Shadow roots under `doc`, outer roots first. Inspects at most
 * `maxElements` elements in all (document and roots) and enters roots at
 * most `maxDepth` deep. Only elements are visited, through a tree walker that
 * stops at the bound: a large page costs no more than the bound.
 */
export function collectShadowRoots(doc: Document, o: ShadowWalkOptions = {}): ShadowRoot[] {
  const rootOf = o.shadowRootOf ?? openShadowRoot;
  const maxElements = o.maxElements ?? MAX_SHADOW_ELEMENTS;
  const maxDepth = o.maxDepth ?? MAX_SHADOW_DEPTH;
  const out: ShadowRoot[] = [];
  const seen = new Set<ShadowRoot>();
  const queue: { root: Document | ShadowRoot; depth: number }[] = [{ root: doc, depth: 0 }];
  let budget = maxElements;
  for (let k = 0; k < queue.length && budget > 0; k++) {
    const { root, depth } = queue[k]!;
    const walker = doc.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
    for (let n = walker.nextNode(); n !== null && budget > 0; n = walker.nextNode()) {
      budget--;
      if (depth >= maxDepth) continue;
      const el = n as Element;
      if (o.skip?.(el)) continue;
      let sr: ShadowRoot | null = null;
      try {
        sr = rootOf(el);
      } catch {
        sr = null;
      }
      if (!sr || seen.has(sr)) continue;
      seen.add(sr);
      out.push(sr);
      queue.push({ root: sr, depth: depth + 1 });
    }
  }
  return out;
}

/** Every element matching `selector` in `doc`, then in each root, at most `max` in all. */
export function queryAll(doc: Document, roots: readonly ShadowRoot[], selector: string, max: number): Element[] {
  const out: Element[] = [];
  for (const r of [doc, ...roots]) {
    for (const el of Array.from(r.querySelectorAll(selector))) {
      if (out.length >= max) return out;
      out.push(el);
    }
  }
  return out;
}

/** The shadow host of the tree holding `n`, or null in the document tree. */
export function hostOf(n: Node): Element | null {
  const r = n.getRootNode();
  return r !== n && "host" in r ? ((r as ShadowRoot).host ?? null) : null;
}

/** Parent across shadow boundaries: the parent element, else the host of the root. */
export function composedParent(el: Element): Element | null {
  if (el.parentElement) return el.parentElement;
  const p = el.parentNode;
  return p !== null && "host" in p ? ((p as ShadowRoot).host ?? null) : null;
}

/** `el.closest(selector)`, else the same from the host of each shadow tree holding `el`, outward. */
export function composedClosest(el: Element, selector: string): Element | null {
  for (let t: Element | null = el, i = 0; t !== null && i <= MAX_SHADOW_DEPTH; t = hostOf(t), i++) {
    const hit = t.closest(selector);
    if (hit) return hit;
  }
  return null;
}

/** Whether `n` is inside `container` (or is it), across the shadow trees nested in `container`. */
export function composedContains(container: Node, n: Node): boolean {
  for (let t: Node | null = n, i = 0; t !== null && i <= MAX_SHADOW_DEPTH; t = hostOf(t), i++) {
    if (container.contains(t)) return true;
  }
  return false;
}

/**
 * The focused element, inside the shadow roots `rootOf` can read: the
 * document's `activeElement` is the host when the focus is in a root. A
 * skipped host (our own UI) is never entered.
 */
export function deepActiveElement(doc: Document, rootOf: ShadowRootOf = openShadowRoot, skip?: (el: Element) => boolean): Element | null {
  let a = doc.activeElement;
  for (let i = 0; a !== null && i < MAX_SHADOW_DEPTH && !skip?.(a); i++) {
    let r: ShadowRoot | null = null;
    try {
      r = rootOf(a);
    } catch {
      r = null;
    }
    const inner = r?.activeElement ?? null;
    if (inner === null) break;
    a = inner;
  }
  return a;
}

/** `n`, then the host of each shadow tree holding it, outward. */
function hostChain(n: Node): Node[] {
  const out: Node[] = [n];
  for (let h = hostOf(n); h !== null && out.length <= MAX_SHADOW_DEPTH + 1; h = hostOf(h)) out.push(h);
  return out;
}

/**
 * Order of two nodes in the flattened page: within one tree, document order;
 * across trees, the order of the hosts they sit under (a host comes before
 * the content of its shadow root).
 */
export function composedOrder(a: Node, b: Node): number {
  if (a === b) return 0;
  const ca = hostChain(a).reverse();
  const cb = hostChain(b).reverse();
  let i = 0;
  while (i < ca.length && i < cb.length && ca[i] === cb[i]) i++;
  if (i === ca.length) return -1;
  if (i === cb.length) return 1;
  const x = ca[i]!;
  const y = cb[i]!;
  return x.compareDocumentPosition(y) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1;
}

/** A part of the content script that listens to or observes each root. */
export interface RootUser {
  attach(root: ShadowRoot): void;
  detach(root: ShadowRoot): void;
}

/**
 * Shadow roots found by the analyses, reused for observation and listening:
 * each root is handed once to every user (observer, gesture listeners).
 * Events from inside a root reach document-level listeners retargeted to its
 * host; the root's own listeners see the real target, so a document-level
 * listener ignores events whose target is a watched host (`isHost`).
 * Roots are held weakly: a removed component is not kept alive.
 */
export class WatchedRoots {
  private readonly known = new WeakSet<ShadowRoot>();
  private readonly hosts = new WeakSet<Element>();
  private live: WeakRef<ShadowRoot>[] = [];
  private readonly users: RootUser[] = [];

  /** Registers a user; it gets the roots already known at once. */
  use(u: RootUser): void {
    this.users.push(u);
    for (const r of this.roots()) u.attach(r);
  }

  /** Hands the roots not seen before to every user. */
  add(roots: readonly ShadowRoot[]): void {
    let added = false;
    for (const r of roots) {
      if (this.known.has(r)) continue;
      this.known.add(r);
      this.hosts.add(r.host);
      this.live.push(new WeakRef(r));
      added = true;
      for (const u of this.users) u.attach(r);
    }
    if (added) this.live = this.live.filter((w) => w.deref() !== undefined);
  }

  /** Whether `t` hosts a watched root (its root's listeners handle its events). */
  isHost(t: EventTarget | null): boolean {
    return t !== null && typeof t === "object" && this.hosts.has(t as Element);
  }

  /** Whether `root` was handed to the users already. */
  has(root: ShadowRoot): boolean {
    return this.known.has(root);
  }

  roots(): ShadowRoot[] {
    return this.live.map((w) => w.deref()).filter((r): r is ShadowRoot => r !== undefined);
  }

  /** Detaches every user from every root (content script stop). */
  clear(): void {
    for (const r of this.roots()) for (const u of this.users) u.detach(r);
    this.users.length = 0;
    this.live = [];
  }
}

type Listener = (e: Event) => void;

interface TreeListener {
  base: EventTarget;
  type: string;
  fn: Listener;
  options: AddEventListenerOptions;
}

/**
 * Event listeners on the document (or window) and on every watched root.
 * An event from inside a root reaches the document retargeted to the root's
 * host, and the root's own listener with its real target: a listener skips
 * events whose target is a watched host (`filter`, the default), so each
 * event is handled once, from its real target. Events that do not cross a
 * shadow boundary (`submit`) reach the root's listener only. Hand it to
 * `WatchedRoots.use` to follow the roots.
 */
export class TreeListeners implements RootUser {
  private readonly entries = new Set<TreeListener>();
  /** Held weakly, as by `WatchedRoots`: a removed component is not kept alive. */
  private readonly attached = new WeakSet<ShadowRoot>();

  constructor(private readonly watched: WatchedRoots) {}

  /** Listens on `base` and on every watched root; returns the removal. */
  listen(base: EventTarget, type: string, fn: Listener, options: AddEventListenerOptions, filter = true): () => void {
    const wrapped: Listener = filter
      ? (e) => {
          if (!this.watched.isHost(e.target)) fn(e);
        }
      : fn;
    const entry: TreeListener = { base, type, fn: wrapped, options };
    this.entries.add(entry);
    base.addEventListener(type, wrapped, options);
    for (const r of this.attachedRoots()) r.addEventListener(type, wrapped, options);
    return () => {
      if (!this.entries.delete(entry)) return;
      base.removeEventListener(type, wrapped, options);
      for (const r of this.attachedRoots()) r.removeEventListener(type, wrapped, options);
    };
  }

  private attachedRoots(): ShadowRoot[] {
    return this.watched.roots().filter((r) => this.attached.has(r));
  }

  attach(root: ShadowRoot): void {
    if (this.attached.has(root)) return;
    this.attached.add(root);
    for (const e of this.entries) root.addEventListener(e.type, e.fn, e.options);
  }

  detach(root: ShadowRoot): void {
    if (!this.attached.delete(root)) return;
    for (const e of this.entries) root.removeEventListener(e.type, e.fn, e.options);
  }
}
