// One user's journey on one real site (README "Parcours d'un utilisateur"):
// the home page, a wait, a scroll; the sign-in link found by its text or its
// href (several languages) and the sign-in page opened; a field focused,
// Escape, clicks on page controls while the card is shown; the card closed
// with ×, the page reloaded (the card must not come back); the field menu
// opened (the clicks and × come before the focus: a focused field takes the
// card away); another page of the site. Never a submit, never a click on a
// control that submits (the page's own handlers never see the bench's
// control clicks, see PROBE_INIT_SCRIPT). Each step ends with a snapshot
// that oracle.ts judges; violations get a screenshot of the card area.
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import type { BrowserContext, CDPSession, ElementHandle, Frame, Page } from "@playwright/test";
import { HostPacer } from "../corpus/schedule.ts";
import { MOVE_GUARD_MS } from "../../src/content/frames.ts";
import { CLICK_GUARD_MS } from "../../src/ui/components.ts";
import type { GuardLog, RobotsGate } from "./guard.ts";
import { type ControlProbe, type FieldRole, type Finding, type FrameProbe, judge, type Rect, type Snapshot } from "./oracle.ts";
import { type ResultRow, shotName, shotRel } from "./report.ts";
import type { Target } from "./targets.ts";
import { siteOf, type VaultIndex } from "./vault.ts";

/** Past the click guard of a freshly shown extension frame (lab/run/browser.ts). */
export const GUARD_WAIT_MS = Math.max(CLICK_GUARD_MS, MOVE_GUARD_MS) + 150;
const VIEWPORT = { width: 1280, height: 860 };
const GOTO_MS = 25_000;
const IDLE_MS = 6_000;
/** After a page settled: the auto pill waits for the load and an analysis. */
const CARD_WAIT_MS = 3_000;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export interface VisitEnv {
  context: BrowserContext;
  onePassId: string;
  pacer: HostPacer;
  robots: RobotsGate | null;
  guard: GuardLog;
  vault: VaultIndex;
  out: string;
  managersLoaded: boolean;
  timeBoxMs: number;
  ownPages: WeakSet<Page>;
  emit(row: ResultRow): void;
}

/** What the page scan returns (main world, no value ever leaves the page except a length-and-hash signature kept in memory). */
interface Scan {
  url: string;
  fields: { index: number; role: FieldRole; box: Rect; sig: string }[];
  loginForm: boolean;
  signupForm: boolean;
  signedInMarks: string[];
  foreignIcons: Rect[];
  foreignMenus: number;
  controls: (ControlProbe & { safe: boolean })[];
  probes: FrameProbe[];
  active: "field" | "onepass" | "foreign" | "page" | "none";
}

/**
 * Runs in the page's main world. Classifies the visible fields, reads the signed-in marks, finds
 * other managers' icons and dropdowns, samples page controls with elementFromPoint, and probes the
 * given points. Self-contained: serialized into the page.
 */
function pageScan(arg: { probePoints: { x: number; y: number }[]; near: { x: number; y: number } }): Scan {
  const SIGN_IN = /sign ?in|log ?in|login|connexion|se connecter|anmelden|einloggen|iniciar sesi[oó]n|entrar|accedi|inloggen|zaloguj|войти|вход|ログイン|登录|登入|로그인|giriş|masuk|đăng nhập/i;
  const SIGN_UP = /sign ?up|register|create (an |your )?account|inscription|cr[ée]er un compte|registrieren|konto erstellen|reg[ií]strate|crear (una )?cuenta|registrati|registreren|join now/i;
  const SEARCH = /search|recherche|suche|buscar|busca|cerca|zoek|szukaj|поиск|検索|搜索|query|keyword/i;
  const NEWSLETTER = /newsletter|subscribe|subscription|abonn|lettre d.information|nieuwsbrief|bolet[ií]n|iscriviti|inscreva/i;
  const USER = /user|login|email|e-mail|mail|ident|account|phone|benutzer|usuario|utente|identifiant|courriel|nutzer|konto/i;
  const LOGOUT = /log ?out|sign ?out|se d[ée]connecter|d[ée]connexion|abmelden|ausloggen|cerrar sesi[oó]n|esci|uitloggen|wyloguj|выйти|ログアウト|退出|登出|로그아웃|çıkış yap|keluar/i;
  const LOGOUT_HREF = /logout|log-out|signout|sign-out|logoff|sign_out|log_out/i;
  const ACCOUNT = /^(my |your )?(account|profile)\b|mon compte|mon profil|mein konto|mi cuenta|il mio account|account menu|user menu/i;
  const AVATAR = /avatar|profile[-_ ]?(pic|photo|image|img)|user[-_ ]?(pic|photo|image|img)/i;
  const r2 = (r: DOMRect) => ({ x: r.x, y: r.y, width: r.width, height: r.height });
  const visible = (el: Element): boolean => {
    const r = el.getBoundingClientRect();
    if (r.width < 4 || r.height < 4) return false;
    const cs = getComputedStyle(el);
    return cs.visibility !== "hidden" && cs.display !== "none" && Number(cs.opacity) > 0.05;
  };
  const attrs = (el: Element) => ["name", "id", "placeholder", "aria-label", "autocomplete", "title", "class"].map((a) => el.getAttribute(a) ?? "").join(" ");
  const sig = (v: string) => {
    let h = 5381;
    for (let i = 0; i < v.length; i++) h = ((h << 5) + h + v.charCodeAt(i)) | 0;
    return `${v.length}:${h}`;
  };
  const ctxOf = (el: Element) => el.closest("form, [role=form], dialog, [role=dialog]") ?? null;
  const textOf = (el: Element | null) => (el ? ((el as HTMLElement).innerText ?? el.textContent ?? "").slice(0, 600) : "");
  const where = `${document.title} ${location.pathname}`;

  const all = Array.from(document.querySelectorAll("input, textarea")) as (HTMLInputElement | HTMLTextAreaElement)[];
  const skipTypes = new Set(["hidden", "submit", "button", "reset", "image", "checkbox", "radio", "file", "range", "color"]);
  const fields: Scan["fields"] = [];
  let loginForm = false;
  let signupForm = false;
  all.forEach((el, index) => {
    const type = (el.getAttribute("type") ?? "text").toLowerCase();
    if (skipTypes.has(type) || !visible(el)) return;
    const ctx = ctxOf(el);
    const scope: ParentNode = ctx ?? document;
    const passwords = Array.from(scope.querySelectorAll("input[type=password]")).filter(visible);
    const ctxText = `${textOf(ctx)} ${ctx ? attrs(ctx) : ""} ${ctx?.getAttribute("action") ?? ""}`;
    const own = attrs(el);
    let role: FieldRole = "other";
    if (type === "password") role = "password";
    else if (type === "search" || el.getAttribute("role") === "searchbox" || ctx?.getAttribute("role") === "search" || (SEARCH.test(own) && passwords.length === 0)) role = "search";
    else if (["email", "text", "tel", ""].includes(type) && passwords.length === 0 && NEWSLETTER.test(`${own} ${ctxText}`) && !SIGN_IN.test(ctxText)) role = "newsletter";
    else if (["email", "text", "tel", ""].includes(type) && (USER.test(own) || /username|email/.test(el.getAttribute("autocomplete") ?? ""))) {
      role = passwords.length > 0 || SIGN_IN.test(`${ctxText} ${where}`) ? "username" : "other";
    }
    if (role === "password") {
      const many = passwords.length >= 2 || el.getAttribute("autocomplete") === "new-password";
      const up = many || (SIGN_UP.test(ctxText) && !SIGN_IN.test(ctxText));
      if (up) signupForm = true;
      else loginForm = true;
    } else if (role === "username" && (passwords.length > 0 || SIGN_IN.test(`${ctxText} ${where}`) || /login|signin|sign-in|log-in|auth|connexion|anmelden/i.test(location.pathname))) {
      if (SIGN_UP.test(ctxText) && !SIGN_IN.test(ctxText)) signupForm = true;
      else loginForm = true;
    }
    fields.push({ index, role, box: r2(el.getBoundingClientRect()), sig: sig(el.value ?? "") });
  });

  const marks = new Set<string>();
  for (const el of Array.from(document.querySelectorAll("a, button, [role=menuitem], [role=button]"))) {
    const label = `${(el as HTMLElement).innerText ?? ""} ${el.getAttribute("aria-label") ?? ""} ${el.getAttribute("title") ?? ""}`.trim();
    const href = el.getAttribute("href") ?? "";
    if ((label.length > 0 && label.length < 40 && LOGOUT.test(label)) || LOGOUT_HREF.test(href)) marks.add("sign-out control");
  }
  for (const el of Array.from(document.querySelectorAll("[aria-label], [title]"))) {
    const label = `${el.getAttribute("aria-label") ?? ""} ${el.getAttribute("title") ?? ""}`.trim();
    if (!ACCOUNT.test(label) || !el.querySelector("img") || !visible(el)) continue;
    if (el.getBoundingClientRect().top < 160) marks.add("account menu");
  }
  for (const img of Array.from(document.images)) {
    const hint = `${img.alt} ${img.className} ${img.id} ${img.getAttribute("src") ?? ""}`;
    if (!AVATAR.test(hint) || !visible(img)) continue;
    const r = img.getBoundingClientRect();
    if (r.top < 160 && r.width <= 96 && r.height <= 96) marks.add("avatar");
  }

  const KNOWN_ICON = "com-1password-button, [data-lastpass-icon-root], [data-dashlane-rid-icon]";
  const KNOWN_MENU = "com-1password-menu, [data-lastpass-root]";
  const foreignIcons: Rect[] = [];
  let foreignMenus = 0;
  const candidates = new Set<Element>(Array.from(document.querySelectorAll(`${KNOWN_ICON}, ${KNOWN_MENU}, [data-fake-manager]`)));
  for (const el of Array.from(document.querySelectorAll("body *"))) {
    if (!el.tagName.includes("-") || el.tagName === "ONEPASS-ROOT") continue;
    const sr = (el as HTMLElement).shadowRoot;
    const frame = el.querySelector("iframe[src^='chrome-extension://']") ?? sr?.querySelector("iframe[src^='chrome-extension://']");
    if (frame) candidates.add(el);
  }
  for (const el of candidates) {
    if (el.tagName === "ONEPASS-ROOT" || !visible(el)) continue;
    const r = el.getBoundingClientRect();
    const menu = el.matches(KNOWN_MENU) || (r.width >= 100 && r.height >= 50);
    if (menu) foreignMenus++;
    else if (r.width <= 48 && r.height <= 48) foreignIcons.push(r2(r));
  }

  const isOurs = (el: Element | null) => !!el && el.tagName === "ONEPASS-ROOT";
  const cands = Array.from(document.querySelectorAll("a[href], button, input:not([type=hidden]), select, textarea, [role=button], [role=link]")).filter((el) => {
    if (!visible(el)) return false;
    const r = el.getBoundingClientRect();
    const cx = r.x + r.width / 2;
    const cy = r.y + r.height / 2;
    return cx > 0 && cy > 0 && cx < innerWidth && cy < innerHeight;
  });
  const dist = (el: Element) => {
    const r = el.getBoundingClientRect();
    return Math.hypot(r.x + r.width / 2 - arg.near.x, r.y + r.height / 2 - arg.near.y);
  };
  const nearest = [...cands].sort((a, b) => dist(a) - dist(b)).slice(0, 25);
  const rest = cands.filter((c) => !nearest.includes(c));
  const step = Math.max(1, Math.floor(rest.length / 15));
  const sample = [...nearest, ...rest.filter((_, i) => i % step === 0).slice(0, 15)];
  const SUBMITTY = /submit|sign ?in|log ?in|continue|next|buy|pay|order|delete|remove|subscribe|send|confirm|accept|agree|logout|sign ?out|connexion|valider|envoyer|weiter|suivant|acheter|kaufen/i;
  const controls: Scan["controls"] = sample.map((el) => {
    const r = el.getBoundingClientRect();
    const x = r.x + r.width / 2;
    const y = r.y + r.height / 2;
    const at = document.elementFromPoint(x, y);
    let hit: ControlProbe["hit"] = "none";
    let by: string | undefined;
    if (isOurs(at)) {
      hit = "onepass";
      const inner = (at as HTMLElement).shadowRoot?.elementFromPoint(x, y) ?? null;
      const ir = inner?.getBoundingClientRect();
      by = inner ? `${inner.tagName.toLowerCase()}.${inner.className || "-"} ${Math.round(ir!.width)}x${Math.round(ir!.height)} op=${getComputedStyle(inner).opacity}` : "host";
    }
    else if (at && (at === el || el.contains(at) || (at instanceof HTMLLabelElement && at.control === el))) hit = "self";
    else if (at) hit = "other";
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute("type") ?? "").toLowerCase();
    const inForm = !!el.closest("form");
    const label = `${(el as HTMLElement).innerText ?? ""} ${el.getAttribute("aria-label") ?? ""} ${el.getAttribute("href") ?? ""}`;
    const safe = (tag === "a" || (tag === "button" && (type === "button" || (!inForm && type !== "submit")))) && !SUBMITTY.test(label);
    return { tag, x, y, hit, safe, ...(by ? { by } : {}) };
  });
  const probes = arg.probePoints.map((p) => ({ x: p.x, y: p.y, onepass: isOurs(document.elementFromPoint(p.x, p.y)) }));

  const a = document.activeElement;
  let active: Scan["active"] = "none";
  if (!a || a === document.body || a === document.documentElement) active = "none";
  else if (isOurs(a)) active = "onepass";
  else if (all.includes(a as HTMLInputElement)) active = "field";
  else if (candidates.has(a) || a.tagName.includes("-")) active = "foreign";
  else active = "page";
  return { url: location.href, fields, loginForm, signupForm, signedInMarks: [...marks], foreignIcons, foreignMenus, controls, probes, active };
}

/** Sign-in link or button candidates (main world, self-contained), best first. */
function findSignIn(): { index: number; href: string | null; button: boolean }[] {
  const SIGN_IN = /^\s*(sign ?in|log ?in|login|se connecter|connexion|s'identifier|identifiez-vous|anmelden|einloggen|iniciar sesi[oó]n|entrar|acceder|accedi|inloggen|aanmelden|zaloguj( się)?|войти|вход|ログイン|登录|登入|로그인|giriş yap|masuk|đăng nhập|my account|mon compte|account)\s*$/i;
  const SIGN_IN_LOOSE = /sign ?in|log ?in|login|connexion|se connecter|anmelden|iniciar sesi[oó]n|accedi|inloggen|войти|ログイン|登录|로그인/i;
  const HREF = /\/(login|signin|sign-in|log-in|sign_in|auth|account\/login|connexion|anmelden|accounts?\/?$|session\/new|ap\/signin|uas\/login)/i;
  const BAD = /sign ?up|register|create|inscription|logout|log ?out|sign ?out|d[ée]connexion|abmelden/i;
  const out: { index: number; href: string | null; button: boolean; score: number }[] = [];
  const els = Array.from(document.querySelectorAll("a, button, [role=button], [role=link]"));
  els.forEach((el, index) => {
    const text = `${(el as HTMLElement).innerText ?? ""}`.trim().slice(0, 60);
    const aria = el.getAttribute("aria-label") ?? "";
    const rawHref = el.getAttribute("href");
    const href = rawHref && !rawHref.startsWith("javascript:") && rawHref !== "#" ? new URL(rawHref, location.href).href : null;
    if (BAD.test(`${text} ${aria}`) || (href && BAD.test(href))) return;
    let score = 0;
    if (SIGN_IN.test(text) || SIGN_IN.test(aria)) score += 10;
    else if (SIGN_IN_LOOSE.test(`${text} ${aria}`) && text.length < 30) score += 5;
    if (href && HREF.test(new URL(href).pathname)) score += 4;
    if (score === 0) return;
    const r = el.getBoundingClientRect();
    const shown = r.width > 0 && r.height > 0;
    const isButton = !href;
    if (isButton) {
      const type = (el.getAttribute("type") ?? "").toLowerCase();
      if (!shown || type === "submit" || (el.closest("form") && type !== "button")) return;
    }
    if (shown) score += 1;
    out.push({ index, href, button: isButton, score });
  });
  return out.sort((a, b) => b.score - a.score).slice(0, 5).map(({ index, href, button }) => ({ index, href, button }));
}

/** Another page of the site to go to: a same-site link off the auth paths (main world, self-contained). */
function findOtherPage(): string | null {
  const BAD = /login|signin|sign-in|log-in|logout|signout|sign-out|log-out|register|signup|sign-up|auth|account|delete|remove|unsubscribe|cart|checkout|basket|panier|\.(pdf|zip|dmg|exe|apk|mp4|mp3)$/i;
  const here = location.href.split("#")[0];
  for (const a of Array.from(document.querySelectorAll("a[href]")) as HTMLAnchorElement[]) {
    const r = a.getBoundingClientRect();
    if (r.width < 4 || r.height < 4) continue;
    let u: URL;
    try {
      u = new URL(a.href);
    } catch {
      continue;
    }
    if (u.protocol !== "https:" || u.href.split("#")[0] === here || u.pathname === "/" || BAD.test(u.pathname + u.search)) continue;
    const mine = location.hostname.split(".").slice(-2).join(".");
    if (!u.hostname.endsWith(mine)) continue;
    return u.href.split("#")[0]!;
  }
  return null;
}

/** Click probe (main world, every frame): while armed, the bench's clicks are recorded and never reach the page. */
export const PROBE_INIT_SCRIPT = `(() => {
  const stop = (e) => {
    const p = window.__onepassLabProbe;
    if (!p || !p.armed) return;
    if (e.type === "click") p.targets.push(e.target);
    e.preventDefault();
    e.stopImmediatePropagation();
  };
  for (const t of ["pointerdown", "mousedown", "pointerup", "mouseup", "click", "auxclick", "dblclick"]) window.addEventListener(t, stop, true);
})();`;

interface ShellFrame { path: string; box: Rect; shown: boolean; inert: boolean }
interface Shell { icons: Rect[]; frames: ShellFrame[] }

type DomNode = { nodeName: string; backendNodeId: number; attributes?: string[]; children?: DomNode[]; shadowRoots?: DomNode[] };

const attr = (n: DomNode, name: string): string | undefined => {
  const a = n.attributes ?? [];
  for (let i = 0; i + 1 < a.length; i += 2) if (a[i] === name) return a[i + 1];
  return undefined;
};

/** The OnePass shell of the top document, read through CDP (its shadow root is closed to the page). */
async function readShell(cdp: CDPSession): Promise<Shell> {
  const out: Shell = { icons: [], frames: [] };
  const { root } = (await cdp.send("DOM.getDocument", { depth: 0 })) as { root: { nodeId: number } };
  const { nodeIds } = (await cdp.send("DOM.querySelectorAll", { nodeId: root.nodeId, selector: "onepass-root" })) as { nodeIds: number[] };
  const box = async (backendNodeId: number): Promise<Rect | null> => {
    try {
      const { model } = (await cdp.send("DOM.getBoxModel", { backendNodeId })) as { model: { border: number[] } };
      const q = model.border;
      const xs = [q[0]!, q[2]!, q[4]!, q[6]!];
      const ys = [q[1]!, q[3]!, q[5]!, q[7]!];
      const r = { x: Math.min(...xs), y: Math.min(...ys), width: Math.max(...xs) - Math.min(...xs), height: Math.max(...ys) - Math.min(...ys) };
      return r.width > 0 && r.height > 0 ? r : null;
    } catch {
      return null;
    }
  };
  for (const nodeId of nodeIds) {
    const { node } = (await cdp.send("DOM.describeNode", { nodeId, depth: -1, pierce: true })) as { node: DomNode };
    const walk = async (n: DomNode): Promise<void> => {
      const cls = attr(n, "class") ?? "";
      if (n.nodeName === "DIV" && /(^|\s)icon(\s|$)/.test(cls) && attr(n, "hidden") === undefined) {
        const b = await box(n.backendNodeId);
        if (b) out.icons.push(b);
      }
      if (n.nodeName === "IFRAME") {
        const src = attr(n, "src") ?? "";
        const b = await box(n.backendNodeId);
        let path = "";
        try {
          path = new URL(src).pathname;
        } catch {
          path = "";
        }
        if (b) out.frames.push({ path, box: b, shown: /(^|\s)shown(\s|$)/.test(cls), inert: /pointer-events:\s*none/.test(attr(n, "style") ?? "") });
      }
      for (const c of [...(n.children ?? []), ...(n.shadowRoots ?? [])]) await walk(c);
    };
    await walk(node);
  }
  return out;
}

/** The card as the overlay frame draws it: its face and the boxes of its visible parts (frame coordinates). */
async function readCard(frame: Frame): Promise<{ face: Snapshot["card"]; boxes: Rect[] }> {
  return frame.evaluate(() => {
    const boxes: { x: number; y: number; width: number; height: number }[] = [];
    for (const el of Array.from(document.querySelectorAll(".ov-pill-wrap *, .ov-pill-wrap"))) {
      const r = el.getBoundingClientRect();
      if (r.width <= 0 || r.height <= 0) continue;
      const cs = getComputedStyle(el);
      if (cs.visibility === "hidden" || cs.display === "none") continue;
      const painted = (cs.backgroundColor !== "rgba(0, 0, 0, 0)" && cs.backgroundColor !== "transparent") || cs.boxShadow !== "none" || el.tagName === "BUTTON";
      if (painted) boxes.push({ x: r.x, y: r.y, width: r.width, height: r.height });
    }
    const face = document.querySelector(".ov-pill[data-generic]") ? "generic"
      : document.querySelector(".ov-pill[data-create]") ? "signup"
      : document.querySelector(".ov-signin") ? "signin"
      : document.querySelector(".ov-pill") ? "other" : null;
    return { face, boxes } as { face: "signin" | "generic" | "signup" | "other" | null; boxes: Rect[] };
  }).catch(() => ({ face: null, boxes: [] }));
}

const extFrames = (page: Page, id: string, path: string) =>
  page.frames().filter((f) => {
    const u = f.url();
    return u.startsWith(`chrome-extension://${id}/`) && new URL(u).pathname === path;
  });

/** A grid of points over each shown OnePass frame, for the transparent-area probe. */
function gridOver(frames: readonly ShellFrame[]): { x: number; y: number }[] {
  const pts: { x: number; y: number }[] = [];
  for (const f of frames) {
    if (!f.shown || f.inert) continue;
    for (let i = 1; i <= 6; i++) {
      for (let j = 1; j <= 4; j++) pts.push({ x: f.box.x + (f.box.width * i) / 7, y: f.box.y + (f.box.height * j) / 5 });
    }
  }
  return pts.filter((p) => p.x >= 0 && p.y >= 0 && p.x < VIEWPORT.width && p.y < VIEWPORT.height);
}

interface Observed { snap: Snapshot; scan: Scan }

/** One user's journey on one site. */
class Journey {
  private stepNo = 0;
  private closedByX = false;
  private lastSigs: { url: string; sigs: Map<number, string> } | null = null;
  private stepStart = Date.now();
  private cdp: CDPSession | null = null;

  constructor(private readonly env: VisitEnv, private readonly target: Target, private readonly page: Page) {}

  private get site(): string {
    try {
      return siteOf(new URL(this.page.url()).hostname);
    } catch {
      return siteOf(this.target.host);
    }
  }

  private row(step: string, rule: ResultRow["rule"], verdict: ResultRow["verdict"], detail: string, shot?: string): void {
    this.env.emit({ host: this.target.host, kind: this.target.kind, step, rule, verdict, detail, ...(shot ? { shot } : {}) });
  }

  private async session(): Promise<CDPSession> {
    if (!this.cdp) this.cdp = await this.env.context.newCDPSession(this.page);
    return this.cdp;
  }

  /** A paced, robots-checked page load of `url`; false when robots refuse it or it fails. */
  private async go(step: string, url: string, reload = false): Promise<boolean> {
    if (this.env.robots && !(await this.env.robots.allowed(url).catch(() => false))) {
      this.row(step, "-", "skip", "robots.txt disallows this page");
      return false;
    }
    await this.env.pacer.wait(siteOf(new URL(url).hostname));
    try {
      if (reload) await this.page.reload({ waitUntil: "domcontentloaded", timeout: GOTO_MS });
      else await this.page.goto(url, { waitUntil: "domcontentloaded", timeout: GOTO_MS });
    } catch (e) {
      this.row(step, "-", "error", `load failed: ${String((e as Error).message ?? e).split("\n")[0]!.slice(0, 160)}`);
      return false;
    }
    await this.page.waitForLoadState("networkidle", { timeout: IDLE_MS }).catch(() => undefined);
    await sleep(CARD_WAIT_MS);
    // A redirect may change the host: the shell's CDP session follows the page.
    return true;
  }

  private async observe(step: string, extra: { focusExpected?: boolean; closeMs?: number | null } = {}): Promise<Observed> {
    const id = this.env.onePassId;
    const shell = await readShell(await this.session()).catch(() => ({ icons: [], frames: [] }) as Shell);
    const overlays = extFrames(this.page, id, "/overlay.html");
    const overlayShell = shell.frames.filter((f) => f.path === "/overlay.html");
    const shownOverlay = overlayShell.find((f) => f.shown);
    let card: Snapshot["card"] = null;
    let cardBoxes: Rect[] = [];
    if (shownOverlay && overlays[0]) {
      const c = await readCard(overlays[0]);
      card = c.face;
      cardBoxes = c.boxes.map((b) => ({ ...b, x: b.x + shownOverlay.box.x, y: b.y + shownOverlay.box.y }));
    }
    const menuShell = shell.frames.find((f) => f.path === "/menu.html" && f.shown);
    const near = shownOverlay ? { x: shownOverlay.box.x + shownOverlay.box.width / 2, y: shownOverlay.box.y + shownOverlay.box.height / 2 } : { x: VIEWPORT.width / 2, y: 60 };
    const scan = await this.page.evaluate(pageScan, { probePoints: gridOver(shell.frames), near }).catch(() => null);
    const empty: Scan = { url: this.page.url(), fields: [], loginForm: false, signupForm: false, signedInMarks: [], foreignIcons: [], foreignMenus: 0, controls: [], probes: [], active: "none" };
    const s = scan ?? empty;
    // Values changed since the last look at this same page, while the bench typed nothing.
    const sigs = new Map(s.fields.map((f) => [f.index, f.sig]));
    const changed: number[] = [];
    if (this.lastSigs && this.lastSigs.url === s.url) {
      for (const [i, v] of sigs) {
        const before = this.lastSigs.sigs.get(i);
        if (before !== undefined && before !== v) changed.push(i);
      }
    }
    this.lastSigs = { url: s.url, sigs };
    const snap: Snapshot = {
      step, host: this.target.host,
      overlayFrames: overlayShell.length,
      card, cardBoxes, cardFrame: shownOverlay?.box ?? null,
      menuOpen: !!menuShell, menuBox: menuShell?.box ?? null,
      icons: shell.icons,
      fields: s.fields.map(({ index, role, box }) => ({ index, role, box })),
      loginForm: s.loginForm, signupForm: s.signupForm, signedInMarks: s.signedInMarks,
      foreignIcons: s.foreignIcons, foreignMenus: s.foreignMenus,
      controls: s.controls.map(({ tag, x, y, hit, by }) => ({ tag, x, y, hit, ...(by ? { by } : {}) })),
      frameProbes: s.probes,
      valuesChanged: changed,
      ...(extra.focusExpected ? { focus: { expected: "field" as const, on: s.active === "foreign" ? "foreign" as const : s.active } } : {}),
      ...(extra.closeMs !== undefined ? { closeMs: extra.closeMs } : {}),
    };
    return { snap, scan: s };
  }

  /** Judges a snapshot, writes its rows and the shots of its violations. */
  private async record(o: Observed, arrival: boolean): Promise<void> {
    this.stepNo++;
    const host = (() => {
      try {
        return new URL(o.scan.url).hostname;
      } catch {
        return this.target.host;
      }
    })();
    const events = this.env.guard.since(this.stepStart, (h) => h === "" || siteOf(h) === siteOf(host) || siteOf(h) === siteOf(this.target.host));
    this.stepStart = Date.now();
    const findings = judge(o.snap, {
      vaultLogins: this.env.vault.loginsFor(host), knownSignedIn: this.target.knownSignedIn, closedByX: this.closedByX, arrival,
    }, events, this.env.managersLoaded);
    const shot = new Map<string, string>();
    for (const f of findings) {
      let file: string | undefined;
      if (f.verdict === "violation") {
        file = shot.get(f.rule) ?? (await this.shoot(f, o.snap));
        if (file) shot.set(f.rule, file);
      }
      this.row(o.snap.step, f.rule, f.verdict, f.detail, file);
    }
  }

  private async shoot(f: Finding, s: Snapshot): Promise<string | undefined> {
    const base = f.box ?? s.cardFrame ?? { x: 0, y: 0, width: VIEWPORT.width, height: 260 };
    // A point (R2): the whole neighbourhood, to see which OnePass frame stands there.
    const pad = f.box && f.box.width <= 2 ? 240 : 60;
    const x = Math.max(0, Math.floor(base.x - pad));
    const y = Math.max(0, Math.floor(base.y - pad));
    const clip = { x, y, width: Math.max(80, Math.min(VIEWPORT.width - x, Math.ceil(base.width + 2 * pad))), height: Math.max(60, Math.min(VIEWPORT.height - y, Math.ceil(base.height + 2 * pad))) };
    const dir = join(this.env.out, "shots");
    mkdirSync(dir, { recursive: true });
    const file = join(dir, shotName(this.target.host, this.target.kind, this.stepNo, f.rule));
    try {
      await this.page.screenshot({ path: file, clip, timeout: 5_000 });
      return shotRel(this.env.out, file);
    } catch {
      return undefined;
    }
  }

  private async fieldHandle(index: number): Promise<ElementHandle | null> {
    const h = await this.page.evaluateHandle((i) => document.querySelectorAll("input, textarea")[i] ?? null, index).catch(() => null);
    return h?.asElement() ?? null;
  }

  /** The field the user would start with: an identifier, else a password, of a sign-in form first. */
  private pickField(scan: Scan): Scan["fields"][number] | undefined {
    return scan.fields.find((f) => f.role === "username") ?? scan.fields.find((f) => f.role === "password");
  }

  /** A user's click in the middle of a field (trusted), and a short wait for what it brings. */
  private async clickField(index: number): Promise<boolean> {
    const h = await this.fieldHandle(index);
    if (!h) return false;
    await h.scrollIntoViewIfNeeded({ timeout: 2_000 }).catch(() => undefined);
    const b = await h.boundingBox().catch(() => null);
    if (!b) return false;
    const x = b.x + Math.min(b.width / 3, 60);
    const y = b.y + b.height / 2;
    // Never a click that would land on OnePass's own card or menu (it could start a sign-in): focus instead.
    const ours = await this.page.evaluate(({ x, y }) => document.elementFromPoint(x, y)?.tagName === "ONEPASS-ROOT", { x, y }).catch(() => true);
    if (ours) await h.focus().catch(() => undefined);
    else await this.page.mouse.click(x, y);
    await sleep(1_200);
    return true;
  }

  /** Clicks a few safe controls with the probe armed: each click must reach its control, not a OnePass frame. */
  private async clickControls(scan: Scan): Promise<ControlProbe[]> {
    // Only controls the page itself shows at their centre: a click on OnePass's own card could start a sign-in.
    const picks = scan.controls.filter((c) => c.safe && c.hit === "self").slice(0, 3);
    const out: ControlProbe[] = [];
    for (const c of picks) {
      const armed = await this.page.evaluate(({ x, y }) => {
        const w = window as unknown as { __onepassLabProbe?: { armed: boolean; targets: EventTarget[]; expect: Element | null } };
        w.__onepassLabProbe = { armed: true, targets: [], expect: document.elementFromPoint(x, y) };
        return true;
      }, { x: c.x, y: c.y }).catch(() => false);
      if (!armed) continue;
      await this.page.mouse.click(c.x, c.y);
      await sleep(150);
      const hit = await this.page.evaluate(({ x, y }) => {
        const w = window as unknown as { __onepassLabProbe?: { armed: boolean; targets: EventTarget[]; expect: Element | null } };
        const p = w.__onepassLabProbe;
        if (!p) return "none" as const;
        p.armed = false;
        const last = p.targets.at(-1) as Element | undefined;
        if (last && p.expect && (last === p.expect || p.expect.contains(last) || last.contains(p.expect))) return "self" as const;
        const now = document.elementFromPoint(x, y);
        if (now && now.tagName === "ONEPASS-ROOT") return "onepass" as const;
        return last ? ("other" as const) : ("none" as const);
      }, { x: c.x, y: c.y }).catch(() => "none" as const);
      out.push({ tag: c.tag, x: c.x, y: c.y, hit });
    }
    return out;
  }

  /** Clicks × on the card; the time until the card is gone (ms), or null when it stays. */
  private async closeCard(): Promise<number | null | undefined> {
    const overlay = extFrames(this.page, this.env.onePassId, "/overlay.html")[0];
    if (!overlay) return undefined;
    const close = overlay.locator(".ov-close").first();
    if (!(await close.isVisible().catch(() => false))) return undefined;
    await sleep(GUARD_WAIT_MS);
    for (let tap = 0; tap < 3; tap++) {
      const t0 = Date.now();
      const clicked = await close.click({ timeout: 3_000 }).then(() => true, () => false);
      if (!clicked) return null;
      const held = await close.evaluate((el) => el.classList.contains("held"), undefined, { timeout: 500 }).catch(() => false);
      if (held) {
        // The frame's click guard swallowed the tap (src/shared/click-guard.ts): tap again, as a user would.
        await sleep(400);
        continue;
      }
      const cdp = await this.session();
      while (Date.now() - t0 < 3_000) {
        const shell = await readShell(cdp).catch(() => null);
        if (shell && !shell.frames.some((f) => f.path === "/overlay.html" && f.shown)) return Date.now() - t0;
        await sleep(40);
      }
      return null;
    }
    return null;
  }

  async run(): Promise<void> {
    const t = this.target;
    // 1. Home, wait, scroll.
    if (!(await this.go("home", t.url))) return;
    await this.record(await this.observe("home"), true);
    for (let i = 0; i < 3; i++) {
      await this.page.mouse.wheel(0, 600);
      await sleep(500);
    }
    await this.page.mouse.wheel(0, -1800);
    await sleep(800);
    await this.record(await this.observe("home-scrolled"), false);

    // 2. The sign-in page.
    const links = await this.page.evaluate(findSignIn).catch(() => [] as ReturnType<typeof findSignIn>);
    let onSignIn = false;
    const link = links.find((l) => l.href && siteOf(new URL(l.href).hostname) === siteOf(new URL(this.page.url()).hostname)) ?? links.find((l) => l.href) ?? links.find((l) => l.button);
    if (link?.href) {
      onSignIn = await this.go("signin-page", link.href);
    } else if (link?.button) {
      const h = await this.page.evaluateHandle((i) => document.querySelectorAll("a, button, [role=button], [role=link]")[i] ?? null, link.index).catch(() => null);
      const el = h?.asElement();
      if (el) {
        await el.click({ timeout: 3_000 }).catch(() => undefined);
        await this.page.waitForLoadState("domcontentloaded", { timeout: GOTO_MS }).catch(() => undefined);
        await sleep(CARD_WAIT_MS);
        onSignIn = true;
      }
    } else {
      this.row("signin-page", "-", "skip", "no sign-in link found; the journey goes on with the home page");
    }
    let o = await this.observe(onSignIn ? "signin-page" : "home-fields");
    await this.record(o, onSignIn);

    // 3. Clicks on page controls while the card is there (before any focus: a focused field takes the card away).
    o = await this.observe("click-controls");
    if (o.snap.card !== null) {
      const clicked = await this.clickControls(o.scan);
      o.snap.controls = [...o.snap.controls, ...clicked];
    }
    await this.record(o, false);

    // 4. × then reload: the card must not come back.
    const closeMs = o.snap.card !== null ? await this.closeCard() : undefined;
    if (closeMs !== undefined) {
      this.closedByX = true;
      await this.record(await this.observe("close-x", { closeMs }), false);
      if (await this.go("reload-after-close", this.page.url(), true)) await this.record(await this.observe("reload-after-close"), true);
    }

    // 5. A field: focus, Escape.
    const field = this.pickField((await this.observe("before-focus")).scan);
    if (field && (await this.clickField(field.index))) {
      await this.record(await this.observe("focus-field", { focusExpected: true }), false);
      await this.page.keyboard.press("Escape");
      await sleep(600);
      await this.record(await this.observe("escape"), false);
    } else {
      this.row("focus-field", "-", "skip", "no sign-in field on the page");
    }

    // 6. The field menu.
    o = await this.observe("before-menu");
    const f2 = this.pickField(o.scan);
    if (f2) {
      const h = await this.fieldHandle(f2.index);
      if (h) {
        await h.focus().catch(() => undefined);
        await this.page.keyboard.press("ArrowDown");
        await sleep(1_500);
        await this.record(await this.observe("field-menu", { focusExpected: true }), false);
        await this.page.keyboard.press("Escape");
        await sleep(400);
      }
    }

    // 7. Another page of the site.
    const other = await this.page.evaluate(findOtherPage).catch(() => null);
    if (other && (await this.go("other-page", other))) await this.record(await this.observe("other-page"), true);
  }

  async dispose(): Promise<void> {
    await this.cdp?.detach().catch(() => undefined);
  }
}

/** Visits one target in a new tab of `env.context`, within the time box. Never throws. */
export async function visitSite(env: VisitEnv, target: Target): Promise<void> {
  let page: Page | undefined;
  let journey: Journey | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    page = await env.context.newPage();
    env.ownPages.add(page);
    await page.setViewportSize(VIEWPORT).catch(() => undefined);
    journey = new Journey(env, target, page);
    const box = new Promise<"timeout">((r) => {
      timer = setTimeout(() => r("timeout"), env.timeBoxMs);
    });
    // A journey cut by the time box goes on failing against the closed page: its rejection is kept, never thrown.
    const running = journey.run().then(() => "done" as const, (e: unknown) => ({ error: e }));
    const done = await Promise.race([running, box]);
    if (typeof done === "object") throw done.error;
    if (done === "timeout") env.emit({ host: target.host, kind: target.kind, step: "journey", rule: "-", verdict: "timeout", detail: `time box of ${Math.round(env.timeBoxMs / 1000)} s reached` });
  } catch (e) {
    env.emit({ host: target.host, kind: target.kind, step: "journey", rule: "-", verdict: "error", detail: String((e as Error)?.message ?? e).split("\n")[0]!.slice(0, 200) });
  } finally {
    if (timer) clearTimeout(timer);
    await journey?.dispose();
    await page?.close().catch(() => undefined);
  }
}

