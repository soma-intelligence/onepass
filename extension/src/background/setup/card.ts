// The two-factor setup card (spec section 1): `setup.html#<token>` in the top frame of the tab
// the popup scanned. The token is the extension's own frame token (tokens.ts), bound to that
// tab, frame 0, origin and document; it lives SETUP_TTL_MS, dies on any top-frame navigation
// and on tab removal, and serves one final `setup_save`. Its record holds the scanned or pasted
// seed (`uri`), so it has no storage area: memory only, and the seed is dropped once the host
// gave a final answer. The card gets the issuer and the account, never the seed.
//
// After a seed is saved the code is filled through the usual login fill (`fields: ["totp"]`,
// ctx `setup`, no submit). No code field: the card shows the code `fill_login` returned (the
// popup's `totp` op is not allowed under ctx `setup`). The page is then watched 5 minutes for
// recovery codes: `storage.session` keeps `{ tabId, site, itemId, until }` (no secret) so a
// top-frame navigation inside the site injects the watcher again. Codes the scanner reports are
// held in memory only, in a card of their own.
import { parseOrigin } from "../../shared/domain";
import { t } from "../../shared/i18n";
import {
  type BgToCs,
  type BgToScan,
  type CsToBg,
  type FormInfo,
  SETUP_REFUSALS,
  type SetupCandidate,
  type SetupCardState,
  type SetupCodesResult,
  type SetupRefusal,
  type SetupSaveResult,
} from "../../shared/messages";
import { type OtpauthShallow, pastedSecret } from "../../setup/otpauth";
import type { PageAnalyses } from "../analyses";
import type { BgExt, StorageArea } from "../ext";
import type { Filler } from "../fill";
import type { CsContext, UiContext } from "../frames";
import { removeFrame, resizeFrame } from "../overlay";
import { BgError, type Session, toBgError } from "../session";
import { type BoundRecord, FrameTokens } from "../tokens";

export const SETUP_TTL_MS = 120_000;
/** How long the page is watched for recovery codes after a seed was saved. */
export const WATCH_MS = 300_000;
/** `storage.session` key of a tab's watch record (`setupWatch:<tabId>`). */
export const WATCH_PREFIX = "setupWatch:";
export const SCANNER_FILE = "setup-scan.js";

const DEFAULT_PERIOD = 30;

interface SetupRecord extends BoundRecord {
  mode: SetupCardState["mode"];
  /** The seed: memory only, gone once the host answered for good. */
  uri?: string;
  issuer: string;
  account: string;
  /** Seconds per code, read from the seed (the countdown of a code the card shows). */
  period: number;
  /** What `init` offered: a save names one of these or none. */
  candidates?: SetupCandidate[];
  selected?: string | null;
  /** The login the seed went to (mode `codes`: the one the codes go to). */
  itemId?: string;
  /** Recovery codes the page showed (mode `codes`), memory only. */
  codes?: string[];
  /** A final answer was given: only `init` and `close` remain. */
  spent: boolean;
  /** The item the host answered `exists` for, in this card: only it may be replaced. */
  existsItemId?: string;
  /** A `save_totp` or `save_recovery_codes` of this card is waiting for the host. */
  inFlight?: boolean;
}

interface WatchRecord {
  tabId: number;
  site: string;
  itemId: string;
  until: number;
}

export interface SetupCardsDeps {
  ext: Pick<BgExt, "tabs" | "runtime" | "storage" | "webNavigation" | "scripting">;
  session: Pick<Session, "request">;
  filler: Pick<Filler, "fillLogin">;
  analyses: Pick<PageAnalyses, "top">;
  /** The login OnePass last filled in `tabId` on the site of `origin` (save-flow), if any. */
  lastUsed?: (tabId: number, origin: string) => string | null;
  /** The existing unlock ask of a click in a card (the app, or Face ID on iOS). */
  askUnlock?: (tabId: number) => Promise<unknown>;
  now?: () => number;
}

export interface OpenSetup {
  tabId: number;
  origin: string;
  documentId?: string;
  /** What the scan read; null: the card asks for the setup key. */
  found: OtpauthShallow | null;
}

const norm = (s: string) => s.trim().toLowerCase();

const REFUSALS: ReadonlySet<string> = new Set(SETUP_REFUSALS);

/** Why the host (or the worker) refused a setup write, as the card says it. */
function refusal(e: unknown): SetupRefusal {
  const code = toBgError(e).code;
  return REFUSALS.has(code) ? (code as SetupRefusal) : "internal";
}

/** Seconds per code of an `otpauth://` URI (30 unless it says otherwise, 1 to 300). */
function periodOf(uri: string): number {
  const q = uri.indexOf("?");
  if (q < 0) return DEFAULT_PERIOD;
  const p = Number(new URLSearchParams(uri.slice(q + 1).split("#")[0]).get("period"));
  return Number.isInteger(p) && p >= 1 && p <= 300 ? p : DEFAULT_PERIOD;
}

/**
 * The target preselected (spec section 1): the item whose username is the QR account; else the
 * one last used on this site; else the only one. Several and no hit: none, the user picks. Never
 * an associated item.
 */
export function preselect(candidates: readonly SetupCandidate[], account: string, lastUsed: string | null): string | null {
  const plain = candidates.filter((c) => !c.associated);
  const a = norm(account);
  if (a !== "") {
    const hit = plain.find((c) => norm(c.username) === a);
    if (hit) return hit.itemId;
  }
  if (lastUsed !== null) {
    const hit = plain.find((c) => c.itemId === lastUsed);
    if (hit) return hit.itemId;
  }
  return plain.length === 1 ? (plain[0]?.itemId ?? null) : null;
}

/** The form of the top analysis that takes a one-time code, if any. */
function codeForm(forms: readonly FormInfo[]): FormInfo | undefined {
  return forms.find((f) => f.kind === "otp") ?? forms.find((f) => f.fields.some((x) => x.role === "otp"));
}

function parseWatch(raw: unknown): WatchRecord | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const int = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  if (!int(r.tabId) || !int(r.until) || typeof r.site !== "string" || typeof r.itemId !== "string") return null;
  return { tabId: r.tabId, site: r.site, itemId: r.itemId, until: r.until };
}

export class SetupCards {
  readonly tokens: FrameTokens<SetupRecord>;
  private readonly now: () => number;
  private readonly area: StorageArea;

  constructor(private readonly deps: SetupCardsDeps) {
    this.now = deps.now ?? Date.now;
    this.area = deps.ext.storage.session;
    this.tokens = new FrameTokens<SetupRecord>({
      prefix: "setup:",
      ttlMs: SETUP_TTL_MS,
      // No `area`: the record holds the seed.
      onDrop: (rec) => this.wipe(rec),
      onExpire: async (rec) => {
        this.wipe(rec);
        await removeFrame(this.deps.ext.tabs, rec, "setup");
      },
      ...(deps.now ? { now: deps.now } : {}),
    });
  }

  private wipe(rec: SetupRecord): void {
    delete rec.uri;
    if (rec.codes) rec.codes.fill("");
    delete rec.codes;
  }

  install(ext: Pick<BgExt, "webNavigation" | "tabs">): void {
    this.tokens.install(ext);
    ext.webNavigation.onCommitted.addListener((d) => {
      if (d.frameId === 0) void this.leftSite(d.tabId, d.url).catch(() => undefined);
    });
    ext.webNavigation.onCompleted.addListener((d) => {
      if (d.frameId === 0) void this.rewatch(d.tabId, d.url).catch(() => undefined);
    });
    ext.tabs.onRemoved.addListener((tabId) => void this.area.remove(WATCH_PREFIX + tabId).catch(() => undefined));
  }

  /** Mints the card's token and shows the card in the top frame of `p.tabId`. */
  async open(p: OpenSetup): Promise<string> {
    const host = parseOrigin(p.origin)?.host ?? "";
    const rec: Omit<SetupRecord, "createdAt"> = p.found
      ? { tabId: p.tabId, frameId: 0, origin: p.origin, mode: "confirm", uri: p.found.uri, issuer: p.found.issuer, account: p.found.account, period: periodOf(p.found.uri), spent: false }
      : { tabId: p.tabId, frameId: 0, origin: p.origin, mode: "paste", issuer: host, account: "", period: DEFAULT_PERIOD, spent: false };
    if (p.documentId !== undefined) rec.documentId = p.documentId;
    return this.show(rec);
  }

  private async show(rec: Omit<SetupRecord, "createdAt">): Promise<string> {
    const token = await this.tokens.register(rec);
    const msg: BgToCs = { type: "show_frame", kind: "setup", url: `${this.deps.ext.runtime.getURL("setup.html")}#${token}` };
    if (rec.documentId === undefined) msg.origin = rec.origin;
    const opts = rec.documentId !== undefined ? { documentId: rec.documentId } : { frameId: 0 };
    try {
      await this.deps.ext.tabs.sendMessage(rec.tabId, msg, opts);
    } catch {
      // No content script in that document (gone meanwhile): no card.
      await this.tokens.drop(token);
      throw new BgError("origin_mismatch");
    }
    return token;
  }

  private async record(token: string, ui: UiContext): Promise<SetupRecord> {
    const rec = await this.tokens.resolve(token, ui);
    if (!rec) throw new BgError("invalid");
    return rec;
  }

  private state(rec: SetupRecord): SetupCardState {
    const candidates = (rec.candidates ?? []).map((c) => ({ ...c }));
    const selected = rec.selected ?? null;
    const sel = candidates.find((c) => c.itemId === selected);
    const out: SetupCardState = {
      mode: rec.mode,
      issuer: rec.issuer,
      account: rec.account,
      candidates,
      selected,
      mismatch: rec.mode === "confirm" && sel !== undefined && norm(rec.account) !== "" && norm(sel.username) !== norm(rec.account),
    };
    if (rec.mode === "codes") out.codeCount = rec.codes?.length ?? 0;
    return out;
  }

  async init(token: string, ui: UiContext): Promise<SetupCardState> {
    const rec = await this.record(token, ui);
    const { items } = await this.deps.session.request({ op: "list_for_origin", ctx: "setup", origin: rec.origin });
    // Only logins of the page itself (exact host or domain): the bridge refuses an associated one.
    rec.candidates = items
      .filter((s) => s.kind === "login" && s.associated !== true)
      .map((s) => ({ itemId: s.item_id, title: s.title, username: s.subtitle, hasTotp: s.has_totp, associated: s.associated === true }));
    if (rec.mode === "codes") {
      // The login the seed just went to.
      rec.selected = rec.candidates.some((c) => c.itemId === rec.itemId) ? (rec.itemId ?? null) : null;
    } else {
      rec.selected = preselect(rec.candidates, rec.account, this.deps.lastUsed?.(rec.tabId, rec.origin) ?? null);
    }
    await this.tokens.update(token, rec);
    return this.state(rec);
  }

  /**
   * The key typed in the card: wrapped into `otpauth://totp/<host>:<account>?secret=<KEY>&issuer=<host>`
   * (the host takes no bare key), the account being the selected item's username.
   */
  async paste(token: string, ui: UiContext, key: string): Promise<SetupCardState | { error: "invalid" }> {
    const rec = await this.record(token, ui);
    if (rec.spent || rec.mode === "codes") throw new BgError("invalid");
    const secret = pastedSecret(key);
    if (secret === null) return { error: "invalid" };
    const host = parseOrigin(rec.origin)?.host ?? "";
    const sel = rec.candidates?.find((c) => c.itemId === rec.selected);
    const account = sel?.username.trim() ?? "";
    const issuer = encodeURIComponent(host);
    rec.uri = `otpauth://totp/${issuer}:${encodeURIComponent(account)}?secret=${secret}&issuer=${issuer}`;
    rec.issuer = host;
    rec.account = account;
    rec.period = DEFAULT_PERIOD;
    rec.mode = "confirm";
    if (rec.candidates) rec.selected = preselect(rec.candidates, account, this.deps.lastUsed?.(rec.tabId, rec.origin) ?? null);
    await this.tokens.update(token, rec);
    return this.state(rec);
  }

  /** Is `token` still this very record (no navigation, removal or expiry meanwhile)? */
  private async alive(token: string, ui: UiContext, rec: SetupRecord): Promise<boolean> {
    return (await this.tokens.resolve(token, ui).catch(() => null)) === rec;
  }

  private askUnlock(tabId: number): void {
    void Promise.resolve()
      .then(() => this.deps.askUnlock?.(tabId))
      .catch(() => undefined);
  }

  async save(token: string, ui: UiContext, itemId: string | null, username?: string, replace?: boolean): Promise<SetupSaveResult> {
    const rec = await this.record(token, ui);
    if (rec.spent || rec.mode !== "confirm" || rec.uri === undefined) throw new BgError("invalid");
    // Only an item the card offered.
    if (itemId !== null && !(rec.candidates ?? []).some((c) => c.itemId === itemId)) throw new BgError("invalid");
    // A second click while the host writes: nothing more is sent.
    if (rec.inFlight) return { status: "refused", reason: "invalid" };
    // Replace only answers an `exists` this very card was given, for that very item.
    if (replace === true && (itemId === null || rec.existsItemId !== itemId)) return { status: "refused", reason: "invalid" };
    const req: { op: "save_totp"; ctx: "setup"; origin: string; uri: string; item_id?: string; username?: string; replace?: boolean; previous_label: string } = {
      op: "save_totp",
      ctx: "setup",
      origin: rec.origin,
      uri: rec.uri,
      previous_label: t("setup.previousCode"),
    };
    if (itemId !== null) req.item_id = itemId;
    else req.username = (username ?? "").trim() || rec.account;
    if (replace === true) req.replace = true;
    let r: { status: "saved" | "same" | "exists" | "replaced"; item_id: string };
    rec.inFlight = true;
    try {
      r = await this.deps.session.request(req);
    } catch (e) {
      rec.inFlight = false;
      if (toBgError(e).code === "locked") {
        // The seed stays: the card's next click retries without a new scan.
        this.askUnlock(rec.tabId);
        return { status: "locked" };
      }
      this.wipe(rec);
      rec.spent = true;
      await this.tokens.update(token, rec);
      return { status: "refused", reason: refusal(e) };
    }
    rec.inFlight = false;
    if (r.status === "exists") {
      if (itemId !== null) rec.existsItemId = itemId;
      return { status: "exists" };
    }
    const period = rec.period;
    this.wipe(rec);
    rec.spent = true;
    rec.itemId = r.item_id;
    // The tab moved on while the host wrote: nothing more goes to it.
    if (!(await this.alive(token, ui, rec))) return { status: r.status };
    await this.tokens.update(token, rec);
    const out: SetupSaveResult = { status: r.status };
    const code = await this.fillCode(rec, r.item_id, period);
    if (code) {
      out.code = code.code;
      out.remaining = code.remaining;
    }
    if (await this.alive(token, ui, rec)) await this.watch(rec, r.item_id);
    return out;
  }

  /**
   * The code of the seed just saved, into the page's code field (no submit). Null when a field
   * took it; else the code `fill_login` returned, for the card to show.
   */
  private async fillCode(rec: SetupRecord, itemId: string, period: number): Promise<{ code: string; remaining: number } | null> {
    const top = await this.deps.analyses.top(rec.tabId).catch(() => null);
    const sameDoc = top !== null && top.origin === rec.origin && (rec.documentId === undefined || top.documentId === undefined || top.documentId === rec.documentId);
    const form = sameDoc ? codeForm(top.analysis.forms) : undefined;
    if (form) {
      const target = { tabId: rec.tabId, frameId: 0, origin: rec.origin, formRef: form.ref };
      const documentId = top?.documentId ?? rec.documentId;
      const written = await this.deps.filler
        .fillLogin(documentId !== undefined ? { ...target, documentId } : target, itemId, ["totp"], "setup")
        .catch(() => 0);
      if (written > 0) return null;
    }
    const r = await this.deps.session.request({ op: "fill_login", ctx: "setup", item_id: itemId, origin: rec.origin, fields: ["totp"] }).catch(() => null);
    if (!r || typeof r.totp !== "string" || r.totp === "") return null;
    const secs = Math.floor(this.now() / 1000);
    return { code: r.totp, remaining: period - (secs % period) };
  }

  /** The page is watched for recovery codes: the scanner in the top frame, the record in `storage.session`. */
  private async watch(rec: SetupRecord, itemId: string): Promise<void> {
    const site = parseOrigin(rec.origin)?.site;
    if (!site) return;
    const w: WatchRecord = { tabId: rec.tabId, site, itemId, until: this.now() + WATCH_MS };
    await this.area.set({ [WATCH_PREFIX + rec.tabId]: w }).catch(() => undefined);
    const msg: BgToScan = { type: "setup_watch_codes", ms: WATCH_MS };
    const opts = rec.documentId !== undefined ? { documentId: rec.documentId } : { frameId: 0 };
    await this.deps.ext.tabs.sendMessage(rec.tabId, msg, opts).catch(() => undefined);
  }

  private async readWatch(tabId: number): Promise<WatchRecord | null> {
    const key = WATCH_PREFIX + tabId;
    const w = parseWatch((await this.area.get(key).catch((): Record<string, unknown> => ({})))[key]);
    if (!w || w.tabId !== tabId) return null;
    if (this.now() >= w.until) {
      await this.area.remove(key).catch(() => undefined);
      return null;
    }
    return w;
  }

  /** A top-frame navigation of a watched tab to another site ends the watch. */
  private async leftSite(tabId: number, url: string): Promise<void> {
    const w = await this.readWatch(tabId);
    if (w && parseOrigin(url)?.site !== w.site) await this.area.remove(WATCH_PREFIX + tabId);
  }

  /** A new top document of the watched site loaded: the watcher again, for what is left. */
  private async rewatch(tabId: number, url: string): Promise<void> {
    const w = await this.readWatch(tabId);
    const o = parseOrigin(url);
    if (!w || !o?.page || o.site !== w.site) return;
    const scripting = this.deps.ext.scripting;
    if (!scripting) return;
    await scripting.executeScript({ target: { tabId, frameIds: [0] }, files: [SCANNER_FILE] });
    const msg: BgToScan = { type: "setup_watch_codes", ms: w.until - this.now() };
    await this.deps.ext.tabs.sendMessage(tabId, msg, { frameId: 0 });
  }

  /** The scanner saw recovery codes: only the top frame of a watched tab, on the watched site. */
  async codesFound(m: Extract<CsToBg, { type: "setup_codes_found" }>, cs: CsContext): Promise<object> {
    if (cs.frameId !== 0) throw new BgError("invalid");
    const o = parseOrigin(cs.origin);
    const w = await this.readWatch(cs.tabId);
    if (!w || !o?.page || o.site !== w.site) throw new BgError("invalid");
    // One report per watch.
    await this.area.remove(WATCH_PREFIX + cs.tabId);
    const rec: Omit<SetupRecord, "createdAt"> = {
      tabId: cs.tabId,
      frameId: 0,
      origin: cs.origin,
      mode: "codes",
      issuer: o.host,
      account: "",
      period: DEFAULT_PERIOD,
      itemId: w.itemId,
      codes: [...m.codes],
      spent: false,
    };
    if (cs.documentId !== undefined) rec.documentId = cs.documentId;
    await this.show(rec);
    return {};
  }

  async codesSave(token: string, ui: UiContext): Promise<SetupCodesResult> {
    const rec = await this.record(token, ui);
    if (rec.spent || rec.mode !== "codes" || !rec.codes || rec.itemId === undefined) throw new BgError("invalid");
    if (rec.inFlight) return { status: "refused", reason: "invalid" };
    rec.inFlight = true;
    try {
      await this.deps.session.request({
        op: "save_recovery_codes",
        ctx: "setup",
        origin: rec.origin,
        item_id: rec.itemId,
        codes: rec.codes.join("\n"),
        label: t("setup.recoveryLabel"),
      });
    } catch (e) {
      rec.inFlight = false;
      if (toBgError(e).code === "locked") {
        this.askUnlock(rec.tabId);
        return { status: "locked" };
      }
      this.wipe(rec);
      rec.spent = true;
      await this.tokens.update(token, rec);
      return { status: "refused", reason: refusal(e) };
    }
    rec.inFlight = false;
    this.wipe(rec);
    rec.spent = true;
    await this.tokens.update(token, rec);
    return { status: "saved" };
  }

  /** The card's content height: the frame in the page takes it. */
  async resize(token: string, ui: UiContext, height: number): Promise<object> {
    const rec = await this.record(token, ui);
    await resizeFrame(this.deps.ext.tabs, rec, "setup", height);
    return {};
  }

  /**
   * The card's Close. A token that no longer resolves (worker restart, expiry) still takes the
   * card out of the top frame of the tab it is shown in.
   */
  async close(token: string, ui: UiContext): Promise<object> {
    const rec = await this.tokens.resolve(token, ui).catch(() => null);
    if (!rec) {
      if (ui.tabId !== undefined) {
        const msg: BgToCs = { type: "remove_frame", kind: "setup" };
        await this.deps.ext.tabs.sendMessage(ui.tabId, msg, { frameId: 0 }).catch(() => undefined);
      }
      throw new BgError("invalid");
    }
    await this.tokens.drop(token);
    await removeFrame(this.deps.ext.tabs, rec, "setup");
    return {};
  }
}
