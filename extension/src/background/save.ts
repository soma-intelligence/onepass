// Save prompt (spec 8.5, 8.7): `save.html#<token>` in the top frame. The
// record holds the submitted password, so it lives in memory only and for
// at most 2 minutes, and blanked as soon as the prompt is saved, dismissed
// or closed (security hardening 6.3). The page gets the username and the choices; the
// password reaches the page only on "Afficher" (`save_reveal`) or as a value
// it asked to generate. Task 17 (save-flow) decides when to prompt and calls
// `open`.
//
// A card left unanswered goes away by itself ("later"): the submission then
// waits in the toolbar popup (`pendingList`, `decidePending`), in memory
// only, for PENDING_SAVE_TTL_MS, its password wiped on decision, expiry or
// tab close. A card opened while the vault was locked (`locked`) unlocks
// first on Save, asks `check_credentials` again, then saves, updates the
// login the host names, or says it is already there.
//
// The vault picked first: the last one used to save for that site, else the
// last one used anywhere, else the first the host lists (`storage.local`
// key `saveVaults`, vault ids and sites only, no secret).
import type { BgToCs, ProviderId, SaveDecision, SaveEdits, SaveOutcome } from "../shared/messages";
import { parseOrigin } from "../shared/domain";
import { newToken } from "../shared/tokens";
import type { PendingSave, SaveInit } from "../shared/ui";
import type { BgExt, StorageArea } from "./ext";
import type { FormGenerator } from "./generate";
import type { UiContext } from "./frames";
import type { NeverSave } from "./never-save";
import { removeFrame, resizeFrame } from "./overlay";
import { BgError, type Session } from "./session";
import { type BoundRecord, FrameTokens } from "./tokens";

export const SAVE_TTL_MS = 2 * 60 * 1000;
/** A submission whose card went away unanswered waits this long in the popup. */
export const PENDING_SAVE_TTL_MS = 10 * 60 * 1000;
/** At most this many waiting submissions (the oldest goes first). */
export const MAX_PENDING_SAVES = 8;
export const SAVE_VAULTS_KEY = "saveVaults";
const MAX_VAULT_SITES = 200;

export interface SavePending {
  tabId: number;
  /** Origin given by `sender` when the credentials were submitted. */
  origin: string;
  documentId?: string;
  kind: "login" | "provider_link";
  status: "new" | "update";
  username: string;
  password: string;
  /** The login to update (from `check_credentials`). */
  update?: { itemId: string; title: string };
  /** Provider link variant: the provider account used on this site. */
  provider?: { id: ProviderId; accountItemId: string; email: string; title?: string };
  /** Open straight in the edit view (menu "Enregistrer un nouveau login"). */
  view?: "edit";
  /**
   * Verified origin of the top document, sent as an origin pin when no
   * `documentId` is known (the content script shows the prompt only there).
   */
  topOrigin?: string;
  /** The vault was locked when the host was asked: Save unlocks first. */
  locked?: boolean;
}

/** What a save needs, from a card or from the popup's waiting list. */
interface Held {
  tabId: number;
  origin: string;
  status: "new" | "update";
  username: string;
  password: string;
  update?: { itemId: string; title: string };
  locked?: boolean;
}

interface Waiting extends Held {
  id: string;
  site: string;
  at: number;
  timer: ReturnType<typeof setTimeout>;
}

interface SaveRecord extends BoundRecord, Omit<SavePending, "tabId" | "origin" | "documentId"> {
  /** Set once saved, updated or "never": only `save_close` remains. */
  decided: boolean;
}

/** Tag of a Login saved before its form was sent (onepass_core::model::PENDING_TAG). */
export const PENDING_TAG = "onepass:pending";
/** Tag of a Login whose password the site forced to be weak (onepass_core::model::WEAK_BY_SITE_TAG). */
export const WEAK_BY_SITE_TAG = "onepass:weak-by-site";
/** Tags only OnePass sets: never taken from what a user types in the prompt. */
const RESERVED_TAGS: ReadonlySet<string> = new Set([PENDING_TAG, WEAK_BY_SITE_TAG]);

/** "atlas-cloud.test" -> "Atlas Cloud". */
export function titleFromSite(site: string): string {
  const label = site.split(".")[0] ?? site;
  const words = label.split(/[-_]+/).filter((w) => w !== "");
  if (words.length === 0) return site;
  return words.map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
}

export interface SaveDeps {
  ext: Pick<BgExt, "tabs" | "runtime">;
  session: Pick<Session, "request">;
  /** The popup's profile; no form here, so no page context. */
  generator: Pick<FormGenerator, "generate">;
  neverSave: NeverSave;
  now?: () => number;
  /** A login was saved or updated from the prompt of `tabId` (the site memory notes it, notes.ts). */
  onSaved?: (tabId: number, origin: string, itemId: string) => Promise<void>;
  /** `storage.local`: the vault last used per site (no secret). None: the first vault. */
  area?: StorageArea;
  /** Brings the app forward before an unlock (a card opened while locked). */
  openApp?: () => Promise<boolean>;
  /**
   * iOS: the vault lives in the Safari extension's own process (no app to bring forward). Save
   * on a card opened while locked unlocks it there with Face ID or Touch ID, the user's tap
   * being the one attempt. True: unlocked; false: still locked; null: no native vault (macOS,
   * other browsers), the app unlocks.
   */
  nativeUnlock?: () => Promise<boolean | null>;
}

interface VaultMemory {
  last?: string;
  sites: Record<string, string>;
}

export class SavePrompts {
  readonly tokens: FrameTokens<SaveRecord>;
  private readonly waiting = new Map<string, Waiting>();

  constructor(private readonly deps: SaveDeps) {
    this.tokens = new FrameTokens<SaveRecord>({
      prefix: "save:",
      ttlMs: SAVE_TTL_MS,
      // Dismiss, close, navigation and tab removal all end in a drop.
      onDrop: (rec) => {
        rec.password = "";
      },
      // Spec 8.5: the submitted password is kept at most 2 minutes.
      onExpire: async (rec) => {
        rec.password = "";
        await removeFrame(this.deps.ext.tabs, rec, "save");
      },
      ...(deps.now ? { now: deps.now } : {}),
    });
  }

  /** Shows the prompt in the top frame of `p.tabId`. */
  async open(p: SavePending): Promise<string> {
    const rec: Omit<SaveRecord, "createdAt"> = {
      tabId: p.tabId,
      frameId: 0,
      origin: p.origin,
      kind: p.kind,
      status: p.status,
      username: p.username,
      password: p.password,
      decided: false,
    };
    if (p.documentId !== undefined) rec.documentId = p.documentId;
    if (p.update) rec.update = { ...p.update };
    if (p.provider) rec.provider = { ...p.provider };
    if (p.view) rec.view = p.view;
    if (p.locked) rec.locked = true;
    const token = await this.tokens.register(rec);
    const msg: BgToCs = { type: "show_frame", kind: "save", url: `${this.deps.ext.runtime.getURL("save.html")}#${token}` };
    if (p.documentId === undefined && p.topOrigin !== undefined) msg.origin = p.topOrigin;
    const opts = p.documentId !== undefined ? { documentId: p.documentId } : { frameId: 0 };
    await this.deps.ext.tabs.sendMessage(p.tabId, msg, opts);
    return token;
  }

  /** The prompt's content height: its frame is sized to it. */
  async resize(token: string, ui: UiContext, height: number): Promise<object> {
    const rec = await this.record(token, ui, false);
    await resizeFrame(this.deps.ext.tabs, rec, "save", height);
    return {};
  }

  private async record(token: string, ui: UiContext, open = true): Promise<SaveRecord> {
    const rec = await this.tokens.resolve(token, ui);
    if (!rec || (open && rec.decided)) throw new BgError("invalid");
    return rec;
  }

  async init(token: string, ui: UiContext): Promise<SaveInit> {
    const rec = await this.record(token, ui);
    const site = parseOrigin(rec.origin)?.site ?? rec.origin;
    let vaults: SaveInit["vaults"] = [];
    let locked = rec.locked === true;
    if (rec.kind === "login") {
      try {
        const r = await this.deps.session.request({ op: "vaults" });
        vaults = r.vaults.map((v) => {
          const out: SaveInit["vaults"][number] = { id: v.id, name: v.name };
          if (typeof v.account === "string" && v.account !== "") out.account = v.account;
          return out;
        });
      } catch (e) {
        // Locked since the check: the card still offers Save (it unlocks first).
        if (!(e instanceof BgError) || e.code !== "locked") throw e;
        locked = true;
      }
    }
    const out: SaveInit = {
      origin: rec.origin,
      site,
      kind: rec.kind,
      status: rec.status,
      title: titleFromSite(site),
      username: rec.username,
      vaults,
    };
    if (rec.update) out.update = { ...rec.update };
    if (rec.provider) {
      out.provider = { id: rec.provider.id, email: rec.provider.email };
      if (rec.provider.title !== undefined) out.provider.title = rec.provider.title;
    }
    if (rec.view) out.view = rec.view;
    if (locked) out.locked = true;
    const vault = await this.defaultVault(site, vaults);
    if (vault !== undefined) out.defaultVault = vault;
    return out;
  }

  // ---- vault memory ----

  private async vaultMemory(): Promise<VaultMemory> {
    const raw = this.deps.area ? (await this.deps.area.get(SAVE_VAULTS_KEY).catch((): Record<string, unknown> => ({})))[SAVE_VAULTS_KEY] : undefined;
    const out: VaultMemory = { sites: {} };
    if (typeof raw !== "object" || raw === null) return out;
    const r = raw as { last?: unknown; sites?: unknown };
    if (typeof r.last === "string") out.last = r.last;
    if (typeof r.sites === "object" && r.sites !== null) {
      for (const [k, v] of Object.entries(r.sites)) if (typeof v === "string") out.sites[k] = v;
    }
    return out;
  }

  /** The vault Save picks first among `vaults`: this site's last, the last one, the first. */
  async defaultVault(site: string, vaults: readonly { id: string }[]): Promise<string | undefined> {
    const m = await this.vaultMemory();
    const ids = new Set(vaults.map((v) => v.id));
    for (const id of [m.sites[site], m.last]) if (id !== undefined && ids.has(id)) return id;
    return vaults[0]?.id;
  }

  private async rememberVault(site: string, vaultId: string): Promise<void> {
    if (!this.deps.area) return;
    const m = await this.vaultMemory();
    delete m.sites[site];
    m.sites[site] = vaultId;
    const keys = Object.keys(m.sites);
    for (const k of keys.slice(0, Math.max(0, keys.length - MAX_VAULT_SITES))) delete m.sites[k];
    await this.deps.area.set({ [SAVE_VAULTS_KEY]: { last: vaultId, sites: m.sites } }).catch(() => undefined);
  }

  async reveal(token: string, ui: UiContext): Promise<{ password: string }> {
    const rec = await this.record(token, ui);
    return { password: rec.password };
  }

  async generate(token: string, ui: UiContext): Promise<{ password: string }> {
    const rec = await this.record(token, ui);
    const g = await this.deps.generator.generate("save_prompt", rec.origin);
    rec.password = g.password;
    await this.tokens.update(token, rec);
    return { password: g.password };
  }

  async decide(token: string, ui: UiContext, decision: SaveDecision, edits?: SaveEdits): Promise<SaveOutcome | object> {
    const rec = await this.record(token, ui);
    /** The login saved or updated (a confirmed save). */
    let out: SaveOutcome = { outcome: "done" };
    switch (decision) {
      case "dismiss":
        await this.tokens.drop(token);
        await removeFrame(this.deps.ext.tabs, rec, "save");
        return {};
      case "later":
        // Unanswered: it waits in the popup (a sign-in the card offered, not the menu's blank login).
        if (rec.kind === "login" && rec.view !== "edit" && rec.password !== "") this.hold(rec);
        await this.tokens.drop(token);
        await removeFrame(this.deps.ext.tabs, rec, "save");
        return {};
      case "never":
        await this.deps.neverSave.add(parseOrigin(rec.origin)?.site ?? rec.origin);
        break;
      case "save":
        if (rec.kind === "provider_link") {
          if (!rec.provider) throw new BgError("invalid");
          await this.deps.session.request({
            op: "link_provider",
            ctx: "save_prompt",
            site_origin: rec.origin,
            provider: rec.provider.id,
            account_item_id: rec.provider.accountItemId,
          });
        } else {
          if (!edits) throw new BgError("invalid");
          out = await this.commit(rec, "save", edits);
        }
        break;
      case "update":
        // Only the item check_credentials named; the page cannot pick another.
        if (rec.kind !== "login" || !rec.update) throw new BgError("invalid");
        out = await this.commit(rec, "update", edits);
        break;
    }
    rec.password = "";
    rec.decided = true;
    await this.tokens.update(token, rec);
    return out;
  }

  /**
   * Saves or updates `h`. A card opened while locked unlocks first and asks
   * the host again: the login may already be there, or be one to update.
   */
  private async commit(h: Held, decision: "save" | "update", edits?: SaveEdits): Promise<SaveOutcome> {
    const site = parseOrigin(h.origin)?.site ?? h.origin;
    let status: "save" | "update" = decision;
    let update = h.update;
    if (h.locked) {
      const native = this.deps.nativeUnlock ? await this.deps.nativeUnlock().catch(() => false) : null;
      if (native === false) throw new BgError("locked");
      if (native === null) {
        await this.deps.openApp?.().catch(() => false);
        const u = await this.deps.session.request({ op: "unlock" });
        if (u.locked) throw new BgError("locked");
      }
      const r = await this.deps.session.request({
        op: "check_credentials",
        ctx: "save_prompt",
        origin: h.origin,
        username: edits && edits.username.trim() !== "" ? edits.username : h.username,
        password: edits && edits.password !== "" ? edits.password : h.password,
      });
      if (r.status === "same" || r.status === "pending") return { outcome: "already" };
      if (r.status === "update" && r.item_id !== undefined) {
        status = "update";
        update = { itemId: r.item_id, title: r.title ?? "" };
      }
    }
    let saved: string;
    let vaultName: string | undefined;
    if (status === "update") {
      if (!update) throw new BgError("invalid");
      await this.deps.session.request({
        op: "update_password",
        ctx: "save_prompt",
        item_id: update.itemId,
        origin: h.origin,
        password: edits && edits.password !== "" ? edits.password : h.password,
      });
      saved = update.itemId;
    } else {
      if (!edits) throw new BgError("invalid");
      // Empty: the password typed on the page (never sent to the prompt unless revealed).
      const password = edits.password === "" ? h.password : edits.password;
      // A login without a password is never saved (new login from the menu, nothing typed).
      if (password === "") throw new BgError("invalid");
      // The vault list names the vault in the outcome; a card opened locked had none: the default one now.
      // A host that cannot list (yet) leaves the choice as is: save_login answers for it.
      const listed = await this.deps.session.request({ op: "vaults" }).catch(() => ({ vaults: [] }));
      const vaults = Array.isArray(listed.vaults) ? listed.vaults : [];
      const vaultId =
        vaults.length === 0 || vaults.some((v) => v.id === edits.vaultId) ? edits.vaultId : await this.defaultVault(site, vaults);
      if (vaultId === undefined) throw new BgError("not_found");
      vaultName = vaults.find((v) => v.id === vaultId)?.name;
      const r = await this.deps.session.request({
        op: "save_login",
        ctx: "save_prompt",
        origin: h.origin,
        title: edits.title.trim() === "" ? titleFromSite(site) : edits.title,
        username: edits.username,
        password,
        vault_id: vaultId,
        rule: edits.rule,
        tags: edits.tags.filter((t) => !RESERVED_TAGS.has(t.trim())),
      });
      saved = r.item_id;
      await this.rememberVault(site, vaultId);
    }
    await this.deps.onSaved?.(h.tabId, h.origin, saved).catch(() => undefined);
    const out: SaveOutcome = { outcome: status === "update" ? "updated" : "saved" };
    if (vaultName !== undefined) out.vault = vaultName;
    return out;
  }

  // ---- waiting in the popup ----

  private hold(rec: SaveRecord): void {
    const id = newToken();
    const site = parseOrigin(rec.origin)?.site ?? rec.origin;
    // One per tab and site: a newer sign-in replaces the older one.
    for (const w of [...this.waiting.values()]) if (w.tabId === rec.tabId && w.site === site) this.forget(w.id);
    while (this.waiting.size >= MAX_PENDING_SAVES) {
      const oldest = this.waiting.keys().next().value;
      if (oldest === undefined) break;
      this.forget(oldest);
    }
    const w: Waiting = {
      id,
      site,
      at: (this.deps.now ?? Date.now)(),
      tabId: rec.tabId,
      origin: rec.origin,
      status: rec.status,
      username: rec.username,
      password: rec.password,
      timer: setTimeout(() => this.forget(id), PENDING_SAVE_TTL_MS),
    };
    if (rec.update) w.update = { ...rec.update };
    if (rec.locked) w.locked = true;
    this.waiting.set(id, w);
  }

  private forget(id: string): void {
    const w = this.waiting.get(id);
    if (!w) return;
    clearTimeout(w.timer);
    w.password = "";
    this.waiting.delete(id);
  }

  /** The tab closed: its waiting sign-ins go. */
  forgetTab(tabId: number): void {
    for (const w of [...this.waiting.values()]) if (w.tabId === tabId) this.forget(w.id);
  }

  /** Waiting sign-ins, newest first (no password). */
  async pendingList(): Promise<PendingSave[]> {
    const now = (this.deps.now ?? Date.now)();
    const out: PendingSave[] = [];
    let vaults: { id: string; name: string }[] | null = null;
    for (const w of [...this.waiting.values()].reverse()) {
      if (now - w.at > PENDING_SAVE_TTL_MS) {
        this.forget(w.id);
        continue;
      }
      const p: PendingSave = { id: w.id, origin: w.origin, site: w.site, username: w.username, status: w.update ? w.status : "new" };
      if (w.update) p.title = w.update.title;
      else if (!w.locked) {
        vaults ??= await this.deps.session.request({ op: "vaults" }).then((r) => r.vaults, () => []);
        const id = await this.defaultVault(w.site, vaults);
        const name = vaults.find((v) => v.id === id)?.name;
        if (name !== undefined) p.vault = name;
      }
      out.push(p);
    }
    return out;
  }

  /** The popup's answer to a waiting sign-in. */
  async decidePending(id: string, decision: "save" | "update" | "never" | "dismiss"): Promise<SaveOutcome | object> {
    const w = this.waiting.get(id);
    if (!w) throw new BgError("not_found");
    if (decision === "dismiss") {
      this.forget(id);
      return {};
    }
    if (decision === "never") {
      await this.deps.neverSave.add(w.site);
      this.forget(id);
      return {};
    }
    if (decision === "update" && !w.update) throw new BgError("invalid");
    const vaults = w.locked || decision === "update" ? [] : (await this.deps.session.request({ op: "vaults" })).vaults;
    const edits: SaveEdits = {
      title: titleFromSite(w.site),
      username: w.username,
      password: "",
      vaultId: (await this.defaultVault(w.site, vaults)) ?? "",
      rule: "domain",
      tags: [],
    };
    const out = await this.commit(w, decision === "update" ? "update" : "save", edits);
    this.forget(id);
    return out;
  }

  async close(token: string, ui: UiContext): Promise<object> {
    const rec = await this.record(token, ui, false);
    await this.tokens.drop(token);
    await removeFrame(this.deps.ext.tabs, rec, "save");
    return {};
  }
}
