// Save prompt (spec 8.5, 8.7): `save.html#<token>` in the top frame. The
// record holds the submitted password, so it lives in memory only and for
// at most 2 minutes, and blanked as soon as the prompt is saved, dismissed
// or closed (security hardening 6.3). The page gets the username and the choices; the
// password reaches the page only on "Afficher" (`save_reveal`) or as a value
// it asked to generate. Task 17 (save-flow) decides when to prompt and calls
// `open`.
import type { BgToCs, ProviderId, SaveDecision, SaveEdits } from "../shared/messages";
import { parseOrigin } from "../shared/domain";
import type { SaveInit } from "../shared/ui";
import type { BgExt } from "./ext";
import type { UiContext } from "./frames";
import type { NeverSave } from "./never-save";
import { removeFrame } from "./overlay";
import { BgError, type Session } from "./session";
import { type BoundRecord, FrameTokens } from "./tokens";

export const SAVE_TTL_MS = 2 * 60 * 1000;

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
  provider?: { id: ProviderId; accountItemId: string; email: string };
  /** Open straight in the edit view (menu "Enregistrer un nouveau login"). */
  view?: "edit";
  /**
   * Verified origin of the top document, sent as an origin pin when no
   * `documentId` is known (the content script shows the prompt only there).
   */
  topOrigin?: string;
}

interface SaveRecord extends BoundRecord, Omit<SavePending, "tabId" | "origin" | "documentId"> {
  /** Set once saved, updated or "never": only `save_close` remains. */
  decided: boolean;
}

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
  neverSave: NeverSave;
  now?: () => number;
}

export class SavePrompts {
  readonly tokens: FrameTokens<SaveRecord>;

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
    const token = await this.tokens.register(rec);
    const msg: BgToCs = { type: "show_frame", kind: "save", url: `${this.deps.ext.runtime.getURL("save.html")}#${token}` };
    if (p.documentId === undefined && p.topOrigin !== undefined) msg.origin = p.topOrigin;
    const opts = p.documentId !== undefined ? { documentId: p.documentId } : { frameId: 0 };
    await this.deps.ext.tabs.sendMessage(p.tabId, msg, opts);
    return token;
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
    if (rec.kind === "login") {
      const r = await this.deps.session.request({ op: "vaults" });
      vaults = r.vaults.map((v) => ({ id: v.id, name: v.name }));
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
    if (rec.provider) out.provider = { id: rec.provider.id, email: rec.provider.email };
    if (rec.view) out.view = rec.view;
    return out;
  }

  async reveal(token: string, ui: UiContext): Promise<{ password: string }> {
    const rec = await this.record(token, ui);
    return { password: rec.password };
  }

  async generate(token: string, ui: UiContext): Promise<{ password: string }> {
    const rec = await this.record(token, ui);
    const g = await this.deps.session.request({ op: "generate", ctx: "save_prompt", recipe: { kind: "smart" } });
    rec.password = g.password;
    await this.tokens.update(token, rec);
    return { password: g.password };
  }

  async decide(token: string, ui: UiContext, decision: SaveDecision, edits?: SaveEdits): Promise<object> {
    const rec = await this.record(token, ui);
    switch (decision) {
      case "dismiss":
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
          // Empty: the password typed on the page (never sent to the prompt unless revealed).
          const password = edits.password === "" ? rec.password : edits.password;
          // A login without a password is never saved (new login from the menu, nothing typed).
          if (password === "") throw new BgError("invalid");
          await this.deps.session.request({
            op: "save_login",
            ctx: "save_prompt",
            origin: rec.origin,
            title: edits.title.trim() === "" ? titleFromSite(parseOrigin(rec.origin)?.site ?? rec.origin) : edits.title,
            username: edits.username,
            password,
            vault_id: edits.vaultId,
            rule: edits.rule,
            tags: edits.tags,
          });
        }
        break;
      case "update":
        // Only the item check_credentials named; the page cannot pick another.
        if (rec.kind !== "login" || !rec.update) throw new BgError("invalid");
        await this.deps.session.request({
          op: "update_password",
          ctx: "save_prompt",
          item_id: rec.update.itemId,
          origin: rec.origin,
          password: edits && edits.password !== "" ? edits.password : rec.password,
        });
        break;
    }
    rec.password = "";
    rec.decided = true;
    await this.tokens.update(token, rec);
    return {};
  }

  async close(token: string, ui: UiContext): Promise<object> {
    const rec = await this.record(token, ui, false);
    await this.tokens.drop(token);
    await removeFrame(this.deps.ext.tabs, rec, "save");
    return {};
  }
}
