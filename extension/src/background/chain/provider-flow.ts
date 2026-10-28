// Sign-in through a provider by hand (spec 8.7): a trusted click on a
// "Continuer avec <fournisseur>" button of a site, then a top frame
// navigation to an official host of that provider (exact host), is
// remembered as (tab, site origin, provider) for 5 minutes. On the
// provider's account chooser, the account the user clicks is noted. When
// the tab is back on the site without a sign-in form and no link existed,
// the save prompt offers "Enregistrer le lien <site> ↔ <fournisseur>
// (<email>)", then `link_provider`.
//
// Records hold no secret (origin, provider, email); kept in memory and in
// `storage.session` for worker restarts.
import { parseOrigin, sameSite } from "../../shared/domain";
import type { PageAnalysis, ProviderId } from "../../shared/messages";
import { providerForHost } from "../../shared/providers";
import type { StorageArea } from "../ext";
import type { CsContext } from "../frames";
import type { NeverSave } from "../never-save";
import type { SavePrompts } from "../save";
import type { Session } from "../session";

export const PROVIDER_FLOW_TTL_MS = 5 * 60 * 1000;
const PREFIX = "pflow:";
const PROVIDER_IDS: ReadonlySet<string> = new Set(["google", "apple", "microsoft", "github", "facebook", "x", "linkedin", "discord", "slack"]);

export interface ProviderFlow {
  tabId: number;
  siteOrigin: string;
  provider: ProviderId;
  at: number;
  /** The tab reached an official host of the provider. */
  visited: boolean;
  /** Account the user clicked on the provider's chooser. */
  email?: string;
}

function parseFlow(raw: unknown): ProviderFlow | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const int = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  if (!int(r.tabId) || !int(r.at) || typeof r.siteOrigin !== "string" || typeof r.visited !== "boolean") return null;
  if (typeof r.provider !== "string" || !PROVIDER_IDS.has(r.provider)) return null;
  if (r.email !== undefined && typeof r.email !== "string") return null;
  return r as unknown as ProviderFlow;
}

const norm = (e: string) => e.trim().toLowerCase();

/** A form the user would sign in with: the sign-in did not complete. */
function hasSignInForm(a: PageAnalysis): boolean {
  return a.forms.some(
    (f) => (f.kind === "login" || f.kind === "otp") && f.fields.some((x) => x.role !== "unknown" && x.role !== "remember_me"),
  );
}

export interface ProviderFlowDeps {
  area: StorageArea;
  session: Pick<Session, "request">;
  saves: Pick<SavePrompts, "open">;
  neverSave: Pick<NeverSave, "has">;
  chainRunning?: (tabId: number) => Promise<boolean>;
  now?: () => number;
}

export class ProviderFlows {
  private readonly mem = new Map<number, ProviderFlow>();
  private readonly now: () => number;

  constructor(private readonly deps: ProviderFlowDeps) {
    this.now = deps.now ?? Date.now;
  }

  private async get(tabId: number): Promise<ProviderFlow | null> {
    let f = this.mem.get(tabId) ?? null;
    if (!f) {
      f = parseFlow((await this.deps.area.get(PREFIX + tabId))[PREFIX + tabId]);
      if (f && f.tabId !== tabId) f = null;
    }
    if (f && (this.now() - f.at > PROVIDER_FLOW_TTL_MS || this.now() < f.at)) {
      await this.drop(tabId);
      return null;
    }
    if (f) this.mem.set(tabId, f);
    return f;
  }

  private async put(f: ProviderFlow): Promise<void> {
    this.mem.set(f.tabId, f);
    await this.deps.area.set({ [PREFIX + f.tabId]: f });
  }

  async drop(tabId: number): Promise<void> {
    this.mem.delete(tabId);
    await this.deps.area.remove(PREFIX + tabId);
  }

  /** Trusted click on a provider button in the top frame of a site. */
  async onProviderClick(cs: CsContext, provider: ProviderId): Promise<void> {
    if (cs.frameId !== 0 || parseOrigin(cs.origin)?.https !== true) return;
    // A button on the provider's own pages is not a site's sign-in.
    if (providerForHost(parseOrigin(cs.origin)?.host ?? "") !== null) return;
    await this.put({ tabId: cs.tabId, siteOrigin: cs.origin, provider, at: this.now(), visited: false });
  }

  /** A committed top frame navigation of `tabId`. */
  async onNavigation(tabId: number, url: string): Promise<void> {
    const f = await this.get(tabId);
    if (!f || f.visited) return;
    const p = parseOrigin(url);
    if (p?.https && providerForHost(p.host) === f.provider) {
      f.visited = true;
      await this.put(f);
    }
  }

  /** Trusted click on an account of the provider's chooser (top frame). */
  async onAccountClick(cs: CsContext, email: string): Promise<void> {
    if (cs.frameId !== 0) return;
    const f = await this.get(cs.tabId);
    const p = parseOrigin(cs.origin);
    if (!f || !p?.https || providerForHost(p.host) !== f.provider) return;
    f.email = norm(email);
    await this.put(f);
  }

  /**
   * The provider pages of a tracked flow: which site the user is signing in
   * to (the menu puts "Utilisé pour <site>" on the linked account).
   */
  async signingInto(tabId: number, origin: string): Promise<{ provider: ProviderId; siteOrigin: string } | null> {
    const f = await this.get(tabId);
    const p = parseOrigin(origin);
    if (!f || !p?.https || providerForHost(p.host) !== f.provider) return null;
    return { provider: f.provider, siteOrigin: f.siteOrigin };
  }

  /** Top frame analysis: back on the site without a form proposes the link. */
  async onAnalysis(a: PageAnalysis, cs: CsContext): Promise<void> {
    if (cs.frameId !== 0) return;
    const f = await this.get(cs.tabId);
    if (!f?.visited || parseOrigin(cs.origin)?.https !== true || !sameSite(cs.origin, f.siteOrigin)) return;
    if (hasSignInForm(a)) return;
    await this.drop(cs.tabId);
    await this.propose(f, cs);
  }

  private async propose(f: ProviderFlow, cs: CsContext): Promise<void> {
    if (await this.deps.chainRunning?.(f.tabId)) return;
    const site = parseOrigin(f.siteOrigin)?.site;
    if (!site || (await this.deps.neverSave.has(site))) return;
    let r: { accounts: { item_id: string; subtitle: string; title: string }[]; linked_item_id?: string };
    try {
      r = await this.deps.session.request({ op: "provider_accounts", ctx: "save_prompt", provider: f.provider, origin: f.siteOrigin });
    } catch {
      return;
    }
    // Spec 8.7: only when no link existed.
    if (r.linked_item_id !== undefined) return;
    const only = r.accounts.length === 1 ? r.accounts[0] : undefined;
    const account = f.email !== undefined ? r.accounts.find((x) => norm(x.subtitle) === f.email) : only;
    if (!account) return;
    const email = f.email ?? norm(account.subtitle);
    const pending = {
      tabId: f.tabId,
      origin: f.siteOrigin,
      kind: "provider_link" as const,
      status: "new" as const,
      username: email,
      password: "",
      provider: { id: f.provider, accountItemId: account.item_id, email, title: account.title },
      // Origin pin of the top document when no documentId is known (Firefox).
      topOrigin: cs.origin,
    };
    try {
      await this.deps.saves.open(cs.documentId !== undefined ? { ...pending, documentId: cs.documentId } : pending);
    } catch {
      // Content script gone.
    }
  }
}
