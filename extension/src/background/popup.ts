// Handlers of the toolbar popup (spec 8.8). The popup never names a target:
// "Remplir" goes to the top frame of the active tab, whose origin the worker
// reads from the browser, into a form the content script reported there.
// Generator history: 20 entries in a module-level array of the service worker,
// never written to any storage. It is cleared when the host answers `locked`
// or the pairing is forgotten, and a worker restart starts it empty.
//
// Smart fill: the suggestions carry the plan of the active tab in one line
// (`planLine`), its alternatives first; the line's Fill asks the tab's
// content script to run smart fill (a gesture of the user); "Oublier mes
// choix sur ce site" forgets the site memory of the tab's site.
import type { FillField, Summary } from "../bridge/client";
import { parseOrigin } from "../shared/domain";
import type { FormInfo, FormKind, PlanOut } from "../shared/messages";
import type { GeneratorEntry, PopupItem, PopupPlanLine, PopupSuggestions } from "../shared/ui";
import type { PageAnalyses } from "./analyses";
import type { BgExt, StorageArea } from "./ext";
import type { FillTarget, Filler } from "./fill";
import type { PairingFlow } from "./pairing";
import type { Handlers } from "./router";
import { BgError, type Session } from "./session";

/** Key an earlier version used in `storage.session`; removed at startup. */
export const HISTORY_KEY = "genHistory";
export const HISTORY_MAX = 20;

/** Memory only: a restart of the worker (a new module evaluation) empties it. */
let historyEntries: GeneratorEntry[] = [];

/** Test-only: the state a fresh worker would have (tests share one module instance). */
export function resetGeneratorHistoryForTests(): void {
  historyEntries = [];
}

export interface PopupDeps {
  ext: Pick<BgExt, "tabs">;
  area: StorageArea;
  session: Pick<Session, "request" | "onLocked">;
  pairing: Pick<PairingFlow, "startPairing" | "confirmPairing" | "cancelPairing" | "forgetPairing">;
  filler: Pick<Filler, "fillLogin" | "fillCard" | "fillIdentity" | "fillGenerated">;
  analyses: Pick<PageAnalyses, "top">;
  /** A generated password was filled in `tabId` (feeds the save proposal, spec 8.8). */
  onGenerated?: (tabId: number, origin: string, password: string) => void;
  /** The host reported a locked vault (secrets held elsewhere must go too). */
  onLock?: () => void;
  /** The fill plan of the top frame of `tabId` (null: no plan, no context). */
  plan?: (tabId: number, origin: string) => Promise<PlanOut | null>;
  /** Run smart fill in the top frame of `tabId`, as a gesture of the user. */
  smartFill?: (tabId: number) => Promise<void>;
  /** The site memory of `origin`'s site was forgotten (the penalty goes too). */
  onForgetSite?: (origin: string) => Promise<void>;
  now?: () => number;
}

const LOGIN_KINDS: readonly FormKind[] = ["login", "otp", "change_password", "signup"];

/** Fields of a login item disclosed for each form kind (least disclosure). */
export function loginFields(kind: FormKind): FillField[] {
  switch (kind) {
    case "otp":
      return ["totp"];
    case "change_password":
      return ["password"];
    case "signup":
      return ["username"];
    default:
      return ["username", "password"];
  }
}

function pickForm(forms: FormInfo[], kinds: readonly FormKind[]): FormInfo | undefined {
  for (const k of kinds) {
    const f = forms.find((x) => x.kind === k);
    if (f) return f;
  }
  return undefined;
}

/** Plans one click carries out (the line); `show_menu` and `nothing` have none. */
const LINE_ACTIONS: ReadonlySet<PlanOut["action"]> = new Set<PlanOut["action"]>(["fill", "fill_and_submit", "open_chain"]);

/**
 * The plan in one line, or null. `label`: the username (else the title) of
 * the plan's first item as the summaries show it; `steps`: 2 for a sign-in
 * whose page asks for the identifier alone (the password comes next), 1
 * otherwise. No value is read.
 */
export function planLine(plan: PlanOut, items: readonly Summary[]): PopupPlanLine | null {
  if (!LINE_ACTIONS.has(plan.action) || plan.intent === "ignore" || plan.groups.length === 0) return null;
  const first = plan.groups.find((g) => g.item_id !== null);
  const s = first ? items.find((x) => x.item_id === first.item_id) : undefined;
  const label = s ? (s.subtitle !== "" ? s.subtitle : s.title) : "";
  const login = plan.groups.find((g) => g.kind === "login");
  const roles = login?.fields.map((f) => f.role) ?? [];
  const identifierOnly = roles.some((r) => r === "username" || r === "email") && !roles.includes("current_password");
  const steps = plan.intent === "login" && identifierOnly ? 2 : 1;
  // The sign-in wording only when one click signs in (a penalty already lowered High to Medium).
  const mode = plan.action === "open_chain" && plan.confidence === "high" ? "chain" : "fill";
  return { intent: plan.intent, label, steps, mode };
}

/**
 * The plan's items best first: the chosen one (its first group with an item),
 * then `alternatives`, which the bridge sends without the chosen one. No
 * duplicate.
 */
export function rankedIds(plan: Pick<PlanOut, "groups" | "alternatives">): string[] {
  const chosen = plan.groups.find((g) => g.item_id !== null)?.item_id;
  const out: string[] = [];
  for (const id of [...(chosen ? [chosen] : []), ...plan.alternatives]) {
    if (!out.includes(id)) out.push(id);
  }
  return out;
}

/** `items` with the plan's alternatives first, in the plan's order. */
export function alternativesFirst<T extends { item_id: string }>(items: readonly T[], alternatives: readonly string[]): T[] {
  const rank = (x: T) => {
    const i = alternatives.indexOf(x.item_id);
    return i < 0 ? alternatives.length : i;
  };
  return items.map((x, i) => ({ x, i })).sort((a, b) => rank(a.x) - rank(b.x) || a.i - b.i).map((e) => e.x);
}

export class PopupBackend {
  /** Summaries shown to the popup, by item id, with the origin they were suggested for. */
  private readonly known = new Map<string, PopupItem>();
  private readonly now: () => number;

  constructor(private readonly deps: PopupDeps) {
    this.now = deps.now ?? Date.now;
    // The history an older version kept in `storage.session` is removed once.
    void Promise.resolve(deps.area.remove(HISTORY_KEY)).catch(() => undefined);
    deps.session.onLocked(() => {
      this.known.clear();
      this.clearHistory();
    });
  }

  /** The active tab and its HTTPS origin, from the browser. */
  private async activeTab(): Promise<{ tabId: number; origin: string; host: string } | null> {
    const [tab] = await this.deps.ext.tabs.query({ active: true, currentWindow: true });
    if (!tab || typeof tab.id !== "number" || typeof tab.url !== "string") return null;
    const o = parseOrigin(tab.url);
    if (!o?.https) return null;
    return { tabId: tab.id, origin: o.origin, host: o.host };
  }

  private remember(items: Summary[], website?: string): void {
    for (const s of items) {
      const it: PopupItem = { summary: s };
      if (website !== undefined) it.website = website;
      // A search result never erases the site a suggestion was made for.
      const prev = this.known.get(s.item_id);
      if (website === undefined && prev?.website !== undefined) it.website = prev.website;
      this.known.set(s.item_id, it);
    }
  }

  private item(itemId: string): PopupItem {
    const it = this.known.get(itemId);
    if (!it) throw new BgError("not_found");
    return it;
  }

  /** The top frame target of the active tab and its reported forms. */
  private async target(kinds: readonly FormKind[]): Promise<{ t: FillTarget; host: string; kind: FormKind }> {
    const tab = await this.activeTab();
    if (!tab) throw new BgError("insecure_origin");
    const top = await this.deps.analyses.top(tab.tabId);
    // The analysis must be of the page the browser shows now.
    if (!top || top.origin !== tab.origin) throw new BgError("no_form");
    const form = pickForm(top.analysis.forms, kinds);
    if (!form) throw new BgError("no_form");
    const t: FillTarget = { tabId: tab.tabId, frameId: 0, origin: tab.origin, formRef: form.ref };
    if (top.documentId !== undefined) t.documentId = top.documentId;
    return { t, host: tab.host, kind: form.kind };
  }

  async status() {
    const s = await this.deps.session.request({ op: "status" });
    if (s.locked) {
      this.known.clear();
      this.clearHistory();
      this.deps.onLock?.();
    }
    return s;
  }

  async suggestions(): Promise<PopupSuggestions> {
    const tab = await this.activeTab();
    if (!tab) return { domain: null, items: [] };
    const { items } = await this.deps.session.request({ op: "list_for_origin", ctx: "popup", origin: tab.origin });
    this.remember(items, tab.origin);
    let plan: PlanOut | null = null;
    try {
      plan = (await this.deps.plan?.(tab.tabId, tab.origin)) ?? null;
    } catch {
      // No content script, a locked vault: the suggestions alone.
      plan = null;
    }
    if (!plan) return { domain: tab.host, items };
    const out: PopupSuggestions = { domain: tab.host, items: alternativesFirst(items, rankedIds(plan)) };
    const line = planLine(plan, items);
    if (line) out.plan = line;
    return out;
  }

  /** The plan line's Fill: smart fill in the active tab. */
  async smartFill(): Promise<{ domain: string }> {
    const tab = await this.activeTab();
    if (!tab || !this.deps.smartFill) throw new BgError("insecure_origin");
    await this.deps.smartFill(tab.tabId);
    return { domain: tab.host };
  }

  /** "Oublier mes choix sur ce site": the bridge reduces the tab's origin to its site. */
  async forgetSite(): Promise<{ domain: string; items: number }> {
    const tab = await this.activeTab();
    if (!tab) throw new BgError("insecure_origin");
    const r = await this.deps.session.request({ op: "forget_site", ctx: "popup", site: tab.origin });
    await this.deps.onForgetSite?.(tab.origin).catch(() => undefined);
    return { domain: tab.host, items: r.items };
  }

  async search(query: string): Promise<{ items: Summary[] }> {
    if (query.trim() === "") return { items: [] };
    const { items } = await this.deps.session.request({ op: "search", ctx: "popup", query });
    this.remember(items);
    return { items };
  }

  async getItem(itemId: string): Promise<PopupItem> {
    return this.item(itemId);
  }

  async reveal(itemId: string): Promise<{ value: string }> {
    this.item(itemId);
    return this.deps.session.request({ op: "reveal", ctx: "popup", item_id: itemId, field: "password" });
  }

  async totp(itemId: string): Promise<{ code: string; remaining: number }> {
    this.item(itemId);
    return this.deps.session.request({ op: "totp", ctx: "popup", item_id: itemId });
  }

  async fill(itemId: string): Promise<{ domain: string }> {
    const { summary } = this.item(itemId);
    if (summary.kind === "card") {
      const { t, host } = await this.target(["card"]);
      await this.deps.filler.fillCard(t, itemId, "popup");
      return { domain: host };
    }
    if (summary.kind === "identity") {
      const { t, host } = await this.target(["identity", "address"]);
      await this.deps.filler.fillIdentity(t, itemId, "popup");
      return { domain: host };
    }
    const { t, host, kind } = await this.target(LOGIN_KINDS);
    await this.deps.filler.fillLogin(t, itemId, loginFields(kind), "popup");
    return { domain: host };
  }

  async fillGenerated(password: string): Promise<{ domain: string }> {
    const { t, host } = await this.target(["signup", "change_password"]);
    await this.deps.filler.fillGenerated(t, password);
    this.deps.onGenerated?.(t.tabId, t.origin, password);
    return { domain: host };
  }

  async generate(kind: GeneratorEntry["kind"], length?: number, symbols?: boolean) {
    const recipe: { kind: GeneratorEntry["kind"]; length?: number; symbols?: boolean } = { kind };
    if (length !== undefined) recipe.length = length;
    if (symbols !== undefined) recipe.symbols = symbols;
    const g = await this.deps.session.request({ op: "generate", ctx: "popup", recipe });
    historyEntries.unshift({ password: g.password, kind, at: this.now() });
    historyEntries.length = Math.min(historyEntries.length, HISTORY_MAX);
    return g;
  }

  async history(): Promise<{ entries: GeneratorEntry[] }> {
    return { entries: historyEntries.map((e) => ({ ...e })) };
  }

  clearHistory(): void {
    historyEntries = [];
  }

  /** "Oublier cet appairage" (spec 6.4): drops the record and everything the popup was shown. */
  async forget(): Promise<Record<string, never>> {
    await this.deps.pairing.forgetPairing();
    this.known.clear();
    this.clearHistory();
    return {};
  }

  handlers(): Handlers["ui"] {
    return {
      popup_status: async () => this.status(),
      popup_unlock: async () => this.deps.session.request({ op: "unlock" }),
      popup_suggestions: async () => this.suggestions(),
      popup_search: async (m) => this.search(m.query),
      popup_item: async (m) => this.getItem(m.itemId),
      popup_reveal: async (m) => this.reveal(m.itemId),
      popup_totp: async (m) => this.totp(m.itemId),
      popup_fill: async (m) => this.fill(m.itemId),
      popup_fill_generated: async (m) => this.fillGenerated(m.password),
      popup_generate: async (m) => this.generate(m.kind, m.length, m.symbols),
      popup_history: async () => this.history(),
      popup_pair_start: async () => this.deps.pairing.startPairing(),
      popup_pair_approve: async () => {
        await this.deps.pairing.confirmPairing();
        return {};
      },
      popup_pair_cancel: async () => {
        this.deps.pairing.cancelPairing();
        return {};
      },
      popup_forget: async () => this.forget(),
      popup_smart_fill: async () => this.smartFill(),
      popup_forget_site: async () => this.forgetSite(),
    };
  }
}
