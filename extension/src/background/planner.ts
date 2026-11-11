// Smart fill in the background: ask the bridge for a plan of the page
// (`plan_fill`, onepass_core::fill_plan), then carry it out through the
// existing fill path. The plan holds item ids, roles and refs only; values
// come from `fill_*` (which verify the frame before and after the host) and
// go straight to the content script. Nothing here logs, stores or throws a
// value.
//
// The engine already refuses auto-submit outside a single-form sign-in, a
// one-time code without site memory, and on signup, checkout or payment.
// The same rules are replayed here before any action (defense in depth):
// `OpenChain` and `FillAndSubmit` fall back to `Fill` unless the intent is
// `login` or `otp`, the frame is the top frame or a child of exactly its
// origin, and no planned form has a pay or create button.
//
// One sign-in path: a plan that may submit (`OpenChain` or `FillAndSubmit`
// after every guard) starts the sign-in chain, the same one the overlay's
// account and a menu row start. The planner itself never submits a form:
// its own fills (`Fill`) write and stop.
//
// Task 10 adds: the site penalty (a site whose last chain ended in `repeat`
// gets `Medium` instead of `High`, penalty.ts), the gesture's form scoping
// (an icon click runs only its form's groups), the anchor of the chain's
// progress, and the report of a fill for the site memory (notes.ts).
//
// Site-aware generator, Task 10: a generated password filled on a signup or
// reset page is saved as a pending Login (save-flow.ts) before the run
// answers; a locked vault or a refusal never blocks the fill.
import type { FillField } from "../bridge/client";
import type { FieldRole, FillAction, PageContext, PageFrameKind, PlanGroupOut, PlanOut, SignupMode } from "../shared/messages";
import { isDocumentRole } from "../shared/messages";
import type { SaveFlow } from "./chain/save-flow";
import type { ChainDriver, StartOptions } from "./chain/types";
import type { FillTarget, Filler } from "./fill";
import type { FormGenerator } from "./generate";
import type { CsContext } from "./frames";
import type { FilledNote } from "./notes";
import { penalized } from "./penalty";
import { BgError, type Session, toBgError } from "./session";

/** What a run did: values written, a chain started, the menu to open instead, or nothing. */
export type RunOutcome = "filled" | "chain" | "menu" | "nothing";

/**
 * The context of what a plan writes by itself (a gesture on the icon, the popup's Fill or the
 * command; the plan chose the item, the user clicked no row). Never "menu" nor "popup": the
 * bridge reads those as the user's pick of that very item and serves an associated-domain login
 * on them. The bridge has no value of its own for a plan's fill yet: "chain" is the accepted one
 * it reads as "follows a gesture, picks nothing".
 */
export const PLAN_FILL_CTX = "chain" as const;

/** The background's origins of a frame, as a `PageContext` carries them. */
export interface PlanOrigins {
  origin: string;
  top_origin: string;
  frame_kind: PageFrameKind;
}

/**
 * Origins of the sending frame for `plan_fill`, from what the browser
 * reported (`sender`, see `contentSender`) and the top frame's origin as the
 * browser reports it now. A child frame gets a plan only at exactly the top
 * frame's origin (the bridge refuses anything else); a cross-origin child,
 * or an unknown top, gets none: null, the caller falls back to the menu.
 */
export function framesFromSender(from: Pick<CsContext, "frameId" | "origin">, topOrigin: string | null): PlanOrigins | null {
  if (from.frameId === 0) return { origin: from.origin, top_origin: from.origin, frame_kind: "top" };
  if (topOrigin === null || topOrigin !== from.origin) return null;
  return { origin: from.origin, top_origin: topOrigin, frame_kind: "same_origin_child" };
}

/** What `fill_login` fetches for a login group's roles, in a stable order. */
export function loginFieldsFor(roles: readonly FieldRole[]): FillField[] {
  const out: FillField[] = [];
  if (roles.includes("username") || roles.includes("email")) out.push("username");
  if (roles.includes("current_password")) out.push("password");
  if (roles.includes("otp")) out.push("totp");
  return out;
}

/**
 * Roles of the plan's main form (the form of its first group): its visible
 * fields with a role, in page order. What `note_fill` reports, the list the
 * bridge hashes into `form_shape_hash` (`main_roles` in onepass-bridge).
 */
export function mainRoles(ctx: Pick<PageContext, "forms">, groups: readonly PlanGroupOut[]): FieldRole[] {
  const ref = groups[0]?.form_ref;
  const form = ref === undefined ? undefined : ctx.forms.find((f) => f.form_ref === ref);
  if (!form) return [];
  return form.fields.filter((f) => f.visible && f.role !== null).map((f) => f.role as FieldRole);
}

export interface PlannerHooks {
  /** The site of `origin` lost a level of confidence (penalty.ts). */
  penalized?: (origin: string) => Promise<boolean>;
  /** A run wrote values without a chain and without a submit (for the site memory, notes.ts). */
  onFilled?: (t: FillTarget, note: FilledNote) => void | Promise<void>;
  /** The page's `pattern` refused every generated password: the run answers "menu" (spec 6.3). */
  onGenerateRefused?: (t: FillTarget) => void;
  /** Before each `plan_fill`: the session's browser profile for the ranking (history.ts). Never throws. */
  beforePlan?: () => Promise<void>;
}

export interface RunOptions {
  /** The form of the gesture (icon click): only its groups run; none left, the menu. */
  form?: string;
  /** The field of the gesture: the chain's progress shows under it (top frame). */
  anchorRef?: string;
}

const SUBMITTING: ReadonlySet<FillAction> = new Set<FillAction>(["open_chain", "fill_and_submit"]);
/** Refusals of `ChainDriver.start` that leave the plain fill: a page the chain does not run on, an item it is not given there. */
const NO_CHAIN: ReadonlySet<string> = new Set(["insecure_origin", "not_found"]);
/** Actions whose groups a gesture's form narrows. */
const SCOPED: ReadonlySet<FillAction> = new Set<FillAction>(["open_chain", "fill_and_submit", "fill"]);

/** What a plan was made for: its page, and the frame and document it may run in. */
interface Made {
  context: PageContext;
  tabId: number;
  frameId: number;
  origin: string;
  documentId: string | undefined;
}

export class Planner {
  /** Per plan, what it was made for (its forms' buttons, its target). */
  private readonly made = new WeakMap<PlanOut, Made>();

  constructor(
    private readonly session: Pick<Session, "request">,
    private readonly filler: Pick<Filler, "fillLogin" | "fillCard" | "fillIdentity" | "fillGenerated">,
    private readonly chain: Pick<ChainDriver, "start">,
    private readonly saveFlow: Pick<SaveFlow, "rememberGenerated" | "savePending">,
    private readonly generator: Pick<FormGenerator, "generateForForm">,
    private readonly hooks: PlannerHooks = {},
  ) {}

  /**
   * The bridge's plan for `ctx` in the frame of `t`. The origins and frame
   * kind of `ctx` are replaced by the ones of `t` (the browser's), whatever
   * the content script put there. A child frame must be flagged
   * `sameOriginAsTop` (see `framesFromSender`).
   */
  async plan(t: FillTarget, ctx: PageContext, from: "menu" | "popup" | "overlay" | "chain" = "menu"): Promise<PlanOut> {
    let frame: PageFrameKind;
    if (t.frameId === 0) frame = "top";
    else if (t.sameOriginAsTop) frame = "same_origin_child";
    else throw new BgError("cross_site_frame");
    // A same-origin child's top is at its very origin.
    const context: PageContext = { ...ctx, origin: t.origin, top_origin: t.origin, frame_kind: frame };
    await this.hooks.beforePlan?.();
    // `from`: where the plan is asked from (the in-page gesture, the popup, the card, a running chain).
    const reply = await this.session.request({ op: "plan_fill", ctx: from, origin: t.origin, context });
    // A refused password on this site: no auto-submit, no chain, until a chain gets through.
    const plan = (await this.isPenalized(t.origin)) ? penalized(reply.plan) : reply.plan;
    this.made.set(plan, { context, tabId: t.tabId, frameId: t.frameId, origin: t.origin, documentId: t.documentId });
    return plan;
  }

  private async isPenalized(origin: string): Promise<boolean> {
    try {
      return (await this.hooks.penalized?.(origin)) === true;
    } catch {
      // Storage unreadable: assume the worst (no auto-submit).
      return true;
    }
  }

  /** The plan's context (its page), when this planner made it. */
  contextOf(plan: PlanOut): PageContext | undefined {
    return this.made.get(plan)?.context;
  }

  /**
   * Carry out `plan` in the frame of `t`. With `opts.form` (an icon click),
   * only the groups of that form run; when it has none, the menu.
   */
  async run(t: FillTarget, full: PlanOut, opts: RunOptions = {}): Promise<RunOutcome> {
    // A plan made for another tab, frame, origin or document: the menu instead.
    const made = this.made.get(full);
    if (
      made &&
      (made.tabId !== t.tabId || made.frameId !== t.frameId || made.origin !== t.origin || made.documentId !== t.documentId)
    ) {
      return "menu";
    }
    // One-click signup: a form that can make a passkey asks first (password or passkey,
    // `runSignup`): the two paths exclude each other (spec 2.3).
    if (full.intent === "signup" && full.action === "fill" && full.passkey && (opts.form === undefined || full.passkey.form_ref === opts.form)) {
      return "menu";
    }
    let plan = full;
    if (opts.form !== undefined && SCOPED.has(full.action)) {
      const groups = full.groups.filter((g) => g.form_ref === opts.form);
      if (groups.length === 0) return "menu";
      plan = { ...full, groups };
    }
    const action = this.guarded(t, plan, made?.context);
    switch (action) {
      case "nothing":
        return "nothing";
      case "show_menu":
        return "menu";
      case "open_chain":
      case "fill_and_submit": {
        // The one sign-in path, whichever of the two the engine named: the chain.
        const start = this.signInOf(t, plan, made, opts.anchorRef);
        if (!start) {
          if (action === "open_chain") return "menu";
          return this.fill(t, plan, made);
        }
        try {
          await this.chain.start(t.tabId, start.itemId, undefined, start.options);
          return "chain";
        } catch (e) {
          const code = toBgError(e).code;
          // A login without a password signs in through a provider: its e-mail is never written
          // into the site's own form (the user would send it, to no account). The menu, where its
          // provider row is; the caller starts that provider's chain when the page shows its button.
          if (code === "invalid") return "menu";
          if (!NO_CHAIN.has(code)) throw e;
          // No chain on this page: this form is filled, nothing is sent.
          return this.fill(t, plan, made);
        }
      }
      case "fill":
        return this.fill(t, plan, made);
    }
  }

  /**
   * The sign-in a plan decides in the frame of `t`: the login item the chain signs in with and how
   * it starts, when the plan may submit there (every guard passed); null otherwise. The one
   * decision behind the field icon, the command, the toolbar's Fill, a resume after an unlock and
   * the overlay's first account.
   */
  signIn(t: FillTarget, plan: PlanOut, anchorRef?: string): { itemId: string; options: StartOptions } | null {
    return this.signInOf(t, plan, this.made.get(plan), anchorRef);
  }

  private signInOf(t: FillTarget, plan: PlanOut, made: Made | undefined, anchorRef?: string): { itemId: string; options: StartOptions } | null {
    if (!SUBMITTING.has(this.guarded(t, plan, made?.context))) return null;
    const login = plan.groups.find((g) => g.kind === "login" && g.item_id !== null);
    if (!login?.item_id) return null;
    const options: StartOptions = { planned: { roles: made ? mainRoles(made.context, plan.groups) : [], intent: plan.intent } };
    if (anchorRef !== undefined && t.frameId === 0) options.anchorRef = anchorRef;
    return { itemId: login.item_id, options };
  }

  /** `Fill`: every group's values written, nothing sent. */
  private async fill(t: FillTarget, plan: PlanOut, made: Made | undefined): Promise<RunOutcome> {
    if (plan.groups.length === 0) return "nothing";
    let generated: string | undefined;
    let weak = false;
    // One new password per run, made for the first generated group's form before anything
    // is written: a page that refuses it gets the menu, not a half-filled form.
    const firstGenerated = plan.groups.find((g) => g.kind === "generated_password");
    if (firstGenerated) {
      const g = await this.generator.generateForForm({ ...t, formRef: firstGenerated.form_ref }, PLAN_FILL_CTX);
      if (g === null) {
        this.hooks.onGenerateRefused?.(t);
        return "menu";
      }
      generated = g.password;
      weak = g.report?.weak_by_site === true;
    }
    let remembered = false;
    /** Signup: the e-mail the identity group wrote in an identifier field, the pending Login's username. */
    let identifier: string | undefined;
    const items: string[] = [];
    let wrote = false;
    try {
      for (const g of plan.groups) {
        const gt: FillTarget = { ...t, formRef: g.form_ref };
        const roles = g.fields.map((f) => f.role);
        let written = 0;
        if (g.kind === "generated_password" && generated !== undefined) {
          // Every generated group gets the same password.
          written = await this.filler.fillGenerated(gt, generated, roles);
          // In the page now: the save prompt must know it, whatever happens next.
          if (written > 0 && !remembered) {
            this.saveFlow.rememberGenerated(t.tabId, t.origin, generated);
            remembered = true;
            // In the vault before the form is sent (spec 7.1): a lock or a closed tab loses nothing.
            // Signup only: a reset keeps the save prompt, which updates the existing Login.
            if (plan.intent === "signup") {
              await this.saveFlow.savePending(t.tabId, t.origin, generated, identifier === undefined ? { weak } : { weak, username: identifier });
            }
          }
        } else if (g.item_id !== null) {
          // Identity groups come before the generated one (onepass_core compose): the e-mail is known in time.
          const onIdentifier =
            plan.intent === "signup" && g.kind === "identity" && roles.some((r) => r === "email" || r === "username")
              ? (email: string) => {
                  identifier ??= email;
                }
              : undefined;
          written = await this.fillGroup(gt, g, g.item_id, roles, onIdentifier);
          if (written > 0 && !items.includes(g.item_id)) items.push(g.item_id);
        }
        if (written > 0) wrote = true;
      }
    } finally {
      generated = undefined;
      identifier = undefined;
    }
    // Ruling: memory after a fill without submit (then a navigation or a save); a chain notes its
    // own at done. A generated password alone counts (its save is noted).
    if (wrote && made) {
      try {
        await this.hooks.onFilled?.(t, { items, roles: mainRoles(made.context, plan.groups), intent: plan.intent, ctx: PLAN_FILL_CTX });
      } catch {
        // The memory is a hint: the fill stands.
      }
    }
    return "filled";
  }

  /**
   * The user's choice in the menu a passkey-offering signup plan opened:
   * `password` runs the plan's groups of the offer's form (identity,
   * generated password, pending Login), `passkey` only its identity groups
   * (no password made, nothing saved: the site's passkey button follows).
   * Never a submit. Not a signup plan with an offer: the menu.
   */
  async runSignup(t: FillTarget, plan: PlanOut, mode: SignupMode): Promise<RunOutcome> {
    const offer = plan.passkey;
    if (plan.intent !== "signup" || !offer) return "menu";
    const groups = plan.groups.filter((g) => g.form_ref === offer.form_ref && (mode === "password" || g.kind === "identity"));
    const chosen: PlanOut = { ...plan, groups, action: "fill", passkey: null };
    const made = this.made.get(plan);
    if (made) this.made.set(chosen, made);
    return this.run(t, chosen);
  }

  /** `plan` may submit in the frame of `t` (`OpenChain` or `FillAndSubmit` after every guard): its sign-in goes to the chain. */
  submits(t: FillTarget, plan: PlanOut): boolean {
    return SUBMITTING.has(this.guarded(t, plan, this.made.get(plan)?.context));
  }

  /** Roles written for a group with an item (0 when none had a value). */
  private async fillGroup(
    t: FillTarget,
    g: PlanGroupOut,
    itemId: string,
    roles: FieldRole[],
    onIdentifier?: (email: string) => void,
  ): Promise<number> {
    switch (g.kind) {
      case "login": {
        const fields = loginFieldsFor(roles);
        return fields.length > 0 ? this.filler.fillLogin(t, itemId, fields, PLAN_FILL_CTX, roles) : 0;
      }
      case "card":
        return this.filler.fillCard(t, itemId, PLAN_FILL_CTX, roles);
      case "identity":
        return onIdentifier ? this.filler.fillIdentity(t, itemId, PLAN_FILL_CTX, roles, onIdentifier) : this.filler.fillIdentity(t, itemId, PLAN_FILL_CTX, roles);
      case "generated_password":
        return 0;
    }
  }

  /**
   * The plan's action after the submit rules: `OpenChain` and
   * `FillAndSubmit` become `Fill` outside a sign-in or code, in a child
   * frame that is not of exactly the top frame's origin, next to a pay or
   * create button, or for a plan this planner did not make (its page is
   * unknown), or for a plan holding a document role. An item offered through
   * Apple's shared-credentials list and never used on this site
   * (`associated_domain`) is shown, never written: the menu.
   */
  private guarded(t: FillTarget, plan: PlanOut, ctx: PageContext | undefined): FillAction {
    if (plan.action !== "nothing" && plan.reasons.includes("associated_domain")) return "show_menu";
    if (!SUBMITTING.has(plan.action)) return plan.action;
    // A document number is filled on a user action only, never submitted (card rule).
    if (plan.groups.some((g) => g.fields.some((f) => isDocumentRole(f.role)))) return "fill";
    if (plan.intent !== "login" && plan.intent !== "otp") return "fill";
    if (plan.confidence !== "high") return "fill";
    // A child frame whose origin equals the top frame's is decided like the top frame (the bridge does the same).
    if (t.frameId !== 0 && t.sameOriginAsTop !== true) return "fill";
    if (plan.reasons.includes("pay_button") || plan.reasons.includes("create_button")) return "fill";
    const planned = new Set(plan.groups.map((g) => g.form_ref));
    if (planned.size > 1) return "fill";
    if (!ctx) return "fill";
    for (const f of ctx.forms) {
      if (planned.has(f.form_ref) && f.buttons.some((b) => b.class === "pay" || b.class === "create")) return "fill";
    }
    return plan.action;
  }
}
