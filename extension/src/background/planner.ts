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
// `login` or `otp`, the frame is the top frame and no planned form has a
// pay or create button.
//
// Task 10 adds: the site penalty (a site whose last chain ended in `repeat`
// gets `Medium` instead of `High`, penalty.ts), the gesture's form scoping
// (an icon click runs only its form's groups), the anchor of the chain's
// progress, and the report of a fill for the site memory (notes.ts).
import type { FillField } from "../bridge/client";
import type { FieldRole, FillAction, PageContext, PageFrameKind, PlanGroupOut, PlanOut } from "../shared/messages";
import type { SaveFlow } from "./chain/save-flow";
import type { ChainDriver, StartOptions } from "./chain/types";
import type { FillTarget, Filler } from "./fill";
import type { CsContext } from "./frames";
import type { FilledNote } from "./notes";
import { penalized } from "./penalty";
import { BgError, type Session } from "./session";

/** What a run did: values written, a chain started, the menu to open instead, or nothing. */
export type RunOutcome = "filled" | "chain" | "menu" | "nothing";

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
}

export interface RunOptions {
  /** The form of the gesture (icon click): only its groups run; none left, the menu. */
  form?: string;
  /** The field of the gesture: the chain's progress shows under it (top frame). */
  anchorRef?: string;
}

const SUBMITTING: ReadonlySet<FillAction> = new Set<FillAction>(["open_chain", "fill_and_submit"]);
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
    private readonly filler: Pick<Filler, "fillLogin" | "fillCard" | "fillIdentity" | "fillGenerated" | "submit">,
    private readonly chain: Pick<ChainDriver, "start">,
    private readonly saveFlow: Pick<SaveFlow, "rememberGenerated">,
    private readonly hooks: PlannerHooks = {},
  ) {}

  /**
   * The bridge's plan for `ctx` in the frame of `t`. The origins and frame
   * kind of `ctx` are replaced by the ones of `t` (the browser's), whatever
   * the content script put there. A child frame must be flagged
   * `sameOriginAsTop` (see `framesFromSender`).
   */
  async plan(t: FillTarget, ctx: PageContext): Promise<PlanOut> {
    let frame: PageFrameKind;
    if (t.frameId === 0) frame = "top";
    else if (t.sameOriginAsTop) frame = "same_origin_child";
    else throw new BgError("cross_site_frame");
    // A same-origin child's top is at its very origin.
    const context: PageContext = { ...ctx, origin: t.origin, top_origin: t.origin, frame_kind: frame };
    const reply = await this.session.request({ op: "plan_fill", ctx: "menu", origin: t.origin, context });
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
      case "open_chain": {
        const login = plan.groups.find((g) => g.kind === "login" && g.item_id !== null);
        if (!login?.item_id) return "menu";
        const start: StartOptions = { planned: { roles: made ? mainRoles(made.context, plan.groups) : [], intent: plan.intent } };
        if (opts.anchorRef !== undefined && t.frameId === 0) start.anchorRef = opts.anchorRef;
        await this.chain.start(t.tabId, login.item_id, undefined, start);
        return "chain";
      }
      case "fill":
      case "fill_and_submit": {
        if (plan.groups.length === 0) return "nothing";
        let generated: string | undefined;
        let remembered = false;
        /** Every group wrote at least one value, and the code went in when it is a code. */
        let complete = true;
        let otpWritten = false;
        const items: string[] = [];
        let wrote = false;
        try {
          for (const g of plan.groups) {
            const gt: FillTarget = { ...t, formRef: g.form_ref };
            const roles = g.fields.map((f) => f.role);
            let written = 0;
            if (g.kind === "generated_password") {
              // One new password per run: every generated group gets the same.
              generated ??= (await this.session.request({ op: "generate", ctx: "menu", recipe: { kind: "smart" } })).password;
              written = await this.filler.fillGenerated(gt, generated, roles);
              // In the page now: the save prompt must know it, whatever happens next.
              if (written > 0 && !remembered) {
                this.saveFlow.rememberGenerated(t.tabId, t.origin, generated);
                remembered = true;
              }
            } else if (g.item_id !== null) {
              written = await this.fillGroup(gt, g, g.item_id, roles);
              // The count is of distinct roles: all of them written means the code was too.
              if (g.kind === "login" && roles.includes("otp") && written === new Set(roles).size) otpWritten = true;
              if (written > 0 && !items.includes(g.item_id)) items.push(g.item_id);
            }
            if (written === 0) complete = false;
            else wrote = true;
          }
        } finally {
          generated = undefined;
        }
        let submitted = false;
        if (action === "fill_and_submit" && complete && (plan.intent !== "otp" || otpWritten)) {
          const last = plan.groups[plan.groups.length - 1] as PlanGroupOut;
          await this.filler.submit({ ...t, formRef: last.form_ref });
          submitted = true;
        }
        // Ruling: memory only after a fill without submit (then a navigation or a save), never
        // after the plan's own submit. A generated password alone counts (its save is noted).
        if (wrote && made && !submitted) {
          try {
            await this.hooks.onFilled?.(t, { items, roles: mainRoles(made.context, plan.groups), intent: plan.intent });
          } catch {
            // The memory is a hint: the fill stands.
          }
        }
        return "filled";
      }
    }
  }

  /** `plan` may submit in the frame of `t` (`OpenChain` or `FillAndSubmit` after every guard). */
  submits(t: FillTarget, plan: PlanOut): boolean {
    return SUBMITTING.has(this.guarded(t, plan, this.made.get(plan)?.context));
  }

  /** Roles written for a group with an item (0 when none had a value). */
  private async fillGroup(t: FillTarget, g: PlanGroupOut, itemId: string, roles: FieldRole[]): Promise<number> {
    switch (g.kind) {
      case "login": {
        const fields = loginFieldsFor(roles);
        return fields.length > 0 ? this.filler.fillLogin(t, itemId, fields, "menu", roles) : 0;
      }
      case "card":
        return this.filler.fillCard(t, itemId, "menu", roles);
      case "identity":
        return this.filler.fillIdentity(t, itemId, "menu", roles);
      case "generated_password":
        return 0;
    }
  }

  /**
   * The plan's action after the submit rules: `OpenChain` and
   * `FillAndSubmit` become `Fill` outside a sign-in or code, in a child
   * frame, next to a pay or create button, or for a plan this planner did
   * not make (its page is unknown).
   */
  private guarded(t: FillTarget, plan: PlanOut, ctx: PageContext | undefined): FillAction {
    if (!SUBMITTING.has(plan.action)) return plan.action;
    if (plan.intent !== "login" && plan.intent !== "otp") return "fill";
    if (plan.confidence !== "high") return "fill";
    if (t.frameId !== 0) return "fill";
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
