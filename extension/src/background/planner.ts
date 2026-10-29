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
import type { FillField } from "../bridge/client";
import type { FieldRole, FillAction, PageContext, PageFrameKind, PlanGroupOut, PlanOut } from "../shared/messages";
import type { SaveFlow } from "./chain/save-flow";
import type { ChainDriver } from "./chain/types";
import type { FillTarget, Filler } from "./fill";
import type { CsContext } from "./frames";
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

const SUBMITTING: ReadonlySet<FillAction> = new Set<FillAction>(["open_chain", "fill_and_submit"]);

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
    const { plan } = await this.session.request({ op: "plan_fill", ctx: "menu", origin: t.origin, context });
    this.made.set(plan, { context, tabId: t.tabId, frameId: t.frameId, origin: t.origin, documentId: t.documentId });
    return plan;
  }

  /** Carry out `plan` in the frame of `t`. */
  async run(t: FillTarget, plan: PlanOut): Promise<RunOutcome> {
    // A plan made for another tab, frame, origin or document: the menu instead.
    const made = this.made.get(plan);
    if (
      made &&
      (made.tabId !== t.tabId || made.frameId !== t.frameId || made.origin !== t.origin || made.documentId !== t.documentId)
    ) {
      return "menu";
    }
    const action = this.guarded(t, plan);
    switch (action) {
      case "nothing":
        return "nothing";
      case "show_menu":
        return "menu";
      case "open_chain": {
        const login = plan.groups.find((g) => g.kind === "login" && g.item_id !== null);
        if (!login?.item_id) return "menu";
        await this.chain.start(t.tabId, login.item_id, undefined, {});
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
            }
            if (written === 0) complete = false;
          }
        } finally {
          generated = undefined;
        }
        if (action === "fill_and_submit" && complete && (plan.intent !== "otp" || otpWritten)) {
          const last = plan.groups[plan.groups.length - 1] as PlanGroupOut;
          await this.filler.submit({ ...t, formRef: last.form_ref });
        }
        return "filled";
      }
    }
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
  private guarded(t: FillTarget, plan: PlanOut): FillAction {
    if (!SUBMITTING.has(plan.action)) return plan.action;
    if (plan.intent !== "login" && plan.intent !== "otp") return "fill";
    if (plan.confidence !== "high") return "fill";
    if (t.frameId !== 0) return "fill";
    if (plan.reasons.includes("pay_button") || plan.reasons.includes("create_button")) return "fill";
    const planned = new Set(plan.groups.map((g) => g.form_ref));
    if (planned.size > 1) return "fill";
    const ctx = this.made.get(plan)?.context;
    if (!ctx) return "fill";
    for (const f of ctx.forms) {
      if (planned.has(f.form_ref) && f.buttons.some((b) => b.class === "pay" || b.class === "create")) return "fill";
    }
    return plan.action;
  }
}
