// The single fill path (spec 8.4): verify the target frame, ask the host
// (which redoes the origin match), verify again, then hand the values to the
// content script of that exact frame. Values are not kept anywhere.
import type { Ctx, FillField, LoginFill } from "../bridge/client";
import type { BgToCs, FieldRole, ProviderId } from "../shared/messages";
import type { BgExt } from "./ext";
import type { Frames } from "./frames";
import { BgError, type Session } from "./session";

export interface FillTarget {
  tabId: number;
  frameId: number;
  /** Origin bound when the gesture started (from `sender`). */
  origin: string;
  documentId?: string;
  formRef: string;
  /** A child frame must have exactly the top frame's origin (the chain, spec C1). */
  sameOriginAsTop?: boolean;
}

export type FillValues = Partial<Record<FieldRole, string>>;

function put(values: FillValues, role: FieldRole, v: string | undefined): void {
  if (typeof v === "string" && v !== "") values[role] = v;
}

/**
 * Only the values of `roles` (a planned group's roles: the fields the plan
 * fills, never one the user typed in). Every value when `roles` is absent.
 */
function only(values: FillValues, roles: readonly FieldRole[] | undefined): FillValues {
  if (roles === undefined) return values;
  const out: FillValues = {};
  for (const r of roles) if (Object.hasOwn(values, r)) out[r] = values[r];
  return out;
}

function loginValues(r: LoginFill): FillValues {
  const values: FillValues = {};
  put(values, "username", r.username);
  put(values, "email", r.username);
  put(values, "current_password", r.password);
  put(values, "otp", r.totp);
  return values;
}

export class Filler {
  constructor(
    private readonly tabs: Pick<BgExt["tabs"], "sendMessage">,
    private readonly frames: Pick<Frames, "checkFillTarget">,
    private readonly session: Pick<Session, "request">,
  ) {}

  private async verify(t: FillTarget): Promise<void> {
    const c = await this.frames.checkFillTarget(t.tabId, t.frameId, t.origin, t.documentId, t.sameOriginAsTop ? "same_origin" : "same_site");
    if (!c.ok) throw new BgError(c.code);
  }

  /** Sends the values; resolves with how many roles had one (0: nothing sent). */
  private async deliver(t: FillTarget, all: FillValues, roles?: readonly FieldRole[]): Promise<number> {
    const values = only(all, roles);
    const written = Object.keys(values).length;
    // A planned group whose roles got no value: nothing to write.
    if (roles !== undefined && written === 0) return 0;
    // The host may have taken seconds (Touch ID): the page could have moved.
    await this.verify(t);
    const msg: BgToCs = { type: "fill", origin: t.origin, formRef: t.formRef, values };
    // documentId pins the exact document; frameId alone where unsupported.
    const opts = t.documentId !== undefined ? { documentId: t.documentId } : { frameId: t.frameId };
    await this.tabs.sendMessage(t.tabId, msg, opts);
    return written;
  }

  /**
   * `roles`: a planned group's roles, the only ones written (likewise below).
   * Each fill resolves with the roles it sent a value for.
   */
  async fillLogin(t: FillTarget, itemId: string, fields: FillField[], ctx: Ctx = "menu", roles?: readonly FieldRole[]): Promise<number> {
    await this.verify(t);
    const r = await this.session.request({ op: "fill_login", ctx, item_id: itemId, origin: t.origin, fields });
    return this.deliver(t, loginValues(r), roles);
  }

  /**
   * The provider account's own credentials, on an official host of that
   * provider (the host checks `provider_origin` and the account), during a
   * sign-in chain to `siteOrigin`.
   */
  async fillProvider(
    t: FillTarget,
    accountItemId: string,
    provider: ProviderId,
    siteOrigin: string,
    fields: FillField[],
  ): Promise<void> {
    await this.verify(t);
    const r = await this.session.request({
      op: "fill_provider",
      ctx: "chain",
      account_item_id: accountItemId,
      provider,
      provider_origin: t.origin,
      site_origin: siteOrigin,
      fields,
    });
    await this.deliver(t, loginValues(r));
  }

  async fillCard(t: FillTarget, itemId: string, ctx: Ctx = "menu", roles?: readonly FieldRole[]): Promise<number> {
    await this.verify(t);
    const r = await this.session.request({ op: "fill_card", ctx, item_id: itemId, origin: t.origin });
    const values: FillValues = {};
    put(values, "cc_name", r.cardholder);
    put(values, "cc_number", r.number);
    put(values, "cc_exp_month", r.exp_month);
    put(values, "cc_exp_year", r.exp_year);
    if (r.exp_month !== "" && r.exp_year !== "") put(values, "cc_exp", `${r.exp_month}/${r.exp_year.slice(-2)}`);
    put(values, "cc_csc", r.cvv);
    return this.deliver(t, values, roles);
  }

  /** With `roles`, the identity's e-mail alone can go into a signup or checkout group, also as its `username`. */
  async fillIdentity(t: FillTarget, itemId: string, ctx: Ctx = "menu", roles?: readonly FieldRole[]): Promise<number> {
    await this.verify(t);
    const r = await this.session.request({ op: "fill_identity", ctx, item_id: itemId, origin: t.origin });
    const values: FillValues = {};
    put(values, "given_name", r.given_name);
    put(values, "family_name", r.family_name);
    put(values, "full_name", [r.given_name, r.family_name].filter((x) => x).join(" "));
    put(values, "email", r.email);
    // A signup's identifier field (`username` role) takes the e-mail, only
    // when a plan put it in the identity group.
    if (roles?.includes("username")) put(values, "username", r.email);
    put(values, "tel", r.tel);
    put(values, "organization", r.organization);
    put(values, "bday", r.birthday);
    const a = r.address;
    if (a) {
      put(values, "address_line1", a.line1);
      put(values, "address_line2", a.line2);
      put(values, "city", a.city);
      put(values, "postal_code", a.postal_code);
      put(values, "region", a.region);
      put(values, "country", a.country);
    }
    return this.deliver(t, values, roles);
  }

  /** A freshly generated password into the new and confirm fields. */
  async fillGenerated(t: FillTarget, password: string, roles?: readonly FieldRole[]): Promise<number> {
    const values: FillValues = {};
    put(values, "new_password", password);
    put(values, "confirm_password", password);
    return this.deliver(t, values, roles);
  }

  /**
   * Submit `t.formRef` (a plan's `FillAndSubmit`), after the same frame check
   * as a fill. `planned`: the content script re-checks the button's class at
   * click time and refuses a re-rendered copy of the form.
   */
  async submit(t: FillTarget): Promise<void> {
    await this.verify(t);
    const msg: BgToCs = { type: "submit", origin: t.origin, ref: t.formRef, planned: true };
    const opts = t.documentId !== undefined ? { documentId: t.documentId } : { frameId: t.frameId };
    await this.tabs.sendMessage(t.tabId, msg, opts);
  }
}
