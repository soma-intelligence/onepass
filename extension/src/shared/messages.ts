// Internal runtime messages (spec 4, 8). `ref` values are opaque ids assigned
// by the content script; they are never selectors supplied by the page.

export type ProviderId =
  | "google"
  | "apple"
  | "microsoft"
  | "github"
  | "facebook"
  | "x"
  | "linkedin"
  | "discord"
  | "slack";

export type FieldRole =
  | "username"
  | "email"
  | "current_password"
  | "new_password"
  | "confirm_password"
  | "otp"
  | "cc_name"
  | "cc_number"
  | "cc_exp"
  | "cc_exp_month"
  | "cc_exp_year"
  | "cc_csc"
  | "given_name"
  | "family_name"
  | "full_name"
  | "tel"
  | "organization"
  | "bday"
  | "address_line1"
  | "address_line2"
  | "city"
  | "postal_code"
  | "region"
  | "country"
  | "remember_me"
  | "unknown";

export type FormKind = "login" | "signup" | "change_password" | "otp" | "card" | "identity" | "address";

export interface FieldInfo {
  ref: string;
  role: FieldRole;
  /**
   * Refs of every cell of a split field, in order (spec 8.2: 4 to 8 one-character
   * OTP inputs form one logical field). `ref` is then the first cell.
   */
  parts?: string[];
}

export interface FormInfo {
  ref: string;
  kind: FormKind;
  fields: FieldInfo[];
  submitRef?: string;
}

export interface PageAnalysis {
  url: string;
  forms: FormInfo[];
  captcha: boolean;
  push: boolean;
  providerButtons: { provider: ProviderId; ref: string }[];
  accountChooser: { email: string; ref: string }[];
}

// ---- Smart fill (mirror of onepass_core::fill_plan and onepass_bridge::api) ----
// snake_case on purpose: these objects go to the native bridge as they are.
// No field value ever appears in them (spec: smart fill, privacy), only roles,
// opaque refs, flags and the salted hash of a username the user typed.

/** Most forms, fields per form and buttons per form of a `PageContext` (`MAX_FORMS`, `MAX_FIELDS`, `MAX_BUTTONS` in Rust). */
export const PAGE_CONTEXT_MAX_FORMS = 32;
export const PAGE_CONTEXT_MAX_FIELDS = 64;
export const PAGE_CONTEXT_MAX_BUTTONS = 32;

/** Rust `FrameKind` (named apart from the extension frames above). */
export type PageFrameKind = "top" | "same_origin_child";
/** What the field held when the page was read: nothing, what the user typed, or what OnePass wrote. */
export type Prefilled = "empty" | "typed" | "ours";
export type ButtonClass = "submit" | "next" | "pay" | "create" | "other";

export interface IntentHints {
  /** Rust `FormKindHint`: the same seven values as `FormKind`. */
  kind: FormKind | null;
  signup_words: boolean;
  reset_words: boolean;
  checkout_words: boolean;
  ignore: boolean;
}

export interface FieldContext {
  field_ref: string;
  role: FieldRole | null;
  /** 0..1, finite. */
  confidence: number;
  visible: boolean;
  prefilled: Prefilled;
}

export interface ButtonContext {
  button_ref: string;
  class: ButtonClass;
}

export interface FormContext {
  form_ref: string;
  intent_hints: IntentHints;
  step_index: number | null;
  fields: FieldContext[];
  buttons: ButtonContext[];
}

/**
 * What a page looks like to the planner. `origin`, `top_origin` and
 * `frame_kind` are owned by the background: it derives them from the message
 * `sender` (never from the content script) before sending `plan_fill`.
 */
export interface PageContext {
  origin: string;
  top_origin: string;
  frame_kind: PageFrameKind;
  forms: FormContext[];
  /** Salted hash of a username the user typed on this page: 32 numbers 0..255 (serde's `[u8; 32]`), never the text. */
  typed_username_hash: number[] | null;
}

/** Rust `Intent`. */
export type FillIntent = "login" | "signup" | "reset" | "otp" | "checkout" | "address" | "ignore";
/** Rust `Action`. */
export type FillAction = "fill" | "fill_and_submit" | "open_chain" | "show_menu" | "nothing";
/** Rust `Confidence`. */
export type PlanConfidence = "low" | "medium" | "high";
/** Rust `GroupKind`. */
export type PlanGroupKind = "login" | "card" | "identity" | "generated_password";
/** Rust `ReasonCode`. */
export type PlanReason =
  | "single_candidate"
  | "last_on_site"
  | "same_shape"
  | "typed_username"
  | "tie"
  | "weak_roles"
  | "no_candidate"
  | "ignored_form"
  | "pay_button"
  | "create_button"
  | "child_frame"
  | "multiple_forms";
/** Rust `Step` of `note_fill`. */
export type FillStep = "fill" | "otp" | "provider_click" | "account";

export interface PlanField {
  field_ref: string;
  role: FieldRole;
}

export interface PlanGroupOut {
  form_ref: string;
  kind: PlanGroupKind;
  /** Hyphenated id; null for a generated password. Always present on the wire. */
  item_id: string | null;
  fields: PlanField[];
}

/** `PlanOut`: the `plan` of a `plan_fill` reply. */
export interface PlanOut {
  intent: FillIntent;
  groups: PlanGroupOut[];
  action: FillAction;
  confidence: PlanConfidence;
  /** Hyphenated item ids. */
  alternatives: string[];
  reasons: PlanReason[];
}

/** Bridge request `plan_fill` (the client adds `id` and `op`). `origin` is the frame's origin as the background knows it; `context.origin` must equal it. */
export interface PlanFillRequest {
  ctx: "popup" | "menu" | "overlay" | "save_prompt" | "chain";
  origin: string;
  context: PageContext;
}

/** Bridge request `note_fill`. `roles`: the planned form's roles in page order. */
export interface NoteFillRequest {
  ctx: PlanFillRequest["ctx"];
  item_id: string;
  origin: string;
  roles: FieldRole[];
  intent: FillIntent;
  steps: FillStep[];
}

/** Bridge reply of `note_fill`: an empty object. */
export type NoteFillResponse = Record<string, never>;

/** Bridge reply of `plan_fill`. */
export interface PlanFillResponse {
  plan: PlanOut;
}

export type FrameKind = "menu" | "overlay" | "save";

/** Content script to background (untrusted sender: origin comes from `sender`). */
export type CsToBg =
  | { type: "page_analysis"; analysis: PageAnalysis }
  /** `auto`: a click into the field, not the icon or a key; opened only when there is something to offer. */
  | { type: "open_menu"; fieldRef: string; formRef: string; formKind: FormKind; auto?: boolean }
  | { type: "close_menu" }
  | {
      type: "submitted_credentials";
      formRef: string;
      username: string;
      password: string;
      /** Password typed in the "new password" field of a signup or change form. */
      isNew: boolean;
    }
  | { type: "provider_click"; provider: ProviderId; ref: string }
  | { type: "account_click"; email: string; ref: string }
  /**
   * A trusted key in the field the menu is anchored to, while the menu is
   * open: the menu moves its highlight or activates it, the focus stays in
   * the page (spec 8.3, keyboard).
   */
  | { type: "menu_key"; key: MenuKey }
  /** The bridge session's username salt, to hash a typed username here (`withTypedUsernameHash`). */
  | { type: "fill_salt" }
  /**
   * Plan the fill of this page and run the plan. Sent only from a trusted
   * gesture (field icon, popup Fill, `fill-smart` command), never on focus.
   * `formRef` and `fieldRef`: the form and field of an icon click (the run
   * keeps that form's groups only, the progress shows under the field);
   * absent for the popup and the command (the whole plan runs). The origins
   * of the context are the background's.
   */
  | { type: "plan_context"; formRef?: string; fieldRef?: string; context: PlanContextBody };

/** What the content script sends of a `PageContext`: everything but the origins and frame kind. */
export type PlanContextBody = Pick<PageContext, "forms" | "typed_username_hash">;

/** Keys the content script relays to an open menu. */
export type MenuKey = "down" | "up" | "enter";

export type SaveDecision = "save" | "update" | "never" | "dismiss";

export interface SaveEdits {
  title: string;
  username: string;
  password: string;
  vaultId: string;
  rule: "domain" | "exact_host" | "exact_url" | "never";
  tags: string[];
}

/** Extension pages (menu, overlay, save, popup) to background; `token` binds the frame. */
export type UiToBg =
  | { type: "menu_init"; token: string }
  | { type: "menu_pick"; token: string; itemId: string }
  /**
   * "Continuer avec <fournisseur>": starts the chain. `accountId`: the
   * provider account picked in the menu (one it offered), else the default.
   */
  | { type: "menu_signin"; token: string; itemId: string; provider: ProviderId; accountId?: string }
  | { type: "menu_generate"; token: string }
  /** "Enregistrer un nouveau login": the save prompt in its edit view. */
  | { type: "menu_new_login"; token: string }
  | { type: "menu_unlock"; token: string }
  | { type: "menu_close"; token: string }
  /** The page's content height: the frame is sized to it (clamped by the content script). */
  | { type: "menu_resize"; token: string; height: number }
  /**
   * Keys relayed from the page's field (`menu_key`): answered as soon as one
   * arrives, or empty after a while; the menu asks again. A request, never a
   * listener: the page talks to the worker only.
   */
  | { type: "menu_keys"; token: string }
  | { type: "overlay_init"; token: string }
  | { type: "overlay_state"; token: string }
  | { type: "overlay_start"; token: string; itemId: string; provider?: ProviderId; accountId?: string }
  | { type: "overlay_resize"; token: string; height: number }
  | { type: "overlay_stop"; token: string }
  | { type: "overlay_close"; token: string }
  | { type: "save_init"; token: string }
  | { type: "save_reveal"; token: string }
  | { type: "save_generate"; token: string }
  | { type: "save_decide"; token: string; decision: SaveDecision; edits?: SaveEdits; itemId?: string }
  | { type: "save_close"; token: string }
  | { type: "save_resize"; token: string; height: number }
  | { type: "popup_status" }
  | { type: "popup_unlock" }
  | { type: "popup_search"; query: string }
  | { type: "popup_suggestions" }
  | { type: "popup_item"; itemId: string }
  | { type: "popup_reveal"; itemId: string }
  | { type: "popup_fill"; itemId: string }
  | { type: "popup_totp"; itemId: string }
  | { type: "popup_generate"; kind: "smart" | "random" | "memorable" | "pin"; length?: number; symbols?: boolean }
  | { type: "popup_history" }
  /** "Remplir" in the generator: into the new password fields of the active tab. */
  | { type: "popup_fill_generated"; password: string }
  | { type: "popup_pair_start" }
  | { type: "popup_pair_approve" }
  | { type: "popup_pair_cancel" }
  | { type: "popup_forget" }
  /** The plan line's Fill: smart fill in the active tab (a trusted gesture). */
  | { type: "popup_smart_fill" }
  /** "Oublier mes choix sur ce site": the site memory of the active tab's site. */
  | { type: "popup_forget_site" };

/**
 * Background to content script. `origin` on `fill`, `click` and `submit` is a
 * pin, not a policy input: the origin the background verified for this
 * frame. The content script refuses the message when `location.origin`
 * differs (a navigation raced the message; Firefox has no `documentId` to
 * target the exact document).
 */
export type BgToCs =
  /** Values keyed by role; the content script writes them into the fields of `formRef` only. */
  | { type: "fill"; origin: string; formRef: string; values: Partial<Record<FieldRole, string>> }
  | { type: "click"; origin: string; ref: string }
  /**
   * `planned`: a submit decided by a fill plan. The content script then
   * refuses a re-rendered copy of the form (no lineage substitution) and a
   * form whose submit control reads as pay or create at click time.
   */
  | { type: "submit"; origin: string; ref: string; planned?: true }
  /** Run smart fill in this frame as if its user clicked (popup Fill, `fill-smart` command). */
  | { type: "smart_fill" }
  /** The page context of this frame, for a plan made without a click (popup line, chain replan): replied, never sent. */
  | { type: "plan_request" }
  /** `origin`: when set, shown only by a frame still at exactly this origin (no documentId pin). */
  | { type: "show_frame"; kind: FrameKind; url: string; ref?: string; origin?: string }
  | { type: "remove_frame"; kind: FrameKind }
  | { type: "chain_highlight"; ref: string | null }
  /** Height the extension page asked for (validated by token in the worker, clamped here). */
  | { type: "resize_frame"; kind: FrameKind; height: number };

const CS_TO_BG_TYPES: ReadonlySet<string> = new Set<CsToBg["type"]>([
  "page_analysis",
  "open_menu",
  "close_menu",
  "submitted_credentials",
  "provider_click",
  "account_click",
  "menu_key",
  "fill_salt",
  "plan_context",
]);

/** Cheap discriminant check for messages received from content scripts. */
export function isCsToBg(m: unknown): m is CsToBg {
  return (
    typeof m === "object" &&
    m !== null &&
    typeof (m as { type?: unknown }).type === "string" &&
    CS_TO_BG_TYPES.has((m as { type: string }).type)
  );
}
