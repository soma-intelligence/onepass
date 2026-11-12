// Internal runtime messages (spec 4, 8). `ref` values are opaque ids assigned
// by the content script; they are never selectors supplied by the page.

import type { FieldFeatures } from "../content/detect/features";

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
  | FormsRole
  | "unknown";

/**
 * Roles of travel, company, car rental and administrative identity forms (forms coverage spec,
 * section 3), in the order of Rust `FieldRole` (onepass-core fill_plan, after `RememberMe`).
 * Heuristic only: the models never yield them (ruling R13).
 */
export const FORMS_ROLES = [
  "honorific_prefix",
  "additional_name",
  "birth_name",
  "sex",
  "birth_place",
  "birth_country",
  "nationality",
  "passport_number",
  "passport_issue_date",
  "passport_expiry",
  "passport_issuing_country",
  "license_number",
  "license_issue_date",
  "license_expiry",
  "license_issuing_country",
  "loyalty_number",
  "job_title",
  "department",
  "vat_number",
  "company_id",
  "website",
] as const;
export type FormsRole = (typeof FORMS_ROLES)[number];

/**
 * A role read from a passport, a driver's license or a loyalty card: it
 * follows the card rule (never a hidden field nor a cross-site frame, only
 * on a user action, never auto-submitted, never in a sign-in, sign-up, code
 * or password change form).
 */
export function isDocumentRole(role: string): boolean {
  return role.startsWith("passport_") || role.startsWith("license_") || role === "loyalty_number";
}

/** The form kinds that never take a document role. */
export const NO_DOCUMENT_KINDS: ReadonlySet<FormKind> = new Set<FormKind>(["login", "signup", "otp", "change_password"]);

/** The form kinds with a new password to make: the menu's generator, the ghost (spec 3.1). */
export const NEW_PASSWORD_FORMS: ReadonlySet<string> = new Set<FormKind>(["signup", "change_password"]);

// ---- fill_identity (mirror of onepass_bridge::api) ----

/** What `fill_identity` may add to the identity's own values, asked only for the roles a form has. */
export type Extra = "passport" | "driver_license" | "loyalty";

/** The passport associated with the identity. Dates `YYYY-MM-DD`, sex `f`, `m` or `x`; absent: unknown. */
export interface PassportOut {
  first_names?: string;
  last_name?: string;
  number?: string;
  issuing_country?: string;
  issued_on?: string;
  expiry?: string;
  nationality?: string;
  sex?: string;
  birth_date?: string;
  birth_place?: string;
}

/** The driver license associated with the identity. */
export interface LicenseOut {
  number?: string;
  country?: string;
  issued_on?: string;
  expiry?: string;
}

/** The site's loyalty program. */
export interface LoyaltyOut {
  number: string;
  program?: string;
}

/** Address of `fill_identity`. */
export interface AddressOut {
  line1: string;
  line2: string;
  city: string;
  postal_code: string;
  region: string;
  country: string;
}

/** `fill_identity` reply: every value optional (absent when empty); documents and loyalty only on request. */
export interface IdentityFill {
  given_name?: string;
  family_name?: string;
  email?: string;
  tel?: string;
  organization?: string;
  birthday?: string;
  address?: AddressOut;
  honorific?: string;
  middle_name?: string;
  birth_name?: string;
  /** `f`, `m` or `x`. */
  sex?: string;
  birth_place?: string;
  nationality?: string;
  job_title?: string;
  department?: string;
  website?: string;
  work_tel?: string;
  vat_number?: string;
  company_registration?: string;
  passport?: PassportOut;
  driver_license?: LicenseOut;
  loyalty?: LoyaltyOut;
}

/**
 * What an identity fill knows besides the values of its roles, never written as such (forms
 * coverage, spec sections 4 and 7): the identity's sex (`f`, `m`, `x`) for a nationality's gender,
 * whether a civility may come from it (the civility role was asked and the vault has none), the
 * work phone for a `work` tel field (the tel role was asked).
 */
export interface FillHints {
  sex?: string;
  civility_from_sex?: true;
  work_tel?: string;
}

/** What a card, identity or address form sent by hand can be saved as. */
export type SavedFormKind = "card" | "identity";

/** Roles a sent card form may report (no `cc_csc`: a security code is never saved from a page). */
export const CARD_SUBMIT_ROLES = ["cc_name", "cc_number", "cc_exp", "cc_exp_month", "cc_exp_year"] as const;
/** Roles a sent identity or address form may report. */
export const IDENTITY_SUBMIT_ROLES = [
  "given_name",
  "family_name",
  "full_name",
  "email",
  "tel",
  "organization",
  "address_line1",
  "address_line2",
  "city",
  "postal_code",
  "region",
  "country",
] as const;
export type SubmittedRole = (typeof CARD_SUBMIT_ROLES)[number] | (typeof IDENTITY_SUBMIT_ROLES)[number];
export type SubmittedValues = Partial<Record<SubmittedRole, string>>;

export type FormKind = "login" | "signup" | "change_password" | "otp" | "card" | "identity" | "address";

export interface FieldInfo {
  ref: string;
  role: FieldRole;
  /**
   * Refs of every cell of a split field, in order (spec 8.2: 4 to 8 one-character
   * OTP inputs form one logical field). `ref` is then the first cell.
   */
  parts?: string[];
  /**
   * The person of the field (forms coverage, ruling R3): absent or 0 is the owner (the identity
   * filled), 1 and more are passengers 2 and later, never filled by OnePass.
   */
  person?: number;
  /** A phone of the work kind (`autocomplete="work tel"`, "Téléphone professionnel"), ruling R7. */
  work?: true;
}

/** Highest `FieldInfo.person` the router accepts. */
export const MAX_PERSON = 16;

export interface FormInfo {
  ref: string;
  kind: FormKind;
  fields: FieldInfo[];
  submitRef?: string;
}

export interface PageAnalysis {
  url: string;
  forms: FormInfo[];
  /** A CAPTCHA challenge is shown to the user now: the chain stops. */
  captcha: boolean;
  /** A CAPTCHA widget sits on the page and asks nothing (yet): no stop; a refused submit there is named a CAPTCHA. */
  captchaWidget?: boolean;
  /** The page shows one button that reads as a passkey sign-in: a sign-in page even with no field and no provider button. */
  passkeySignIn?: boolean;
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
/** `passkey`: makes a passkey (one-click signup offers it), never a sign-in with one. */
export type ButtonClass = "submit" | "next" | "pay" | "create" | "other" | "passkey";

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
  /** Several accounts, one of them saved for this exact host, no memory: confident, may submit. */
  | "sole_exact_host"
  /** Offered through Apple's shared-credentials list, never used on this site: shown in the menu, never submitted. */
  | "associated_domain"
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
  | "multiple_forms"
  | "passkey_offered";
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
  /** Signup only: the form's passkey button, offered instead of a password (null or absent: none). */
  passkey?: PlanPasskey | null;
}

/** Rust `PasskeyOffer`: refs of the signup form and of its passkey button. */
export interface PlanPasskey {
  form_ref: string;
  button_ref: string;
}

/** `menu_signup`: the signup with a generated password, or a passkey made by the site's own button. */
export type SignupMode = "password" | "passkey";

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

/** Bridge request `client_info`: the browser and this profile's opaque id (once per session). */
export interface ClientInfoRequest {
  browser: "unknown" | "safari" | "chrome" | "edge" | "brave" | "firefox" | "arc" | "opera" | "vivaldi" | "chromium";
  profile_id?: string;
  profile_name?: string;
}

/** Bridge request `note_autofill`: one event of the on-device autofill history. */
export interface NoteAutofillRequest {
  ctx: "menu" | "popup" | "overlay" | "chain";
  origin: string;
  action: "shown" | "picked" | "filled" | "submitted" | "dismissed" | "picked_other";
  item_id?: string;
  rank?: number;
  /** `shown`: item ids, best first, at most 8. */
  shown?: string[];
}

/** Bridge reply of `note_fill`: an empty object. */
export type NoteFillResponse = Record<string, never>;

/** Bridge reply of `plan_fill`. */
export interface PlanFillResponse {
  plan: PlanOut;
}

/** The extension frames of the in-page shell (content/frames.ts); `ghost`: the suggested password over its field. */
export type FrameKind = "menu" | "overlay" | "save" | "ghost";

/** A box in CSS px: the field's in the viewport, or the ghost's pill in its own frame. */
export interface GhostRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

/**
 * The field's text box as the content script measures it, for the ghost laid over it (spec
 * 3.2): its computed type metrics in CSS px and its box in the viewport. Never a value of the
 * field.
 */
export interface GhostMetrics {
  fontSize: number;
  lineHeight: number;
  paddingLeft: number;
  paddingRight: number;
  textAlign: "left" | "right" | "center";
  /** The field's own family when it is a local font; null: the system font. */
  fontFamily: string | null;
  box: GhostRect;
}

/** What the ghost and the menu's preview row show of a held suggestion (no metrics for the menu). */
export interface SuggestionPreview {
  password: string;
  /** The four-segment strength bar: 0 (none) to 4. */
  strength: 0 | 1 | 2 | 3 | 4;
  length: number;
}

/**
 * The menu's reply to `menu_preview`, `menu_regenerate` and `menu_profile`: the preview and the
 * stored custom generator profile the length panel starts from (never read off the password).
 */
export interface MenuPreview extends SuggestionPreview {
  profile: { length: number; symbols: boolean };
}

/**
 * Spec 5.3: a form kept on screen is judged this long after its submission (`submit_outcome`),
 * and a new top document reports a `role="alert"` shown this long after its load (`page_alert`).
 * Shared by the content script and the worker.
 */
export const UNCERTAIN_MS = 1500;

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
  /**
   * A lone identifier step of a sign-in was sent (identifier first, password on the next page):
   * the identifier only, so the password step can be proposed with it.
   */
  | { type: "submitted_identifier"; formRef: string; username: string }
  /**
   * Spec 5.3: UNCERTAIN_MS after a trusted sign-in submission whose form is still in the
   * document: the URL changed (path or hash), the password field was emptied or removed, a
   * `role="alert"` or `aria-invalid="true"` is in the form. No identifier, no password.
   */
  | { type: "submit_outcome"; formRef: string; urlChanged: boolean; passwordCleared: boolean; alert: boolean }
  /**
   * Spec 5.3: a top document shows a `role="alert"` within UNCERTAIN_MS of its load (an error or
   * captcha page). The worker only ever makes a pending sign-in more cautious with it.
   */
  | { type: "page_alert" }
  /**
   * A card, identity or address form sent by the user (trusted gesture, like a sign-in): the
   * values of its card or identity roles (never a security code), to offer saving them.
   */
  | { type: "submitted_form"; formRef: string; kind: SavedFormKind; values: SubmittedValues }
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
   * of the context are the background's. `bare`: a gesture without a field
   * in a frame that has none to open the menu under (a locked vault then has
   * no menu to wait in: a card of the page waits instead).
   */
  | { type: "plan_context"; formRef?: string; fieldRef?: string; context: PlanContextBody; bare?: true }
  /**
   * Model builds only (Task 15): features of one form (never a field value), one label per field
   * back. An empty list is the handshake: the worker answers its model kind, or null.
   */
  | { type: "classify"; fields: FieldFeatures[] }
  /**
   * A trusted focus in an empty new-password field of a signup or change-password form (spec
   * 3.1): the worker generates and holds a password for it, and answers the ghost frame's URL.
   */
  | { type: "ghost_open"; fieldRef: string; formRef: string; formKind: FormKind; metrics: GhostMetrics }
  /** Tab or Enter in the field while the ghost shows: the held password is filled. */
  | { type: "ghost_accept" }
  /** A printable key or Escape: the ghost goes, its password is forgotten. */
  | { type: "ghost_dismiss" }
  /** Arrow Down or the chevron: the ghost goes, the menu opens on its suggestion (answers its URL). */
  | { type: "ghost_menu" }
  /**
   * A trusted input in the top page while the sign-in pill it showed by itself is there: that
   * card folds away (the worker checks it is one, and idle). Carries nothing typed.
   */
  | { type: "page_typed" };

/** What the content script sends of a `PageContext`: everything but the origins and frame kind. */
export type PlanContextBody = Pick<PageContext, "forms" | "typed_username_hash">;

/** Keys the content script relays to an open menu. */
export type MenuKey = "down" | "up" | "enter";

/**
 * "later": the card went away by itself (no action for a while); the submission waits in the
 * toolbar popup instead.
 */
export type SaveDecision = "save" | "update" | "never" | "dismiss" | "later";

/** What a save or an update did (the card and the popup say it). */
export interface SaveOutcome {
  outcome: "saved" | "updated" | "already" | "done";
  /** The vault the login went to. */
  vault?: string;
}

export interface SaveEdits {
  title: string;
  username: string;
  password: string;
  vaultId: string;
  rule: "domain" | "exact_host" | "exact_url" | "never";
  tags: string[];
  /** Spec 5.2, decision `update`: the login picked among the card's `choices`. */
  itemId?: string;
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
  /** The suggestion row's preview (`SuggestionPreview`): the held password of the menu's field. */
  | { type: "menu_preview"; token: string }
  /** "Other suggestion": a new draw for the held password; answers the preview. */
  | { type: "menu_regenerate"; token: string }
  /**
   * "Length and characters": writes the custom generator profile (`GENERATOR_PROFILE_KEY`) and
   * redraws the held password with it; answers the preview.
   */
  | { type: "menu_profile"; token: string; length: number; symbols: boolean }
  /** The ghost page's first call: `SuggestionPreview` plus the field's `GhostMetrics`. */
  | { type: "ghost_init"; token: string }
  /** A click on the ghost's "Use" pill. */
  | { type: "ghost_accept"; token: string }
  /** A click on the ghost's chevron: the ghost goes, the menu opens on its suggestion. */
  | { type: "ghost_menu"; token: string }
  /**
   * Where the ghost's pill is in its frame (frame-local CSS px), sent once laid out and again when
   * the pointer leaves the pill (`over: false`): the content script lets the frame take the pointer
   * only over the pill (spec 3.2), every other point of the field goes through to the page.
   */
  | { type: "ghost_pill"; token: string; rect: GhostRect; over: boolean }
  /** The signup choice of a menu a passkey-offering plan opened (one-click signup). */
  | { type: "menu_signup"; token: string; mode: SignupMode }
  /** "Enregistrer un nouveau login": the save prompt in its edit view. */
  | { type: "menu_new_login"; token: string }
  | { type: "menu_unlock"; token: string }
  /** "Appairer avec OnePass" in a menu of an unpaired extension: opens the popup, where pairing happens. */
  | { type: "menu_pair"; token: string }
  /**
   * iOS (spec 2026-11-03-ios-safari-autofill 4): the unlock sheet in the menu. `menu_vault` reads
   * the native vault (refused with "unsupported" where there is none, macOS and the other
   * browsers); the two others unlock it with Face ID or Touch ID, or the master password.
   */
  | { type: "menu_vault"; token: string }
  /**
   * Face ID (or Touch ID) in the iOS sheet. `gesture`: a tap on its button, the fill resumes.
   * Absent: the menu's one automatic try; it resumes the fill too when a trusted gesture (the
   * field icon, the command) opened this menu on the locked vault, and only unlocks otherwise.
   */
  | { type: "menu_unlock_biometric"; token: string; gesture?: true }
  | { type: "menu_unlock_password"; token: string; password: string }
  /**
   * The menu asks whether the unlock asked for it in the app is done (Touch ID on the Mac): asked
   * by its own button (`menu_unlock`), or already by the trusted gesture that opened it on a
   * locked vault or a missing app (the menu then waits with no second click). Open: its field
   * runs its plan again in the menu's frame, once. Still locked or still starting: "locked" /
   * "host_missing", nothing is used up. Never asked for this menu: "invalid". The iOS sheet's
   * unlocks resume in their own call (`menu_unlock_biometric`, `menu_unlock_password`), never by this.
   */
  | { type: "menu_resume"; token: string }
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
  /**
   * The click on a generic card (shown on a sign-in page reached with the vault locked, nothing
   * of the vault on it): the app is asked to unlock, then the page's own plan runs, once.
   */
  | { type: "overlay_unlock"; token: string }
  | { type: "overlay_stop"; token: string }
  | { type: "overlay_close"; token: string }
  /** The create pill's click (a card that appeared by itself on a signup page): a strong password fills the form, nothing is sent. */
  | { type: "overlay_create"; token: string }
  /** "Never on this site" on a card that appeared by itself: its site joins the never-list, the card goes. */
  | { type: "overlay_never"; token: string }
  | { type: "save_init"; token: string }
  | { type: "save_reveal"; token: string }
  | { type: "save_generate"; token: string }
  | { type: "save_decide"; token: string; decision: SaveDecision; edits?: SaveEdits; itemId?: string }
  | { type: "save_close"; token: string }
  /** The toast's Undo: the login saved moments ago is deleted (the bridge's `undo_save`). */
  | { type: "save_undo"; token: string }
  /** The toast's Edit: its edit view opens; its Save then replaces the saved login. */
  | { type: "save_edit"; token: string }
  /** `width`: the pill's own width (absent: the card's). */
  | { type: "save_resize"; token: string; height: number; width?: number }
  /** The card folds into its pill (spec 4.2): the worker keeps the sign-in for PILL_TTL_MS. */
  | { type: "save_fold"; token: string }
  /** A click on the pill: the card again. */
  | { type: "save_unfold"; token: string }
  | { type: "popup_status" }
  /** Sign-ins whose save card went away unanswered. */
  | { type: "popup_pending" }
  | { type: "popup_pending_decide"; id: string; decision: "save" | "update" | "never" | "dismiss" }
  | { type: "popup_unlock" }
  /**
   * iOS (IOSSAF-01): the unlock sheet in the toolbar popup, the same native vault calls as the
   * menu's (`menu_vault` and its two unlocks); refused with "invalid" where there is none.
   */
  | { type: "popup_vault" }
  | { type: "popup_unlock_biometric" }
  | { type: "popup_unlock_password"; password: string }
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
  /** "Associer à OnePass": pair without a code if the app vouches for this browser. */
  | { type: "popup_pair_auto" }
  | { type: "popup_pair_start" }
  | { type: "popup_pair_approve" }
  | { type: "popup_pair_cancel" }
  | { type: "popup_forget" }
  /** The plan line's Fill: smart fill in the active tab (a trusted gesture). */
  | { type: "popup_smart_fill" }
  /** "Oublier mes choix sur ce site": the site memory of the active tab's site. */
  | { type: "popup_forget_site" }
  // ---- passkey choice window (passkey.html, background/passkey.ts) ----
  | { type: "passkey_init"; token: string }
  /** Sign in with this passkey (one `passkey_init` offered). */
  | { type: "passkey_pick"; token: string; itemId: string; credentialId: string }
  /** Create the passkey in OnePass; `vaultId`: one `passkey_init` offered, else the host's default. */
  | { type: "passkey_save"; token: string; vaultId?: string }
  /** "Autre appareil": the browser's own passkey dialog takes over. */
  | { type: "passkey_other"; token: string }
  | { type: "passkey_cancel"; token: string };

/**
 * Background to content script. `origin` on `fill`, `click` and `submit` is a
 * pin, not a policy input: the origin the background verified for this
 * frame. The content script refuses the message when `location.origin`
 * differs (a navigation raced the message; Firefox has no `documentId` to
 * target the exact document).
 */
export type BgToCs =
  /** Values keyed by role; the content script writes them into the fields of `formRef` only. */
  | { type: "fill"; origin: string; formRef: string; values: Partial<Record<FieldRole, string>>; hints?: FillHints }
  | { type: "click"; origin: string; ref: string }
  /** The user chose a passkey: click this button only if it still reads as a passkey button. */
  | { type: "click_passkey"; origin: string; ref: string }
  /**
   * A gesture on a sign-in page with no form: press the page's one button that reads as a
   * passkey sign-in (the worker armed the site's one passkey account for the request it makes).
   */
  | { type: "click_passkey_signin"; origin: string }
  /**
   * `planned`: a submit decided by a fill plan. The content script then
   * refuses a re-rendered copy of the form (no lineage substitution) and a
   * form whose submit control reads as pay or create at click time.
   */
  | { type: "submit"; origin: string; ref: string; planned?: true }
  /**
   * Run smart fill in this frame as if its user clicked (popup Fill, `fill-smart` command).
   * `fieldRef`, `origin`: the field of a menu the user unlocked from, its plan run once after the
   * unlock (MS-03, IOSSAF-02); only that field, only at that origin. `formRef`: that menu's form.
   * A page that redrew the form while the unlock was pending has killed the field's ref: the one
   * copy of that very form (same identity, `FormLineage`) takes the fill, or nothing does.
   */
  | { type: "smart_fill"; fieldRef?: string; formRef?: string; origin?: string }
  /** The page context of this frame, for a plan made without a click (popup line, chain replan): replied, never sent. */
  | { type: "plan_request" }
  /** `origin`: when set, shown only by a frame still at exactly this origin (no documentId pin). */
  /** `auto`: the sign-in card that appeared by itself (no gesture); the page's first input folds it (`page_typed`). */
  | { type: "show_frame"; kind: FrameKind; url: string; ref?: string; origin?: string; auto?: true }
  | { type: "remove_frame"; kind: FrameKind }
  | { type: "chain_highlight"; ref: string | null }
  /** Height the extension page asked for (validated by token in the worker, clamped here). */
  | { type: "resize_frame"; kind: FrameKind; height: number; width?: number }
  /** The ghost page's pill box and pointer state (`ghost_pill` of UiToBg), vouched by the worker. */
  | { type: "ghost_pill"; rect: GhostRect; over: boolean }
  /**
   * What the page says about the new password fields of `formRef` (rules,
   * lengths, written hints, `pattern`): replied as `PasswordContextReply`,
   * never a value typed in the page.
   */
  | { type: "password_context"; origin: string; formRef: string }
  /**
   * Does `candidate` pass the `pattern` of the new password fields of
   * `formRef`? Tested in the page's tab, never in the worker (spec 6.3);
   * replied `{ ok, matches }`. The candidate is neither kept nor logged.
   */
  | { type: "pattern_check"; origin: string; formRef: string; candidate: string }
  /**
   * Does `candidate` fit the `username` field of `formRef` (its type, `maxlength`, `minlength`,
   * `pattern`)? Replied as `UsernameCheckReply`; tested in the page's tab, not kept.
   */
  | { type: "username_check"; origin: string; formRef: string; candidate: string };

/**
 * The page's password rules as the bridge's `generate` takes them
 * (`RecipeContext` of onepass-bridge): at most 8 `passwordrules` strings of
 * at most 1024 UTF-8 bytes each, `hint_text` at most 600 chars.
 */
export interface WirePasswordContext {
  rules: string[];
  min_length?: number;
  max_length?: number;
  hint_text?: string;
}

/** Reply of the content script to `password_context`; `has_pattern`: a candidate must pass `pattern_check`. */
export interface PasswordContextReply {
  ok: boolean;
  context?: WirePasswordContext;
  has_pattern?: boolean;
}

/** Reply of the content script to `username_check`; `max_length`: the field's `maxlength`. */
export interface UsernameCheckReply {
  ok: boolean;
  matches?: boolean;
  max_length?: number;
}

/** Reply of the content script to `pattern_check`. */
export interface PatternCheckReply {
  ok: boolean;
  matches?: boolean;
}

const CS_TO_BG_TYPES: ReadonlySet<string> = new Set<CsToBg["type"]>([
  "page_analysis",
  "open_menu",
  "close_menu",
  "submitted_credentials",
  "submitted_identifier",
  "submit_outcome",
  "page_alert",
  "submitted_form",
  "provider_click",
  "account_click",
  "menu_key",
  "fill_salt",
  "plan_context",
  "classify",
  "ghost_open",
  "ghost_accept",
  "ghost_dismiss",
  "ghost_menu",
  "page_typed",
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

// ---- Passkeys (spec 3.2) ----
// The MAIN-world shim (content/passkey-shim.ts) wraps navigator.credentials and
// talks to the isolated relay (content/passkey.ts) over a MessageChannel; the
// relay sends `passkey_request` here. Byte strings are unpadded base64url.
// Nothing the page sends is an origin: the worker takes it from `sender`.

/** Marker of the handshake messages between the MAIN-world shim and the relay (the shim repeats it). */
export const PASSKEY_CHANNEL = "onepass-passkey";

/** Largest base64url string of a challenge (1024 bytes, the host's bound). */
export const PASSKEY_MAX_CHALLENGE = 1366;
/** Largest base64url credential id (1023 bytes, WebAuthn). */
export const PASSKEY_MAX_CREDENTIAL_ID = 1364;
/** Largest base64url user handle (64 bytes, WebAuthn). */
export const PASSKEY_MAX_USER_ID = 86;
/** Most entries of `allowCredentials` / `excludeCredentials` (the host's bound for `exclude`). */
export const PASSKEY_MAX_CREDENTIALS = 64;
export const PASSKEY_MAX_USER_NAME = 1024;
export const PASSKEY_MAX_RP_ID = 253;
export const PASSKEY_MAX_ALGS = 32;
/** Largest `timeout` the page may ask for, in ms (the worker clamps it again). */
export const PASSKEY_MAX_TIMEOUT = 600_000;

export interface PasskeyGetRequest {
  kind: "get";
  /** `publicKey.rpId`; absent: the host of the frame's origin. */
  rpId?: string;
  challenge: string;
  /** `allowCredentials` ids; empty: any passkey of the site. */
  allow: string[];
  timeout?: number;
}

export interface PasskeyCreateRequest {
  kind: "create";
  /** `publicKey.rp.id`; absent: the host of the frame's origin. */
  rpId?: string;
  challenge: string;
  userId: string;
  userName: string;
  /** `excludeCredentials` ids. */
  exclude: string[];
  /** `pubKeyCredParams` algorithms (COSE); OnePass signs ES256 (-7) only. */
  algs: number[];
  timeout?: number;
}

export type PasskeyRequest = PasskeyGetRequest | PasskeyCreateRequest;

/** Isolated relay to background (untrusted: sizes and types checked again there). */
export type PasskeyCsToBg =
  | { type: "passkey_request"; reqId: string; request: PasskeyRequest; activated: boolean }
  | { type: "passkey_abort"; reqId: string };

export type PasskeyErrorName = "NotAllowedError" | "InvalidStateError" | "AbortError";

/** What the page gets back: the browser's own API, a DOMException, or the final credential. */
export type PasskeyResult =
  | { kind: "fallback" }
  | { kind: "error"; name: PasskeyErrorName }
  | {
      kind: "assertion";
      credentialId: string;
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
      userHandle: string;
    }
  | {
      kind: "registration";
      credentialId: string;
      clientDataJSON: string;
      attestationObject: string;
      authenticatorData: string;
      publicKey: string;
      publicKeyAlgorithm: number;
    };

/** One account of the choice window. */
export interface PasskeyAccount {
  itemId: string;
  credentialId: string;
  title: string;
  userName: string;
  vaultName: string;
}

/** `passkey_init` reply. */
export interface PasskeyInit {
  kind: "get" | "create";
  origin: string;
  /** Relying party id the passkey is for (shown as the site). */
  rpId: string;
  /** get: the passkeys offered. */
  accounts: PasskeyAccount[];
  /** create: the account name the site asked for. */
  userName?: string;
  /** create: the vaults a new Login may go to. */
  vaults?: { id: string; name: string }[];
}

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

/** Unpadded base64url of `min`..`max` characters (no bit left over). */
export function isB64url(v: unknown, max: number, min = 1): v is string {
  return typeof v === "string" && v.length >= min && v.length <= max && B64URL_RE.test(v) && v.length % 4 !== 1;
}

const ERROR_NAMES: ReadonlySet<string> = new Set<PasskeyErrorName>(["NotAllowedError", "InvalidStateError", "AbortError"]);

/** A `PasskeyResult` rebuilt from untrusted input (the relay checks the worker's reply), or null. */
export function parsePasskeyResult(v: unknown): PasskeyResult | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  const b = (k: string, max = 1 << 16, min = 1): string => {
    const x = o[k];
    if (!isB64url(x, max, min)) throw new Error(k);
    return x;
  };
  try {
    switch (o.kind) {
      case "fallback":
        return { kind: "fallback" };
      case "error":
        return typeof o.name === "string" && ERROR_NAMES.has(o.name) ? { kind: "error", name: o.name as PasskeyErrorName } : null;
      case "assertion":
        return {
          kind: "assertion",
          credentialId: b("credentialId", PASSKEY_MAX_CREDENTIAL_ID),
          clientDataJSON: b("clientDataJSON"),
          authenticatorData: b("authenticatorData"),
          signature: b("signature"),
          userHandle: b("userHandle", PASSKEY_MAX_USER_ID, 0),
        };
      case "registration": {
        const alg = o.publicKeyAlgorithm;
        if (typeof alg !== "number" || !Number.isSafeInteger(alg)) return null;
        return {
          kind: "registration",
          credentialId: b("credentialId", PASSKEY_MAX_CREDENTIAL_ID),
          clientDataJSON: b("clientDataJSON"),
          attestationObject: b("attestationObject"),
          authenticatorData: b("authenticatorData"),
          publicKey: b("publicKey"),
          publicKeyAlgorithm: alg,
        };
      }
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/** A `PasskeyRequest` rebuilt from untrusted input, sizes and types checked, or null. */
export function parsePasskeyRequest(v: unknown): PasskeyRequest | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const ids = (x: unknown): string[] | null => {
    if (!Array.isArray(x) || x.length > PASSKEY_MAX_CREDENTIALS) return null;
    return x.every((id) => isB64url(id, PASSKEY_MAX_CREDENTIAL_ID)) ? (x as string[]) : null;
  };
  if (!isB64url(o.challenge, PASSKEY_MAX_CHALLENGE)) return null;
  let rpId: string | undefined;
  if (o.rpId !== undefined) {
    if (typeof o.rpId !== "string" || o.rpId.length < 1 || o.rpId.length > PASSKEY_MAX_RP_ID) return null;
    rpId = o.rpId.toLowerCase();
  }
  let timeout: number | undefined;
  if (o.timeout !== undefined) {
    if (typeof o.timeout !== "number" || !Number.isSafeInteger(o.timeout) || o.timeout < 0 || o.timeout > PASSKEY_MAX_TIMEOUT) return null;
    timeout = o.timeout;
  }
  const opt = { ...(rpId !== undefined ? { rpId } : {}), ...(timeout !== undefined ? { timeout } : {}) };
  if (o.kind === "get") {
    const allow = ids(o.allow);
    if (!allow) return null;
    return { kind: "get", challenge: o.challenge, allow: [...allow], ...opt };
  }
  if (o.kind === "create") {
    const exclude = ids(o.exclude);
    if (!exclude) return null;
    if (!isB64url(o.userId, PASSKEY_MAX_USER_ID)) return null;
    if (typeof o.userName !== "string" || o.userName.length < 1 || o.userName.length > PASSKEY_MAX_USER_NAME) return null;
    const algs = o.algs;
    if (!Array.isArray(algs) || algs.length > PASSKEY_MAX_ALGS || !algs.every((a) => typeof a === "number" && Number.isSafeInteger(a))) return null;
    return {
      kind: "create",
      challenge: o.challenge,
      userId: o.userId,
      userName: o.userName,
      exclude: [...exclude],
      algs: [...(algs as number[])],
      ...opt,
    };
  }
  return null;
}
