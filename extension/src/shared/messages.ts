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

export type FrameKind = "menu" | "overlay" | "save";

/** Content script to background (untrusted sender: origin comes from `sender`). */
export type CsToBg =
  | { type: "page_analysis"; analysis: PageAnalysis }
  | { type: "open_menu"; fieldRef: string; formRef: string; formKind: FormKind }
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
  | { type: "account_click"; email: string; ref: string };

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
  /** "Se connecter avec <fournisseur> (<email>)": starts the chain. */
  | { type: "menu_signin"; token: string; itemId: string; provider: ProviderId }
  | { type: "menu_generate"; token: string }
  /** "Enregistrer un nouveau login": the save prompt in its edit view. */
  | { type: "menu_new_login"; token: string }
  | { type: "menu_unlock"; token: string }
  | { type: "menu_close"; token: string }
  | { type: "overlay_init"; token: string }
  | { type: "overlay_state"; token: string }
  | { type: "overlay_start"; token: string; itemId: string; provider?: ProviderId }
  | { type: "overlay_stop"; token: string }
  | { type: "overlay_close"; token: string }
  | { type: "save_init"; token: string }
  | { type: "save_reveal"; token: string }
  | { type: "save_generate"; token: string }
  | { type: "save_decide"; token: string; decision: SaveDecision; edits?: SaveEdits; itemId?: string }
  | { type: "save_close"; token: string }
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
  | { type: "popup_forget" };

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
  | { type: "submit"; origin: string; ref: string }
  /** `origin`: when set, shown only by a frame still at exactly this origin (no documentId pin). */
  | { type: "show_frame"; kind: FrameKind; url: string; ref?: string; origin?: string }
  | { type: "remove_frame"; kind: FrameKind }
  | { type: "chain_highlight"; ref: string | null };

const CS_TO_BG_TYPES: ReadonlySet<string> = new Set<CsToBg["type"]>([
  "page_analysis",
  "open_menu",
  "close_menu",
  "submitted_credentials",
  "provider_click",
  "account_click",
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
