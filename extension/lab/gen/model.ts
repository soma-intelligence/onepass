// World model of the autofill lab: the plain data a seed expands into (sites,
// scenarios, identity providers, fixture vault). Types only, plus the
// generator version stamped into every world.

export const GENERATOR_VERSION = 1;
export type Lang = string; // BCP 47 primary subtag: "fr", "en", "de", "es", ...
export type ProviderId = "google" | "apple" | "microsoft";
export type FlowId = "login_single" | "login_username_first" | "login_email_then_password" | "login_totp"
  | "login_passkey" | "sso" | "signup" | "checkout_card" | "address" | "identity";
export type TraitId = "iframe_same_origin" | "iframe_cross_site" | "shadow_open" | "shadow_closed" | "spa_rerender"
  | "delayed_fields" | "no_autocomplete" | "obfuscated_names" | "split_otp" | "honeypot" | "decoy_form"
  | "lookalike" | "mixed_language";
export type Role = "username" | "email" | "password" | "new_password" | "otp" | "cc_name" | "cc_number" | "cc_exp"
  | "cc_exp_month" | "cc_exp_year" | "cc_csc" | "given_name" | "family_name" | "tel" | "birth_date" | "organization"
  | "address_line1" | "address_line2" | "postal_code" | "city" | "country";
export type HoneypotStyle = "display_none" | "offscreen" | "opacity" | "one_pixel" | "aria_hidden";
export type LookalikeKind = "suffix" | "typo" | "hyphen" | "idn";
export type LoginStyle = "single" | "username_first" | "email_then_password";
export interface FieldSpec { role: Role; name: string; id: string; label: string; type: string; autocomplete?: string; }
export interface Honeypot { role: Role; name: string; style: HoneypotStyle; }
export interface Passkey { credentialId: string /* base64url */; d: string /* hex scalar */; x: string; y: string /* base64url */; }
export interface Account { username: string; password: string; totpSecret?: string; passkey?: Passkey; }
export interface Site {
  index: number; seed: string; host: string; brand: string; lang: Lang; labelLang: Lang;
  flow: FlowId; traits: TraitId[];
  fields: FieldSpec[];            // fields of the flow's main form, in order
  buttons: { submit: string; next?: string; sso?: string; passkey?: string };
  account?: Account;              // login flows, signup (password undefined until created: use "")
  sso?: { provider: ProviderId; email: string };
  passkeyOnly?: boolean;          // login_passkey: passkey button without password
  loginStyle?: LoginStyle;        // login_totp, login_passkey: shape of the password step
  totpCells?: boolean;            // split_otp
  honeypot?: Honeypot;
  lookalike?: { host: string; kind: LookalikeKind };
  frameHost?: string;             // iframe_cross_site: registrable domain different from host
  delayMs?: number;               // delayed_fields
  cardTitle?: string; identityTitle?: string;  // menu item titles (checkout_card / address, identity)
  itemTitle?: string;             // overlay title of the login item ("<brand>" or "<brand> via <Provider>")
}
export type DriverId = "one_click" | "menu_fill" | "lookalike" | "passkey_control";
export type Expect = "pass" | "xfail" | "nofill";
export interface Scenario { id: string /* "<site index>:<driver>" */; site: number; driver: DriverId; expect: Expect; reason?: string; }
export interface IdpAccount { email: string; password: string; name: string; itemTitle: string; }
export interface FixtureFile { _comment: string; account: string; vaults: { name: string; color?: string }[]; items: unknown[]; }
export interface World {
  version: typeof GENERATOR_VERSION; seed: string; sites: Site[]; scenarios: Scenario[];
  idp: Record<ProviderId, IdpAccount[]>; fixture: FixtureFile; hosts: string[];
}
