// World model of the autofill lab: the plain data a seed expands into (sites,
// scenarios, identity providers, fixture vault). Types only, plus the
// generator version stamped into every world.

import type { CountryCase } from "./cases.ts";
import type { Behaviour, Profile } from "./population.ts";

export const GENERATOR_VERSION = 4;
export type Lang = string; // BCP 47 primary subtag: "fr", "en", "de", "es", ...
export type ProviderId = "google" | "apple" | "microsoft";
export type FlowId = "login_single" | "login_username_first" | "login_email_then_password" | "login_totp"
  | "login_passkey" | "sso" | "signup" | "checkout_card" | "address" | "identity" | "multi_step"
  | "travel_booking" | "company_b2b" | "car_rental" | "admin_identity";
export type TraitId = "iframe_same_origin" | "iframe_cross_site" | "shadow_open" | "shadow_closed" | "spa_rerender"
  | "delayed_fields" | "no_autocomplete" | "obfuscated_names" | "split_otp" | "honeypot" | "decoy_form"
  | "lookalike" | "mixed_language";
export type Role = "username" | "email" | "password" | "new_password" | "otp" | "cc_name" | "cc_number" | "cc_exp"
  | "cc_exp_month" | "cc_exp_year" | "cc_csc" | "given_name" | "family_name" | "tel" | "birth_date" | "organization"
  | "address_line1" | "address_line2" | "postal_code" | "city" | "country";
/**
 * Roles of the forms flows (travel, company, car rental, admin identity), outside the 21 model classes (ruling R13):
 * the dataset labels them "none". `bday_*` are the parts of a birth date split in three controls; a document date
 * split the same way keeps its document role and says its part in `FieldRender.date`.
 */
export type FormsRole = "honorific" | "additional_name" | "birth_name" | "sex" | "birth_place" | "birth_country"
  | "nationality" | "bday_day" | "bday_month" | "bday_year" | "passport_number" | "passport_issuing_country"
  | "passport_issue_date" | "passport_expiry" | "loyalty_number" | "license_number" | "license_issuing_country"
  | "license_issue_date" | "license_expiry" | "job_title" | "department" | "vat_number" | "company_id" | "website"
  | "tel_work";
/** Any role a generated field can have. */
export type LabRole = Role | FormsRole;
/** Block of a forms page a field sits in. */
export type Block = "billing" | "shipping" | "contact" | "passenger";
export type DatePart = "day" | "month" | "year";
/**
 * How a date field is rendered: a date input, a text field written in `format` (tokens DD, MM, YYYY, any
 * separator; `placeholder` says whether the page shows the format), or one part of a date split in three
 * controls (`group` is the shared legend; months as numbers or names in the label language; days with or without
 * a leading zero; `select` false for a text part).
 */
export type DateRender =
  | { kind: "input" }
  | { kind: "text"; format: string; placeholder: boolean }
  | { kind: "part"; part: DatePart; group: string; select: boolean; months?: "number" | "name"; pad?: boolean };
export interface ChoiceOption { value: string; label: string }
/** A choice field (civility, sex, nationality, issuing country): a list, a radio group (same name), or free text. */
export type ChoiceRender = { kind: "select" | "radio"; options: ChoiceOption[] } | { kind: "text" };
export interface FieldRender { date?: DateRender; choice?: ChoiceRender }
export type HoneypotStyle = "display_none" | "offscreen" | "opacity" | "one_pixel" | "aria_hidden";
export type LookalikeKind = "suffix" | "typo" | "hyphen" | "idn";
export type LoginStyle = "single" | "username_first" | "email_then_password";
export type LayoutId = "stacked" | "floating" | "placeholder_only" | "side_label" | "grid" | "inline" | "card";
export type FrameworkId = "static" | "react" | "vue" | "angular";
export interface FieldSpec {
  role: LabRole; name: string; id: string; label: string; type: string; autocomplete?: string;
  /** Forms flows: the traveller the field belongs to (0 or absent: the vault's person; 1 and up: passengers 2 and up). */
  person?: number;
  /** Forms flows: the block of the page the field sits in. */
  block?: Block;
  /** Forms flows: date and choice rendering (absent: a plain control of `type`). */
  render?: FieldRender;
}
export interface Honeypot { role: LabRole; name: string; style: HoneypotStyle; }
/**
 * What a forms site holds besides its fields (forms flows only): the titles of the vault items it reads (the
 * identity is `Site.identityTitle`), the company ids the identity carries (kept here too: the vault template gets
 * them in plan Task 5), whether the shipping block is hidden by "same as billing", the date format the page writes.
 */
export interface SiteForms {
  passportTitle?: string; licenseTitle?: string;
  /** The site's loyalty program in the vault (absent: the site asks for one the vault does not have). */
  loyaltyTitle?: string;
  /** A passport of another person in the vault (about 30 % of travel sites): it must never come out. */
  decoyPassportTitle?: string;
  vatNumber?: string; companyId?: string;
  /** company_b2b with a shipping block: whether "same as billing" is checked (block hidden, expected empty). */
  shippingSame?: boolean;
  /** Text date format of the site (tokens DD, MM, YYYY), when its date fields are text. */
  dateFormat?: string;
}
export interface Passkey { credentialId: string /* base64url */; d: string /* hex scalar */; x: string; y: string /* base64url */; }
export interface Account { username: string; password: string; totpSecret?: string; passkey?: Passkey; }
/**
 * Password rules a signup site enforces (server side) and states (page side). `via` lists where the page states them:
 * `attributes` (minlength, maxlength, pattern), `passwordrules` (Apple attribute), `hints` (a sentence in the site language).
 * Every part is stated by at least one of the `via` sources, so a policy is satisfiable by a reader of those sources.
 */
export interface PasswordPolicy {
  min?: number; max?: number;
  required?: ("upper" | "digit" | "special")[];
  noSpecial?: boolean;
  pattern?: string;
  via: ("attributes" | "passwordrules" | "hints")[];
}
export interface Site {
  index: number; seed: string; host: string; brand: string; lang: Lang; labelLang: Lang;
  flow: FlowId; traits: TraitId[];
  fields: FieldSpec[];            // fields of the flow's main form, in order
  steps?: FieldSpec[][];          // multi_step: the same fields split by page, one form per step
  framework?: FrameworkId;        // simulated front-end framework of the forms (absent = "static")
  layout?: LayoutId;              // label and field arrangement of the forms (absent = "stacked")
  buttons: { submit: string; next?: string; sso?: string; passkey?: string };
  passwordPolicy?: PasswordPolicy; // signup only: rules the relying party enforces (about 60 % of signup sites)
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
  forms?: SiteForms;              // forms flows only (generator version 4)
}
export type DriverId = "one_click" | "menu_fill" | "lookalike" | "passkey_control" | "smart_fill";
/** Driver sets a run plays: "current" (overlay, menu, lookalike, passkey control) and "smart_fill" (field icon, plan). */
export type DriverGroup = "current" | "smart_fill";
export type Expect = "pass" | "xfail" | "nofill";
/**
 * What the vault and the host are when the user's gesture happens: unlocked with the host running (the historical
 * start), vault locked (the lab's stand-in for Touch ID approves the unlock), or host not running (cold).
 */
export type StartState = "unlocked_warm" | "locked" | "cold";
export const START_STATES: readonly StartState[] = ["unlocked_warm", "locked", "cold"];
/** How the user starts OnePass: the field's icon, the toolbar Fill, the fill-smart shortcut, the overlay's account, ArrowDown in a field. */
export type Trigger = "field_icon" | "toolbar" | "shortcut" | "overlay_row" | "menu_key";
export interface Scenario {
  /**
   * "<site index>:<driver>", "<profile>:<site index>:<driver>" in a multi-profile world; then "/shortcut" for a
   * smart_fill started by the keyboard command and "@<start>" for a start state other than unlocked_warm.
   */
  id: string; site: number; driver: DriverId;
  expect: Expect; reason?: string;
  profile?: string;               // multi-profile worlds only (absent: the default profile)
  behaviour?: Behaviour;          // menu_fill under a non-default behaviour: judged on the fill, not on the user's later action
  start?: StartState;             // absent: unlocked_warm
  shortcut?: boolean;             // smart_fill started by the fill-smart command instead of the field's icon
  /** Account profiles (population.ts): the vault item the user means, the account that must sign in, the stated outcome. */
  account?: {
    title: string; username: string; outcome: string;
    /** The user signed in with it on this site before: the driver makes that site memory first. */
    lastUsed?: boolean;
  };
}
export interface IdpAccount { email: string; password: string; name: string; itemTitle: string; }
export interface FixtureFile { _comment: string; account: string; vaults: { name: string; color?: string }[]; items: unknown[]; }
export interface World {
  version: typeof GENERATOR_VERSION; seed: string; sites: Site[]; scenarios: Scenario[];
  idp: Record<ProviderId, IdpAccount[]>; fixture: FixtureFile; hosts: string[];
  /** Simulated users, only when more than one was asked (absent: the single default profile, vault = `fixture`). */
  profiles?: Profile[];
  /** Country and region fixture cases (lab/gen/cases.ts), played by the country-cases test. */
  cases?: CountryCase[];
}
