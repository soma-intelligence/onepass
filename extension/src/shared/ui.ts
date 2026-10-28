// Reply shapes of the background to the extension pages (menu, overlay,
// save prompt, popup). The pages validate every reply against these shapes
// before rendering (src/ui/parse.ts): a reply is data, never markup.
import type { Summary } from "../bridge/client";
import type { FormKind, ProviderId } from "./messages";

export type { Summary };

/** Stop reasons of a sign-in chain (spec 8.6). */
export type StopReason = "domain" | "captcha" | "push" | "otp" | "unknown" | "timeout" | "user" | "locked" | "repeat" | "account";

export const STOP_REASONS: readonly StopReason[] = [
  "domain",
  "captcha",
  "push",
  "otp",
  "unknown",
  "timeout",
  "user",
  "locked",
  "repeat",
  "account",
];

export type StepState = "pending" | "active" | "done" | "stopped";

/**
 * What a step did, for the page to word in its own language: clicked the
 * provider's button, chose the account, filled the username, the password,
 * both, or a one-time code; or the end (done, stop) the status line says.
 */
export type StepWhat = "click" | "account" | "user" | "password" | "both" | "otp" | "end";

export const STEP_WHATS: readonly StepWhat[] = ["click", "account", "user", "password", "both", "otp", "end"];

export interface ChainStepView {
  label: string;
  detail?: string;
  state: StepState;
  what?: StepWhat;
  /** The step acted on the provider's pages. */
  onProvider?: boolean;
}

/** What the overlay shows of a chain; no secret in it. */
export interface ChainView {
  itemId: string;
  status: "running" | "done" | "stopped" | "handoff";
  steps: ChainStepView[];
  reason?: StopReason;
  /** Host that stopped the chain (`domain` reason). */
  host?: string;
  /** Title of the item signing in ("Atlas Docs"). */
  title?: string;
  /** Registrable domain of the site the chain signs in to. */
  site?: string;
  /** Provider the chain signs in with, if any. */
  provider?: ProviderId;
  /** The account used: the provider account's email, or the item's username. */
  email?: string;
  /** While running: what happens now (the page words it: "Ouverture de Google…"). */
  phase?: ChainPhase;
}

/**
 * What a running chain does now: opening the provider, choosing the account
 * on its chooser, signing in to the provider, coming back to the site,
 * signing in to the site, checking a one-time code.
 */
export type ChainPhase = "opening" | "choosing" | "provider" | "back" | "signin" | "code";

export const CHAIN_PHASES: readonly ChainPhase[] = ["opening", "choosing", "provider", "back", "signin", "code"];

/** A provider account of the vault (its own login item), offered as a choice. */
export interface ProviderChoice {
  itemId: string;
  email: string;
  title: string;
}

/**
 * How an item signs in with one provider on this site: the account used by
 * default (the last one picked here, else the linked one) and every account
 * of that provider in the vault, for the inline picker.
 */
export interface SignInChoice {
  itemId: string;
  provider: ProviderId;
  /** Default account; absent when the vault has none for this method. */
  accountId?: string;
  accounts: ProviderChoice[];
}

export interface MenuInit {
  origin: string;
  formKind: FormKind;
  items: Summary[];
  /** On a provider's pages: the account linked to the site being signed in to ("Utilisé pour <site>"). */
  linked?: { itemId: string; site: string };
  /** Provider accounts per item method (sign-in forms only). */
  choices?: SignInChoice[];
}

/** One way to sign in offered by the overlay. */
export interface OverlayAccount {
  itemId: string;
  title: string;
  subtitle: string;
  iconLetter: string;
  iconColor: string;
  provider?: ProviderId;
  email?: string;
  /** Provider rows: the default account and the other accounts of that provider. */
  accountId?: string;
  accounts?: ProviderChoice[];
  /** Password rows: the item also fills a one-time code. */
  totp?: boolean;
}

export interface OverlayInit {
  origin: string;
  accounts: OverlayAccount[];
  chain: ChainView | null;
}

export interface SaveInit {
  origin: string;
  /** Registrable domain, as shown in "Ne jamais proposer pour <domaine>". */
  site: string;
  kind: "login" | "provider_link";
  status: "new" | "update";
  title: string;
  username: string;
  /** The login to update (status `update`). */
  update?: { itemId: string; title: string };
  vaults: { id: string; name: string }[];
  /** Provider link: the provider account (its own item) the site signs in with. */
  provider?: { id: ProviderId; email: string; title?: string };
  /** Open in the edit view, nothing typed yet (menu "Enregistrer un nouveau login"). */
  view?: "edit";
}

export interface PopupStatus {
  locked: boolean;
  account: string;
  vaults: number;
}

export interface PopupSuggestions {
  /** Host of the active tab, or null when it is not an HTTPS page. */
  domain: string | null;
  items: Summary[];
}

export interface PopupItem {
  summary: Summary;
  /** Origin the item was suggested for (the active tab), if any. */
  website?: string;
}

export type GeneratorKind = "smart" | "random" | "memorable" | "pin";

export interface GeneratorEntry {
  password: string;
  kind: GeneratorKind;
  at: number;
}
