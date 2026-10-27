// Reply shapes of the background to the extension pages (menu, overlay,
// save prompt, popup). The pages validate every reply against these shapes
// before rendering (src/ui/parse.ts): a reply is data, never markup.
import type { Summary } from "../bridge/client";
import type { FormKind, ProviderId } from "./messages";

export type { Summary };

/** Stop reasons of a sign-in chain (spec 8.6). */
export type StopReason = "domain" | "captcha" | "push" | "otp" | "unknown" | "timeout" | "user" | "locked" | "repeat";

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
];

export type StepState = "pending" | "active" | "done" | "stopped";

export interface ChainStepView {
  label: string;
  detail?: string;
  state: StepState;
}

/** What the overlay shows of a chain; no secret in it. */
export interface ChainView {
  itemId: string;
  status: "running" | "done" | "stopped" | "handoff";
  steps: ChainStepView[];
  reason?: StopReason;
  /** Host that stopped the chain (`domain` reason). */
  host?: string;
}

export interface MenuInit {
  origin: string;
  formKind: FormKind;
  items: Summary[];
  /** On a provider's pages: the account linked to the site being signed in to ("Utilisé pour <site>"). */
  linked?: { itemId: string; site: string };
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
  provider?: { id: ProviderId; email: string };
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
