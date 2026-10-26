import type { ProviderId } from "./messages";

export interface Provider {
  id: ProviderId;
  name: string;
  /** Official sign-in hosts: exact hosts, never registrable domains (spec 8.7). */
  hosts: string[];
}

export const PROVIDERS: readonly Provider[] = [
  { id: "google", name: "Google", hosts: ["accounts.google.com"] },
  { id: "apple", name: "Apple", hosts: ["appleid.apple.com", "idmsa.apple.com"] },
  {
    id: "microsoft",
    name: "Microsoft",
    hosts: ["login.microsoftonline.com", "login.live.com", "account.live.com"],
  },
  { id: "github", name: "GitHub", hosts: ["github.com"] },
  { id: "facebook", name: "Facebook", hosts: ["www.facebook.com", "m.facebook.com"] },
  { id: "x", name: "X", hosts: ["x.com", "twitter.com", "api.x.com"] },
  { id: "linkedin", name: "LinkedIn", hosts: ["www.linkedin.com"] },
  { id: "discord", name: "Discord", hosts: ["discord.com"] },
  { id: "slack", name: "Slack", hosts: ["slack.com"] },
];

/** Exact (case-insensitive, trailing dot ignored) match on an official host. */
export function providerForHost(host: string): ProviderId | null {
  const h = host.toLowerCase().replace(/\.+$/, "");
  if (h === "") return null;
  return PROVIDERS.find((p) => p.hosts.includes(h))?.id ?? null;
}

const PREFIX = "(?:continuer avec|se connecter avec|sign in with|continue with|log in with)";
const FILLER = "(?:(?:votre|your|mon|my|le|the|un|a|compte|account)\\s+)*";
const NAMES: readonly (readonly [ProviderId, string])[] = [
  ["google", "google"],
  ["apple", "apple"],
  ["microsoft", "microsoft"],
  ["github", "github"],
  ["facebook", "facebook"],
  ["x", "x|twitter"],
  ["linkedin", "linkedin"],
  ["discord", "discord"],
  ["slack", "slack"],
];
const BUTTON_PATTERNS = NAMES.map(
  ([id, alt]) =>
    [id, new RegExp(`${PREFIX}\\s+${FILLER}(?:${alt})(?:\\s+(?:id|account|compte))?[^\\p{L}\\p{N}]*$`, "u")] as const,
);

/**
 * Provider named by a "Continue with ..." style button label (French and
 * English). The provider name must end the label, so "Continue with Xbox"
 * or "Continue with phone x" never match "X".
 */
export function providerFromButtonText(text: string): ProviderId | null {
  const t = text.toLowerCase().replace(/\s+/g, " ").trim();
  if (t === "") return null;
  return BUTTON_PATTERNS.find(([, re]) => re.test(t))?.[0] ?? null;
}
