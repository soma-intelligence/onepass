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

// Button wording per language: the words before the provider's name, and the small words that
// may sit between ("your", "account"). French, English, Spanish, Italian, German, Portuguese, Dutch.
const PREFIX = [
  "continuer avec|se connecter avec|connexion avec",
  "sign in with|continue with|log in with|login with",
  "continuar con|iniciar sesi[oó]n con|inicia sesi[oó]n con|acceder con|accede con|entrar con|entra con",
  "continua con|accedi con|prosegui con",
  "weiter mit|anmelden mit|einloggen mit|fortfahren mit|anmelden [uü]ber",
  "continuar com|entrar com|iniciar sess[aã]o com|fazer login com|iniciar sess[aã]o com",
  "doorgaan met|inloggen met|aanmelden met|log in met|verder met|ga verder met|verdergaan met",
].join("|");
const FILLER = "(?:(?:votre|your|mon|my|le|the|un|a|compte|account|tu|su|mi|el|la|cuenta|de|il|tuo|suo|ihrem|deinem|dem|einem|o|sua|seu|conta|do|da|je|jouw|uw|mijn|het|een)\\s+)*";
/** After the name: "ID", "account" ("Google-Konto", "Microsoft-account"). */
const SUFFIX = "(?:[\\s-]+(?:id|account|compte|konto|cuenta|conta))?";
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
/** German puts the verb last: "Mit Google anmelden", "Über Apple anmelden". The name still stands alone before it. */
const GERMAN_TAIL = "(?:anmelden|einloggen|fortfahren|weiter|registrieren)";
const BUTTON_PATTERNS = NAMES.map(
  ([id, alt]) =>
    [
      id,
      new RegExp(
        `(?:^|[^\\p{L}\\p{N}])(?:(?:${PREFIX})\\s+${FILLER}(?:${alt})${SUFFIX}|(?:mit|[uü]ber)\\s+${FILLER}(?:${alt})${SUFFIX}\\s+${GERMAN_TAIL})[^\\p{L}\\p{N}]*$`,
        "u",
      ),
    ] as const,
);

/**
 * Provider named by a "Continue with ..." style button label (French, English, Spanish, Italian,
 * German, Portuguese, Dutch). The provider name must end the label (before the verb in German),
 * so "Continue with Xbox" or "Continue with phone x" never match "X".
 */
export function providerFromButtonText(text: string): ProviderId | null {
  const t = text.toLowerCase().replace(/\s+/g, " ").trim();
  if (t === "") return null;
  return BUTTON_PATTERNS.find(([, re]) => re.test(t))?.[0] ?? null;
}
