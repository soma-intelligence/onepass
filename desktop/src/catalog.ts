// The words and pictures shared with the iPhone app: the 26 categories in iOS
// order with their names (DesignKit's string catalog) and drawn tiles
// (assets/categories, imported by scripts/import-apple-assets.ps1), and the
// Watchtower checks with their exact titles and sentences.

// The language follows Windows (status.language); the web view's own
// language is only a first guess.
let french = (navigator.language || "fr").toLowerCase().startsWith("fr");
export function setFrench(v: boolean): void {
  french = v;
}
export const t = (fr: string, en: string): string => (french ? fr : en);

export interface Category {
  key: string;
  singular: string;
  plural: string;
}

const C = (key: string, sFr: string, sEn: string, pFr: string, pEn: string): Category => ({
  key,
  singular: t(sFr, sEn),
  plural: t(pFr, pEn),
});

export const categories = (): Category[] => [
  C("login", "Connexion", "Login", "Connexions", "Logins"),
  C("password", "Mot de passe", "Password", "Mots de passe", "Passwords"),
  C("email", "Compte email", "Email account", "Comptes email", "Email accounts"),
  C("server", "Serveur", "Server", "Serveurs", "Servers"),
  C("database", "Base de données", "Database", "Bases de données", "Databases"),
  C("router", "Routeur Wi-Fi", "Wi-Fi router", "Routeurs Wi-Fi", "Wi-Fi routers"),
  C("apiCredential", "Identifiant d'API", "API credential", "Identifiants API", "API credentials"),
  C("sshKey", "Clé SSH", "SSH key", "Clés SSH", "SSH keys"),
  C("creditCard", "Carte bancaire", "Credit card", "Cartes bancaires", "Credit cards"),
  C("bankAccount", "Compte bancaire", "Bank account", "Comptes bancaires", "Bank accounts"),
  C("cryptoWallet", "Portefeuille crypto", "Crypto wallet", "Portefeuilles crypto", "Crypto wallets"),
  C("subscription", "Abonnement", "Subscription", "Abonnements", "Subscriptions"),
  C("identity", "Identité", "Identity", "Identités", "Identities"),
  C("idCard", "Carte d'identité", "ID card", "Cartes d'identité", "ID cards"),
  C("passport", "Passeport", "Passport", "Passeports", "Passports"),
  C("driverLicense", "Permis de conduire", "Driver's license", "Permis de conduire", "Driver's licenses"),
  C("socialSecurityNumber", "Numéro de sécurité sociale", "Social Security number", "Numéros de sécu", "Social Security numbers"),
  C("medicalRecord", "Dossier médical", "Medical record", "Dossiers médicaux", "Medical records"),
  C("membership", "Adhésion", "Membership", "Cartes de membre", "Memberships"),
  C("rewardProgram", "Programme de fidélité", "Reward program", "Programmes de fidélité", "Reward programs"),
  C("insurance", "Assurance", "Insurance", "Assurances", "Insurance"),
  C("vehicle", "Véhicule", "Vehicle", "Véhicules", "Vehicles"),
  C("accessCode", "Code d'accès", "Access code", "Digicodes", "Access codes"),
  C("secureNote", "Note sécurisée", "Secure note", "Notes sécurisées", "Secure notes"),
  C("document", "Document", "Document", "Documents", "Documents"),
  C("softwareLicense", "Licence logicielle", "Software license", "Licences logicielles", "Software licenses"),
];

export function category(key: string): Category {
  return categories().find((c) => c.key === key) ?? { key, singular: key, plural: key };
}

/** The vault tile palette of the iPhone app. */
export const VAULT_COLORS: Record<string, string> = {
  blue: "#2F80ED",
  teal: "#13A09A",
  orange: "#E08A00",
  red: "#E5484D",
  purple: "#8E4EC6",
  green: "#22A06B",
  pink: "#DB2777",
  indigo: "#5856D6",
  gray: "#8E8E93",
};

export function vaultColor(name: string): string {
  const known = VAULT_COLORS[name];
  if (known) return known;
  const all = Object.values(VAULT_COLORS);
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) | 0;
  return all[Math.abs(h) % all.length]!;
}

export type Source = "local" | "breaches" | "sites" | "breachCatalog";

export interface WatchCard {
  id: string;
  checks: string[];
  title: string;
  message: string;
  icon: string;
  color: string;
  source: Source;
}

const W = (id: string, checks: string[], tFr: string, tEn: string, mFr: string, mEn: string, icon: string, color: string, source: Source): WatchCard => ({
  id,
  checks,
  title: t(tFr, tEn),
  message: t(mFr, mEn),
  icon,
  color,
  source,
});

export const watchCards = (): WatchCard[] => [
  W("compromised", ["compromised"], "Mots de passe compromis", "Compromised Passwords",
    "Ils apparaissent dans des fuites de données connues. Change-les en priorité.", "They appear in known data breaches. Change them first.",
    "compromised", "var(--red)", "breaches"),
  W("breached_site", ["breached_site"], "Sites piratés", "Breached sites",
    "Ces sites ont subi une fuite depuis ton dernier changement de mot de passe. Change-le sur chacun.",
    "These sites had a breach since you last changed your password. Change it on each one.", "breached", "var(--red)", "breachCatalog"),
  W("provider_exposed", ["provider_exposed"], "Comptes de connexion exposés", "Exposed sign-in accounts",
    "Un compte qui te sert à te connecter ailleurs est compromis, faible, réutilisé ou sans double authentification : tous les sites qui en dépendent sont exposés.",
    "An account you use to sign in elsewhere is compromised, weak, reused or without two-factor authentication: every site that depends on it is exposed.",
    "exposed", "var(--red)", "local"),
  W("reused", ["reused"], "Mots de passe réutilisés", "Reused Passwords",
    "Un même mot de passe sur plusieurs comptes : une seule fuite suffit à tous les ouvrir.", "One password on several accounts: a single breach opens them all.",
    "reused", "var(--orange)", "local"),
  W("weak", ["weak"], "Mots de passe faibles", "Weak Passwords",
    "Faciles à deviner. Remplace-les par des mots de passe générés.", "Easy to guess. Replace them with generated passwords.",
    "lock_open", "var(--orange)", "local"),
  W("passkey", ["passkey_available"], "Passkeys disponibles", "Passkeys Available",
    "Ces sites acceptent les passkeys, plus sûres et plus simples qu'un mot de passe.", "These sites support passkeys, safer and simpler than a password.",
    "passkey", "var(--accent)", "sites"),
  W("2fa", ["missing_2fa"], "Double authentification disponible", "Two-factor authentication available",
    "Ces sites proposent des codes à usage unique que tu n'as pas encore ajoutés.", "These sites offer one-time codes you haven’t added yet.",
    "two_factor", "var(--blue)", "sites"),
  W("http", ["insecure_url"], "Sites en HTTP", "HTTP Sites",
    "Ces adresses ne sont pas chiffrées. Passe-les en HTTPS si le site le permet.", "These addresses aren’t encrypted. Switch them to HTTPS if the site allows it.",
    "globe", "var(--yellow)", "local"),
  W("expiring", ["expired", "expiring"], "Éléments qui expirent", "Expiring Items",
    "Cartes, documents et licences expirés ou qui expirent dans les 30 jours.", "Cards, documents and licenses that expired or expire within 30 days.",
    "calendar_alert", "#FF2D55", "local"),
  W("wifi", ["wifi_insecure"], "Wi-Fi peu protégés", "Poorly protected Wi-Fi",
    "Ces réseaux utilisent WEP ou aucun chiffrement. Passe-les en WPA2 ou WPA3 sur le routeur.",
    "These networks use WEP or no encryption. Switch them to WPA2 or WPA3 on the router.", "wifi", "var(--orange)", "local"),
  W("ssh", ["ssh_weak"], "Clés SSH faibles", "Weak SSH keys",
    "Clés RSA de moins de 3 072 bits ou DSA. Remplace-les par une clé Ed25519.", "RSA keys under 3,072 bits, or DSA. Replace them with an Ed25519 key.",
    "terminal", "var(--orange)", "local"),
  W("wallet", ["wallet_no_backup"], "Portefeuilles sans sauvegarde", "Wallets without a backup",
    "Indique où est rangée la copie physique de la phrase de récupération de ces portefeuilles.",
    "Note where the physical copy of these wallets' recovery phrase is kept.", "archive", "var(--yellow)", "local"),
  W("duplicate", ["duplicate"], "Doublons", "Duplicates",
    "Même site et même identifiant dans plusieurs éléments. Garde-en un seul.", "Same site and same username in several items. Keep only one.",
    "duplicates", "#8E8E93", "local"),
  W("old", ["old_password"], "Vieux mots de passe", "Old Passwords",
    "Inchangés depuis plus d'un an. Pense à les renouveler.", "Unchanged for over a year. Consider renewing them.",
    "history", "#8E8E93", "local"),
  W("pending", ["pending_unused"], "Mot de passe en attente", "Pending password",
    "Mot de passe généré mais jamais confirmé depuis plus de 30 jours. L'inscription n'a sans doute pas abouti.",
    "Generated password never confirmed for over 30 days. The signup probably did not finish.", "hourglass", "#8E8E93", "local"),
];

export const ALERT_IDS = new Set(["compromised", "expiring", "breached_site", "provider_exposed"]);

export function scoreColor(score: number): string {
  if (score < 40) return "var(--red)";
  if (score < 60) return "var(--orange)";
  if (score < 80) return "var(--yellow)";
  return "var(--green)";
}

export function scoreLabel(score: number): string {
  if (score < 40) return t("Faible", "Weak");
  if (score < 60) return t("Moyen", "Fair");
  if (score < 80) return t("Bon", "Good");
  if (score < 95) return t("Excellent", "Excellent");
  return t("Fantastique", "Fantastic");
}

/** The strength meter's words, level 0 to 4 (thresholds 40, 60, 80, 100 bits). */
export const strengthWords = (): string[] => [t("Trop court", "Too short"), t("Faible", "Weak"), t("Moyen", "Fair"), t("Bon", "Good"), t("Excellent", "Excellent")];

export function strengthLevel(bits: number): number {
  return [40, 60, 80, 100].filter((x) => bits >= x).length;
}
