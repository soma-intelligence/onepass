// Cleon for Windows, laid out like the iPad and Mac app of the same
// codebase (sidebar, list, item) with the iPhone's look (DesignKit colors,
// cards, category tiles, Watchtower). Plain DOM, no framework. Every text
// from an item is set with textContent, never innerHTML (spec 2026-10-30
// section 3.2); a secret reaches the page only when the user reveals it.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ICON_PATHS as BASE_ICONS } from "./icons";
import { EXTRA_ICON_PATHS } from "./icons-extra";

const ICON_PATHS = { ...BASE_ICONS, ...EXTRA_ICON_PATHS };
type IconName = keyof typeof ICON_PATHS;
import {
  ALERT_IDS,
  VAULT_COLORS,
  categories,
  category,
  setFrench,
  strengthWords,
  scoreColor,
  scoreLabel,
  strengthLevel,
  t,
  vaultColor,
  watchCards,
  type WatchCard,
} from "./catalog";
import { categoryIdentity, currentWallpaper, identityColor, identityWash, isLightWallpaper, setWallpaper, wallpaperName, wallpaperThemes, wallpaperUrl, type Tone } from "./rx";

// ---- IPC types (mirror src-tauri/src/view.rs and commands.rs) -----------------

interface UiError {
  code: string;
  detail: string;
}
interface Status {
  state: "empty" | "locked" | "unlocked" | "missing" | "noDeviceFile";
  language: string;
  accountId: string | null;
  protection: string;
  autoLockMinutes: number;
  helloEnrolled: boolean;
  helloWanted: boolean;
  helloDropped: "expired" | "rebooted" | "invalidated" | null;
  helloDaysLeft: number | null;
  siteIcons: boolean;
}
interface HelloStatus {
  availability: "available" | "notConfigured" | "unavailable";
  wanted: boolean;
  enrolled: boolean;
  daysLeft: number | null;
}
interface Vault {
  id: string;
  name: string;
  icon: string;
  color: string;
  itemCount: number;
  /** A shared vault: this account's role. */
  sharedRole: "read" | "write" | "manage" | null;
  sharedOwner: boolean;
  memberCount: number;
}
interface Summary {
  id: string;
  vaultId: string;
  itemType: string;
  title: string;
  subtitle: string;
  favorite: boolean;
  primaryUrl: string | null;
  archived: boolean;
  trashed: boolean;
  trashedAt: number | null;
  updatedAt: number;
  tags: string[];
}
interface Field {
  id: string;
  label: string;
  kind: string;
  value: string | null;
  secret: boolean;
  hasValue: boolean;
  strength: number | null;
  data?: FieldInput;
  options: string[];
}
type FieldInput =
  | { type: "text"; value: string }
  | { type: "date"; year: number; month: number; day: number }
  | { type: "monthYear"; year: number; month: number }
  | { type: "address"; line1: string; line2: string; postalCode: string; city: string; region: string; country: string }
  | { type: "empty" };
interface Attachment {
  id: string;
  name: string;
  size: number;
  mime: string;
}
interface Section {
  id: string;
  label: string;
  fields: Field[];
}
interface Item {
  id: string;
  vaultId: string;
  itemType: string;
  title: string;
  favorite: boolean;
  notes: string;
  tags: string[];
  urls: { label: string; url: string; rule: string }[];
  sections: Section[];
  createdAt: number;
  updatedAt: number;
  trashed: boolean;
  archived: boolean;
  passwordHistoryCount: number;
  attachments: Attachment[];
  travelHidden: boolean;
  travelGuard: boolean;
}
interface Report {
  score: number;
  itemsAnalyzed: number;
  checks: { check: string; itemIds: string[] }[];
  strength: number[];
  pwned: "checked" | "partial" | "unavailable" | "disabled";
  sitesChecked: boolean;
  breachCatalog: boolean;
  checkBreaches: boolean;
  missingPrefixes: number;
}
interface Account {
  accountId: string;
  name: string;
  devices: DeviceInfo[];
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    const err = e as UiError;
    if (err && err.code === "Locked") void route();
    throw err;
  }
}

function message(e: unknown): string {
  const err = e as UiError;
  switch (err?.code) {
    case "WrongPassword":
      return t("Mot de passe incorrect.", "Incorrect password.");
    case "WeakPassword":
      return t("Pas encore assez solide : ajoute un mot, ou touche Générer.", "Not strong enough yet. Add a word, or tap Generate.");
    case "Locked":
      return t("Cleon est verrouillé.", "Cleon is locked.");
    case "Validation":
      return t("Un champ n'est pas valide : ", "A field is not valid: ") + err.detail;
    case "NotFound":
      return t("Élément introuvable.", "Item not found.");
    case "ContactNotVerified":
      return t("Vérifie d'abord ce contact en personne ou avec son numéro de sécurité.", "Verify this contact in person or with their safety number first.");
    case "ReadOnlyRole":
      return t("Tu peux seulement consulter ce coffre.", "You can only view this vault.");
    case "IdentityPending":
      return t("Un gestionnaire du coffre doit confirmer tes nouvelles clés avant que tu puisses modifier.", "A vault manager must confirm your new keys before you can make changes.");
    case "MembershipFork":
      return t("Le serveur a montré deux listes de membres différentes.", "The server showed two different member lists.");
    default:
      return err?.detail ?? String(e);
  }
}

// ---- DOM helpers ------------------------------------------------------------------

type Child = Node | string | null | undefined | false;

function h<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<Record<string, unknown>> = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") {
      el.addEventListener(k.slice(2).toLowerCase(), v as EventListener);
    } else if (k === "class") {
      el.className = String(v);
    } else if (k === "style") {
      el.setAttribute("style", String(v));
    } else if (k in el && k !== "list") {
      (el as unknown as Record<string, unknown>)[k] = v;
    } else {
      el.setAttribute(k, String(v));
    }
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    el.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return el;
}

const SVG = "http://www.w3.org/2000/svg";

/** A Material Symbol (assets generated by scripts/ui-icons.mjs), tinted by currentColor. */
function icon(name: IconName, size = 20, cls = ""): SVGSVGElement {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 -960 960 960");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", "glyph " + cls);
  const p = document.createElementNS(SVG, "path");
  p.setAttribute("d", ICON_PATHS[name]);
  svg.append(p);
  return svg;
}

/** A rounded colored square with a white glyph (the iPhone's SymbolTile). */
function tile(name: IconName, color: string, size = 28): HTMLElement {
  const el = h("span", { class: "tile", "aria-hidden": "true" }, icon(name, Math.round(size * 0.62)));
  el.style.width = el.style.height = size + "px";
  el.style.background = color;
  el.style.borderRadius = Math.round(size * 0.24) + "px";
  return el;
}

function art(type: string, size: number, favorite = false): HTMLElement {
  const box = h("span", { class: "art", "aria-hidden": "true" }, h("img", { src: `assets/categories/${type}.png`, alt: "", draggable: false }));
  box.style.width = box.style.height = size + "px";
  if (favorite) box.append(h("span", { class: "fav-badge" }, icon("star_fill", 10)));
  return box;
}

function monogram(text: string, color: string, size: number, round = false): HTMLElement {
  const el = h("span", { class: "monogram" + (round ? " round" : ""), "aria-hidden": "true" }, text);
  el.style.width = el.style.height = size + "px";
  el.style.fontSize = Math.round(size * 0.42) + "px";
  el.style.background = color;
  return el;
}

const initials = (name: string): string =>
  name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]!.toUpperCase())
    .join("") || "1";

const app = document.getElementById("app")!;
const toastEl = document.getElementById("toast")!;
let toastTimer: number | undefined;

function toast(text: string): void {
  toastEl.textContent = text;
  toastEl.hidden = false;
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => (toastEl.hidden = true), 2600);
}

const timers: number[] = [];
function stopTimers(): void {
  while (timers.length) window.clearInterval(timers.pop());
}

function mount(...nodes: Node[]): void {
  stopTimers();
  closeMenus();
  app.replaceChildren(...nodes);
}

const plural = (n: number, one: string, many: string): string => (n === 1 ? one : many.replace("%d", String(n)));
const countLabel = (n: number): string => plural(n, t("1 élément", "1 item"), t("%d éléments", "%d items"));
const dateTime = (s: number): string =>
  new Date(s * 1000).toLocaleString(t("fr-FR", "en-US"), { day: "numeric", month: "long", year: "numeric", hour: "2-digit", minute: "2-digit" });

/** Digits in blue, symbols in red, as the iPhone draws a password. */
function colored(p: string): DocumentFragment {
  const f = document.createDocumentFragment();
  for (const ch of p) {
    const cls = /[0-9]/.test(ch) ? "d" : /[\p{L}]/u.test(ch) ? "" : "s";
    f.append(cls ? h("span", { class: cls }, ch) : document.createTextNode(ch));
  }
  return f;
}

// ---- menus (popovers) and sheets -------------------------------------------------------

let openMenu: HTMLElement | null = null;
function closeMenus(): void {
  openMenu?.remove();
  openMenu = null;
}
document.addEventListener("mousedown", (e) => {
  if (openMenu && !openMenu.contains(e.target as Node)) closeMenus();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeMenus();
});

type MenuEntry = { label: string; icon: IconName; action: () => void; destructive?: boolean } | "separator";

function menu(anchor: HTMLElement, entries: MenuEntry[], align: "left" | "right" = "right"): void {
  closeMenus();
  const m = h("div", { class: "menu", role: "menu" });
  for (const e of entries) {
    if (e === "separator") {
      m.append(h("div", { class: "menu-sep" }));
      continue;
    }
    m.append(
      h(
        "button",
        {
          class: "menu-item" + (e.destructive ? " destructive" : ""),
          role: "menuitem",
          onclick: () => {
            closeMenus();
            e.action();
          },
        },
        h("span", {}, e.label),
        icon(e.icon, 18),
      ),
    );
  }
  // Inside the open sheet, if any: a modal dialog sits above the page.
  const dialogs = document.querySelectorAll("dialog[open]");
  (dialogs[dialogs.length - 1] ?? document.body).append(m);
  const r = anchor.getBoundingClientRect();
  const w = m.offsetWidth;
  m.style.top = Math.min(r.bottom + 6, window.innerHeight - m.offsetHeight - 8) + "px";
  m.style.left = Math.max(8, align === "right" ? r.right - w : r.left) + "px";
  openMenu = m;
}

interface Sheet {
  dialog: HTMLDialogElement;
  body: HTMLElement;
  close: () => void;
}

/** An iOS-style sheet: "Annuler" on the left, the title, the main action on the right. */
function sheet(title: string, opts: { cancel?: string; action?: string; onAction?: (s: Sheet) => void | Promise<void>; wide?: boolean; confirmCancel?: () => boolean } = {}): Sheet {
  const body = h("div", { class: "sheet-body" });
  const dialog = h("dialog", { class: "sheet" + (opts.wide ? " wide" : "") });
  const close = () => {
    dialog.close();
    dialog.remove();
  };
  const s: Sheet = { dialog, body, close };
  // "Annuler" with unsaved changes asks first, as the Apple editor does.
  const cancel = () => {
    if (!opts.confirmCancel?.()) return close();
    confirmSheet(t("Abandonner les modifications ?", "Discard changes?"), t("Abandonner", "Discard"), close, t("Continuer la modification", "Keep Editing"));
  };
  const bar = h(
    "div",
    { class: "sheet-bar" },
    h("button", { class: "bar-text", type: "button", onclick: cancel }, opts.cancel ?? t("Annuler", "Cancel")),
    h("div", { class: "sheet-title" }, title),
    opts.action
      ? h(
          "button",
          {
            class: "bar-text bold",
            type: "button",
            onclick: async () => {
              await opts.onAction?.(s);
            },
          },
          opts.action,
        )
      : h("span", { class: "bar-spacer" }),
  );
  dialog.append(bar, body);
  dialog.addEventListener("cancel", (e) => {
    e.preventDefault();
    cancel();
  });
  document.body.append(dialog);
  dialog.showModal();
  return s;
}

function confirmSheet(text: string, action: string, onYes: () => void, cancel?: string): void {
  const s = sheet("", { action, cancel, onAction: (sh) => (sh.close(), onYes()) });
  s.dialog.classList.add("alert");
  s.body.append(h("p", { class: "alert-text" }, text));
  (s.dialog.querySelector(".bar-text.bold") as HTMLElement).classList.add("destructive");
}

// ---- state -------------------------------------------------------------------------------

type Filter =
  | { kind: "all" }
  | { kind: "favorites" }
  | { kind: "vault"; id: string }
  | { kind: "category"; key: string }
  | { kind: "tag"; tag: string }
  | { kind: "archive" }
  | { kind: "trash" }
  | { kind: "ids"; ids: string[] };
type Page = { kind: "home" } | { kind: "watchtower" } | { kind: "duplicates" } | { kind: "list"; filter: Filter; title: string };

const ui = {
  vaults: [] as Vault[],
  items: [] as Summary[],
  report: null as Report | null,
  name: "",
  page: { kind: "home" } as Page,
  selected: null as string | null,
  query: "",
  /** Opened this session (Accueil "Récents"): memory only, emptied on lock. */
  recents: [] as string[],
  folded: new Set<string>(),
  duplicates: [] as DuplicateGroup[],
};

const active = (): Summary[] => ui.items.filter((i) => !i.trashed && !i.archived);

async function reload(): Promise<void> {
  const [vaults, items, account] = await Promise.all([call<Vault[]>("vaults"), call<Summary[]>("items"), call<Account>("account")]);
  ui.vaults = vaults;
  ui.items = items;
  ui.name = account.name;
  ui.report = null;
  ui.duplicates = await call<DuplicateGroup[]>("duplicate_groups").catch(() => []);
  await loadSharing();
  await loadSiteIcons();
  void loadReport();
}

let reportLoading = false;
/** True while the breach lookups run (the online pass). */
let checkingBreaches = false;

/** The offline report at once, then, with "Vérifier les fuites" on, the one
 * with the catalogs and the Have I Been Pwned ranges (as on the iPhone). */
async function loadReport(): Promise<void> {
  if (reportLoading) return;
  reportLoading = true;
  const redraw = () => {
    if (ui.page.kind !== "list") renderMain();
    renderSidebar();
  };
  try {
    ui.report = await call<Report>("watchtower", { online: false });
    if (ui.report.checkBreaches) {
      checkingBreaches = true;
      redraw();
      ui.report = await call<Report>("watchtower", { online: true });
    }
  } catch {
    /* the page says "Analyse…" */
  } finally {
    checkingBreaches = false;
    reportLoading = false;
    if (ui.report) redraw();
  }
}

// ---- routing --------------------------------------------------------------------

async function route(): Promise<void> {
  let status: Status;
  try {
    status = await invoke<Status>("status");
    setFrench(status.language === "fr");
  } catch (e) {
    mount(problem(t("Cleon n'a pas pu lire son coffre.", "Cleon could not read its vault."), message(e)));
    return;
  }
  switch (status.state) {
    case "empty":
      mount(intro(0));
      break;
    case "locked":
      mount(lockScreen(status));
      break;
    case "unlocked":
      await shell();
      break;
    case "noDeviceFile":
      mount(problem(t("Les secrets de cet appareil sont introuvables.", "This device's secrets are missing."),
        t("Le coffre existe sur ce PC mais pas le fichier qui garde sa Secret Key. La restauration par l'Emergency Kit arrive dans une prochaine version.",
          "The vault exists on this PC but not the file that keeps its Secret Key. Restoring from the Emergency Kit comes in a later version.")));
      break;
    case "missing":
      mount(problem(t("Le compte de cet appareil a disparu du coffre.", "This device's account is gone from the vault."),
        t("C'est une anomalie d'intégrité : Cleon ne crée pas de compte par-dessus.", "That is an integrity fault: Cleon does not create an account over it.")));
      break;
  }
}

function appIcon(size: number): HTMLElement {
  const img = h("img", { class: "app-icon", src: "assets/app-icon.png", alt: "", draggable: false });
  img.style.width = img.style.height = size + "px";
  return img;
}

function problem(title: string, detail: string): HTMLElement {
  return h("div", { class: "center" }, h("div", { class: "column" }, appIcon(88), h("h1", {}, title), h("p", { class: "secondary" }, detail)));
}

// ---- intro, welcome, create ----------------------------------------------------------------

const introCards = (): { icon: IconName; title: string; body: string }[] => [
  { icon: "key", title: t("Tous tes mots de passe, au même endroit", "All your passwords in one place"),
    body: t("Cleon les retient pour toi et les remplit quand tu te connectes.", "Cleon remembers them for you and fills them in when you sign in.") },
  { icon: "lock", title: t("Toi seul as la clé", "Only you hold the key"),
    body: t("Pas de compte chez nous. Ton coffre est chiffré sur ton appareil, et même nous ne pouvons pas l'ouvrir.",
      "No account with us. Your vault is encrypted on your device, and even we can't open it.") },
  { icon: "shield_check", title: t("Sur tous tes appareils", "On all your devices"),
    body: t("Ton coffre chiffré se synchronise avec tes autres appareils, sans compte chez nous.",
      "Your encrypted vault syncs with your other devices, with no account with us.") },
];

function intro(step: number): HTMLElement {
  const INTRO = introCards();
  const card = INTRO[step]!;
  const last = step === INTRO.length - 1;
  return h(
    "div",
    { class: "center intro" },
    h("button", { class: "bar-text skip", onclick: () => mount(welcome()) }, t("Passer", "Skip")),
    h(
      "div",
      { class: "column" },
      tile(card.icon, "var(--accent)", 96),
      h("h1", { class: "big" }, card.title),
      h("p", { class: "secondary lead" }, card.body),
      h("div", { class: "dots" }, ...INTRO.map((_, i) => h("span", { class: i === step ? "on" : "" }))),
      h("button", { class: "capsule prominent wide", onclick: () => mount(last ? welcome() : intro(step + 1)) }, last ? t("Commencer", "Get Started") : t("Continuer", "Continue")),
    ),
  );
}

function welcome(): HTMLElement {
  const option = (ic: IconName, color: string, title: string, detail: string, onclick: () => void) =>
    h("button", { class: "row", onclick }, tile(ic, color, 36), h("span", { class: "row-text" }, h("span", { class: "row-title" }, title), h("span", { class: "row-sub" }, detail)), icon("chevron_right", 18, "chev"));
  return h(
    "div",
    { class: "center" },
    h(
      "div",
      { class: "column" },
      appIcon(88),
      h("h1", { class: "big" }, t("Bienvenue dans Cleon", "Welcome to Cleon")),
      h("p", { class: "secondary lead" }, t("Comment veux-tu commencer ?", "How would you like to start?")),
      h(
        "div",
        { class: "card list-card" },
        option("vault_new", "var(--accent)", t("Créer un coffre", "Create a Vault"), t("Première fois sur Cleon", "First time on Cleon"), () => mount(create())),
        option("person_add", "var(--blue)", t("Ajouter cet appareil", "Add This Device"), t("Avec un code, depuis ton autre appareil", "With a code from your other device"), () => mount(joinScreen())),
        option("restore", "var(--orange)", t("Restaurer avec mon Emergency Kit", "Restore with My Emergency Kit"), t("Aucun autre appareil sous la main", "No other device at hand"), () => mount(restoreScreen())),
      ),
    ),
  );
}

function secretInput(id: string, placeholder: string, autocomplete: string): { box: HTMLElement; input: HTMLInputElement } {
  const input = h("input", { id, type: "password", placeholder, autocomplete, spellcheck: false, "aria-label": placeholder });
  const eye = h("button", { class: "icon-button", type: "button", title: t("Afficher le mot de passe", "Show Password") }, icon("eye", 20));
  eye.addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    eye.replaceChildren(icon(show ? "eye_off" : "eye", 20));
    eye.title = show ? t("Masquer le mot de passe", "Hide Password") : t("Afficher le mot de passe", "Show Password");
  });
  return { box: h("div", { class: "secret-box" }, input, eye), input };
}

function meter(bits: number): HTMLElement {
  const level = strengthLevel(bits);
  const color = level <= 1 ? "var(--red)" : level === 2 ? "var(--orange)" : "var(--green)";
  const segs = h("span", { class: "segs" });
  for (let i = 0; i < 4; i++) {
    const s = h("span");
    if (i < level) s.style.background = color;
    segs.append(s);
  }
  return h("span", { class: "meter" }, segs, h("span", { class: "meter-label" }, strengthWords()[level]!));
}

function create(): HTMLElement {
  const name = h("input", { id: "name", placeholder: t("Ton prénom (facultatif)", "Your first name (optional)"), autocomplete: "given-name" });
  const a = secretInput("pw", t("Mot de passe maître", "Master Password"), "new-password");
  const b = secretInput("pw2", t("Confirme ton mot de passe", "Confirm your password"), "new-password");
  const meterBox = h("div", { class: "meter-row" });
  const err = h("div", { class: "error", role: "alert" });
  a.input.addEventListener("input", async () => {
    const p = a.input.value;
    meterBox.replaceChildren();
    if (p) meterBox.append(meter(await call<number>("strength", { password: p }).catch(() => 0)));
  });
  const go = h("button", { class: "capsule prominent", type: "submit" }, t("Créer un coffre", "Create a Vault"));
  // "Où est rangé mon coffre ?" (D.2, point 1): the Cleon server unless the user picks theirs.
  const whereLink = h("button", { class: "bar-text where", type: "button", id: "sync-choice" });
  const whereLabel = () => (whereLink.textContent = t(`Où est rangé mon coffre ? ${choiceName(syncChoice)}`, `Where Is My Vault Kept? ${choiceName(syncChoice)}`));
  whereLabel();
  whereLink.addEventListener("click", () => syncChoiceSheet(syncChoice, (c) => ((syncChoice = c), whereLabel())));
  const generate = h(
    "button",
    {
      class: "capsule",
      type: "button",
      onclick: async () => {
        const g = await call<{ password: string }>("generate_password", { recipe: { kind: "words", count: 5, french: t("fr", "en") === "fr", capitalize: false } });
        a.input.type = b.input.type = "text";
        a.input.value = b.input.value = g.password;
        a.input.dispatchEvent(new Event("input"));
      },
    },
    t("Générer", "Generate"),
  );
  const form = h(
    "form",
    {
      class: "column left",
      onsubmit: async (ev: Event) => {
        ev.preventDefault();
        err.textContent = "";
        if (a.input.value !== b.input.value) {
          err.textContent = t("Les deux saisies doivent être identiques.", "Both entries must match.");
          return;
        }
        let bits = 0;
        try {
          bits = await call<number>("strength", { password: a.input.value });
        } catch (e) {
          err.textContent = message(e);
          return;
        }
        if (a.input.value.length < 10 || bits < 60) {
          err.textContent = t("Pas encore assez solide : ajoute un mot, ou touche Générer.", "Not strong enough yet. Add a word, or tap Generate.");
          return;
        }
        go.disabled = true;
        go.textContent = t("Création du coffre...", "Creating Vault...");
        try {
          const created = await call<{ secretKey: string }>("create_account", { password: a.input.value, sync: syncChoice });
          a.input.value = b.input.value = "";
          if (name.value.trim()) await call("set_profile_name", { name: name.value.trim() }).catch(() => {});
          mount(secretKeyScreen(created.secretKey));
        } catch (e) {
          err.textContent = message(e);
          go.disabled = false;
          go.textContent = t("Créer un coffre", "Create a Vault");
        }
      },
    },
    h("h1", { class: "big" }, t("Ton mot de passe maître", "Your master password")),
    h("p", { class: "secondary" }, t("Il ouvre ton coffre. Personne ne peut le retrouver pour toi : ni nous, ni personne.", "It opens your vault. Nobody can recover it for you: not us, not anyone.")),
    h("div", { class: "field-box" }, name),
    a.box,
    meterBox,
    b.box,
    err,
    h("p", { class: "footnote" }, t("Conseil : cinq mots tirés au hasard (« tapis-orage-girafe-violon-nuage ») sont plus solides et plus faciles à retenir qu'un mot compliqué. « Générer » en tire cinq pour toi.",
      "Tip: five random words (“carpet-storm-giraffe-violin-cloud”) are stronger and easier to remember than one complicated word. “Generate” picks five for you.")),
    h("div", { class: "buttons-row" }, generate, go),
    whereLink,
    h("button", { class: "bar-text", type: "button", onclick: () => mount(welcome()) }, t("Retour", "Back")),
  );
  queueMicrotask(() => a.input.focus());
  return h("div", { class: "center" }, form);
}

function secretKeyScreen(secretKey: string): HTMLElement {
  const ok = h("input", { type: "checkbox", id: "ok" });
  const next = h("button", { class: "capsule prominent", disabled: true, onclick: () => void route() }, t("Continuer", "Continue"));
  ok.addEventListener("change", () => (next.disabled = !ok.checked));
  return h(
    "div",
    { class: "center" },
    h(
      "div",
      { class: "column left" },
      h("h1", { class: "big" }, t("Ton Emergency Kit", "Your Emergency Kit")),
      h("p", { class: "secondary" }, t("Ce kit plus ton mot de passe maître donnent un accès complet à ton coffre. Recopie la Secret Key sur papier et range la feuille hors ligne ; ne la photographie pas. Ce PC la garde scellée par Windows.",
        "This kit plus your master password give full access to your vault. Copy the Secret Key on paper and keep the sheet offline; don't photograph it. This PC keeps it sealed by Windows.")),
      h("div", { class: "secret-key-card" }, h("div", { class: "caps accent" }, "SECRET KEY"), h("div", { class: "secret-key" }, secretKey)),
      h("label", { class: "check", for: "ok" }, ok, t("Coche la case une fois ta Secret Key rangée.", "Check the box once your Secret Key is stored safely.")),
      next,
    ),
  );
}

// ---- lock ---------------------------------------------------------------------------------

const HELLO = "Windows Hello";

function helloReason(reason: Status["helloDropped"]): string {
  switch (reason) {
    case "expired":
      return t("Le mot de passe maître est demandé régulièrement.", "Your master password is required from time to time.");
    case "rebooted":
      return t("Le mot de passe maître est demandé après un redémarrage.", "Your master password is required after a restart.");
    case "invalidated":
      return t("La biométrie a changé : saisis ton mot de passe maître.", "Biometrics changed. Enter your master password.");
    default:
      return "";
  }
}

/** Set by "Verrouiller": the next lock screen does not prompt Windows Hello by itself. */
let lockedByHand = false;

function lockScreen(status: Status): HTMLElement {
  const { box, input } = secretInput("pw", t("Mot de passe maître", "Master Password"), "current-password");
  const err = h("div", { class: "error", role: "alert" });
  const go = h("button", { class: "go", type: "submit", title: t("Déverrouiller", "Unlock"), "aria-label": t("Déverrouiller", "Unlock") }, icon("arrow_forward", 20));
  const hint = h("p", { class: "footnote center-text hello-hint" });
  if (status.helloDropped) err.textContent = helloReason(status.helloDropped);
  else if (status.helloWanted && !status.helloEnrolled) hint.textContent = t(`Déverrouille une fois avec ton mot de passe : Cleon te proposera ${HELLO}.`, `Unlock once with your password: Cleon will offer ${HELLO}.`);
  if (status.helloEnrolled) {
    const days = status.helloDaysLeft ?? 14;
    const tip = t(`Déverrouiller avec ${HELLO}`, `Unlock with ${HELLO}`);
    const reminder = days === 1
      ? t("Mot de passe maître redemandé dans 1 jour, puis tous les 14 jours.", "Master password required again in 1 day, then every 14 days.")
      : t(`Mot de passe maître redemandé dans ${days} jours, puis tous les 14 jours.`, `Master password required again in ${days} days, then every 14 days.`);
    const hello = h("button", { class: "icon-button hello", type: "button", title: `${tip}. ${reminder}`, "aria-label": tip }, icon("fingerprint", 22));
    const helloUnlock = async () => {
      err.textContent = "";
      hello.disabled = true;
      try {
        await call("unlock_with_hello");
        await route();
      } catch (e) {
        const code = (e as UiError).code;
        if (code === "HelloDropped") {
          const now = await invoke<Status>("status").catch(() => null);
          err.textContent = helloReason(now?.helloDropped ?? null) || t("Saisis ton mot de passe maître.", "Enter your master password.");
          hello.remove();
          input.focus();
        } else if (code !== "HelloNotConfirmed") {
          err.textContent = message(e);
        }
        hello.disabled = false;
      }
    };
    hello.addEventListener("click", () => void helloUnlock());
    box.append(hello);
    // Offered first, as Face ID is on the iPhone; not right after "Verrouiller".
    if (!lockedByHand) queueMicrotask(() => void helloUnlock());
  }
  lockedByHand = false;
  box.append(go);
  const form = h(
    "form",
    {
      class: "column",
      onsubmit: async (ev: Event) => {
        ev.preventDefault();
        if (!input.value) return;
        err.textContent = "";
        go.disabled = true;
        box.classList.remove("bad");
        try {
          await call("unlock", { password: input.value });
          input.value = "";
          await route();
        } catch (e) {
          err.textContent = (e as UiError).code === "WrongPassword" ? t("Mot de passe incorrect. Tu peux réessayer.", "Incorrect password. You can try again.") : message(e);
          box.classList.add("bad");
          input.select();
          go.disabled = false;
        }
      },
    },
    appIcon(96),
    h("div", { id: "lock-alerts" }),
    h("h1", {}, t("Déverrouille Cleon", "Unlock Cleon")),
    h("div", { class: "account-capsule" }, monogram("1", "var(--accent)", 26, true), h("span", {}, t("Compte Cleon", "Cleon Account"))),
    box,
    err,
    hint,
    h("p", { class: "footnote center-text" },
      t(`Verrouillage automatique après ${status.autoLockMinutes} min. Clés de l'appareil protégées par ${status.protection === "dpapi" ? "Windows (DPAPI)" : status.protection}.`,
        `Auto-lock after ${status.autoLockMinutes} min. Device keys protected by ${status.protection === "dpapi" ? "Windows (DPAPI)" : status.protection}.`)),
  );
  queueMicrotask(() => input.focus());
  queueMicrotask(() => void showLockAlerts());
  return h("div", { class: "center" }, form);
}

/** A recovery asked by an organizer shows locked too (spec 11.5). */
async function showLockAlerts(): Promise<void> {
  const box = document.getElementById("lock-alerts");
  if (!box) return;
  recoveryAlerts = await call<RecoveryAlertInfo[]>("recovery_alerts").catch(() => []);
  box.replaceChildren(...recoveryAlerts.map((a) => recoveryAlertCard(a, () => void showLockAlerts())));
}

async function lockNow(): Promise<void> {
  lockedByHand = true;
  await call("lock");
  resetSession();
  await route();
}

function resetSession(): void {
  ui.selected = null;
  ui.recents = [];
  ui.report = null;
  ui.page = { kind: "home" };
  for (const d of document.querySelectorAll("dialog")) d.remove();
  closeMenus();
}

// ---- shell -------------------------------------------------------------------------------

const sidebarEl = h("nav", { class: "sidebar", "aria-label": "Cleon" });
const mainEl = h("div", { class: "main" });

async function shell(): Promise<void> {
  try {
    await reload();
  } catch (e) {
    mount(problem(t("Impossible d'ouvrir le coffre.", "Could not open the vault."), message(e)));
    return;
  }
  mount(h("div", { class: "shell" }, sidebarEl, mainEl));
  renderSidebar();
  renderMain();
}

function go(page: Page): void {
  ui.page = page;
  ui.query = "";
  if (page.kind !== "list") ui.selected = null;
  else ui.selected = listed()[0]?.id ?? null;
  renderSidebar();
  renderMain();
}

function samePage(a: Page, b: Page): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function renderSidebar(): void {
  const live = active();
  const nav = (label: string, lead: Node, count: number | string | null, page: Page) =>
    h(
      "button",
      { class: "nav" + (samePage(page, ui.page) ? " active" : ""), onclick: () => go(page) },
      lead,
      h("span", { class: "nav-label" }, label),
      count === null ? null : h("span", { class: "count" }, String(count)),
    );
  // RX (RXMacSidebar): the account row sits at the foot of the sidebar, its menu opening upwards.
  const account = h(
    "button",
    { class: "account", title: t("Compte", "Account") },
    monogram(initials(ui.name), "var(--accent)", 32, true),
    h("span", { class: "account-text" },
      h("span", { class: "account-name" }, ui.name || t("Mon compte", "My account")),
      h("span", { class: "account-sub" }, t("Appareil personnel", "Personal Device"))),
    icon("chevron_down", 16, "tertiary"),
  );
  account.addEventListener("click", () =>
    menu(account, [
      { label: t("Réglages", "Settings"), icon: "settings", action: () => openSettings() },
      { label: t("Nouveau coffre", "New Vault"), icon: "vault_new", action: () => vaultEditor(null) },
      { label: t("Générateur", "Generator"), icon: "wand", action: () => generator(null) },
      "separator",
      { label: t("Verrouiller", "Lock"), icon: "lock", action: () => void lockNow(), destructive: true },
    ], "left"),
  );
  const score = ui.report?.score;
  const cats = categories().filter((c) => live.some((i) => i.itemType === c.key));
  const tags = [...new Set(live.flatMap((i) => i.tags))].sort((a, b) => a.localeCompare(b));
  // RX rows (RXMacSidebar): a 20 px glyph in the row's colour, no tile behind it.
  const glyph = (name: IconName, color: string) => {
    const g = h("span", { class: "nav-glyph" }, icon(name, 18));
    g.style.color = color;
    return g;
  };
  const allItems = { kind: "list", filter: { kind: "all" }, title: t("Tous les éléments", "All Items") } as Page;
  const search = h("button", { class: "side-search", title: t("Rechercher", "Search"), onclick: () => {
    go(allItems);
    (document.querySelector(".search-input") as HTMLInputElement | null)?.focus();
  } }, icon("search", 18), h("span", {}, t("Rechercher", "Search")), h("kbd", {}, "Ctrl F"));
  sidebarEl.replaceChildren(
    h("div", { class: "sidebar-top" },
      h("div", { class: "brand" }, h("span", { class: "brand-glyph" }, icon("grid", 16)), h("span", { class: "brand-name" }, "Cleon"),
        h("button", { class: "round", title: t("Nouvel élément", "New Item"), "aria-label": t("Nouvel élément", "New Item"), onclick: () => newItem() }, icon("add", 18))),
      search),
    h(
      "div",
      { class: "sidebar-scroll" },
      nav(t("Accueil", "Home"), glyph("home_fill", "var(--accent)"), null, { kind: "home" }),
      nav(t("Tous les éléments", "All Items"), glyph("grid", "var(--accent)"), live.length, allItems),
      nav(t("Favoris", "Favorites"), glyph("star_fill", "var(--orange)"), live.filter((i) => i.favorite).length, { kind: "list", filter: { kind: "favorites" }, title: t("Favoris", "Favorites") }),
      nav("Watchtower", glyph("watchtower", "#E14D3C"), score ?? null, { kind: "watchtower" }),
      ui.duplicates.length || ui.page.kind === "duplicates" ? nav(t("Doublons possibles", "Possible Duplicates"), glyph("duplicates", "var(--orange)"), ui.duplicates.length, { kind: "duplicates" }) : null,
      h("h3", {}, t("Coffres", "Vaults"), h("button", { class: "section-add", title: t("Nouveau coffre", "New Vault"), "aria-label": t("Nouveau coffre", "New Vault"), onclick: () => vaultEditor(null) }, icon("add", 14))),
      ...ui.vaults
        .slice()
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((v) => {
          const b = nav(v.name, monogram(v.name.slice(0, 1).toUpperCase(), vaultColor(v.color), 20, true), live.filter((i) => i.vaultId === v.id).length, { kind: "list", filter: { kind: "vault", id: v.id }, title: v.name });
          if (v.sharedRole) b.querySelector(".nav-label")!.after(h("span", { class: "shared-mark", title: t("Partagé", "Shared") }, icon("share", 14, "secondary")));
          return b;
        }),
      cats.length ? h("h3", {}, t("Catégories", "Categories")) : null,
      ...cats.map((c) => nav(c.plural, art(c.key, 20), live.filter((i) => i.itemType === c.key).length, { kind: "list", filter: { kind: "category", key: c.key }, title: c.plural })),
      tags.length ? h("h3", {}, "Tags") : null,
      ...tags.map((tag) => nav(tag, h("span", { class: "nav-glyph" }, h("i", { class: "tag-dot" })), live.filter((i) => i.tags.includes(tag)).length, { kind: "list", filter: { kind: "tag", tag }, title: tag })),
      h("h3", {}, t("Plus", "More")),
      nav(t("Archive", "Archive"), glyph("archive", "var(--secondary)"), ui.items.filter((i) => i.archived && !i.trashed).length, { kind: "list", filter: { kind: "archive" }, title: t("Archive", "Archive") }),
      nav(t("Supprimés récemment", "Recently Deleted"), glyph("trash", "var(--secondary)"), ui.items.filter((i) => i.trashed).length, { kind: "list", filter: { kind: "trash" }, title: t("Supprimés récemment", "Recently Deleted") }),
    ),
    h("div", { class: "sidebar-foot" }, account),
  );
}

function renderMain(): void {
  stopTimers();
  const p = ui.page;
  if (p.kind === "home") mainEl.replaceChildren(homePage());
  else if (p.kind === "watchtower") mainEl.replaceChildren(watchtowerPage());
  else if (p.kind === "duplicates") mainEl.replaceChildren(duplicatesPage());
  else {
    mainEl.replaceChildren(h("div", { class: "split" }, listPane(p), detailEl));
    void renderDetail();
  }
}

// ---- Accueil ------------------------------------------------------------------------------

function homePage(): HTMLElement {
  const live = active();
  const first = ui.name.split(/\s+/).find(Boolean);
  const greeting = first ? t(`Bonjour ${first}`, `Hi ${first}`) : t("Bonjour", "Hi");
  const byId = new Map(live.map((i) => [i.id, i]));
  const r = ui.report;
  const score = r?.score;

  // RX hero (RXMacHome): the wallpaper picked in Réglages, two veils, the state in words.
  const wp = currentWallpaper();
  const light = isLightWallpaper(wp);
  const status = score === undefined ? t("Vérification…", "Checking…")
    : score >= 80 ? t("Tout va bien", "All Good") : score >= 60 ? t("Presque parfait", "Almost There") : t("À vérifier", "Needs a Look");
  const chip = h("span", { class: "glass-chip score-chip" + (score === undefined ? " pending" : "") },
    icon("watchtower", 16), h("b", {}, t("Score", "Score")), h("b", {}, String(score ?? 100), h("span", { class: "dim" }, "/100")));
  (chip.firstChild as SVGElement).style.color = score === undefined ? "inherit" : scoreColor(score);
  const words = h("button", { class: "hero-words", onclick: () => go({ kind: "watchtower" }), "aria-label": `${greeting}. ${status}` },
    h("span", { class: "hero-greeting" }, greeting),
    h("span", { class: "hero-status" }, status),
    h("span", { class: "hero-chips" }, chip, h("span", { class: "hero-count" }, countLabel(live.length))));
  const hero = h("section", { class: "hero" + (light ? " light" : "") },
    h("img", { class: "hero-photo", src: wallpaperUrl(wp), alt: "", draggable: false }),
    h("div", { class: "hero-veil" }),
    h("div", { class: "hero-body" }, words,
      h("div", { class: "hero-actions" },
        h("button", { class: "hero-primary", onclick: () => newItem() }, icon("add", 18), t("Nouvel élément", "New Item")),
        h("button", { class: "glass-capsule", onclick: () => generator(null) }, icon("wand", 18), t("Générer", "Generate")))));

  const cardHead = (title: string, page?: Page) =>
    h("div", { class: "rx-card-head" }, h("span", {}, title), page ? h("button", { class: "see-all", onclick: () => go(page) }, t("Tout voir", "See All")) : null);
  const homeRow = (lead: Node, title: string, sub: string, trailing: Node | null, onclick: () => void) =>
    h("button", { class: "home-row", onclick }, lead, h("span", { class: "row-text" }, h("span", { class: "row-title" }, title), sub ? h("span", { class: "row-sub" }, sub) : null), trailing);

  const recentCount = Math.min(6, Math.max(3, ui.vaults.length));
  const recents = ui.recents.map((id) => byId.get(id)).filter((s): s is Summary => !!s).slice(0, recentCount);
  const recentsCard = h("div", { class: "rx-card" }, cardHead(t("Récents", "Recents")),
    recents.length
      ? h("div", { class: "rx-rows" }, ...recents.map((s) => homeRow(itemArt(s, 32), s.title || t("Sans titre", "Untitled"), secondLine(s), null, () => openItem(s))))
      : h("p", { class: "rx-empty" }, t("Les éléments ouverts apparaissent ici jusqu'au verrouillage.", "Items you open appear here until Cleon locks.")));
  const vaultsCard = h("div", { class: "rx-card" }, cardHead(t("Coffres", "Vaults")),
    h("div", { class: "rx-rows" }, ...ui.vaults.slice().sort((a, b) => a.name.localeCompare(b.name)).map((v) =>
      homeRow(monogram(v.name.slice(0, 1).toUpperCase(), vaultColor(v.color), 32), v.name, countLabel(live.filter((i) => i.vaultId === v.id).length),
        icon("chevron_right", 16, "tertiary"), () => go({ kind: "list", filter: { kind: "vault", id: v.id }, title: v.name })))));

  const favs = live.filter((i) => i.favorite).sort((a, b) => a.title.localeCompare(b.title));
  const strip = h("div", { class: "fav-strip" }, ...favs.map((s) =>
    h("button", { class: "fav-tile", onclick: () => openItem(s), title: s.title }, h("span", { class: "fav-art" }, itemArt(s, 40)), h("span", { class: "fav-title" }, s.title || t("Sans titre", "Untitled")))));
  const favCard = h("div", { class: "rx-card" }, cardHead(t("Favoris", "Favorites"), { kind: "list", filter: { kind: "favorites" }, title: t("Favoris", "Favorites") }),
    favs.length ? strip : h("p", { class: "rx-empty" }, t("Touche l'étoile d'un élément pour le retrouver ici.", "Tap an item's star to find it here.")));

  const empty = live.length ? null : h("div", { class: "rx-card empty-state" },
    h("h2", {}, t("Ton coffre est vide", "Your Vault Is Empty")),
    h("p", { class: "secondary" }, t("Mots de passe, cartes, identités, notes : tout ce que tu ranges ici est chiffré sur tes appareils.", "Passwords, cards, identities, notes: everything you keep here is encrypted on your devices.")),
    h("button", { class: "capsule prominent", onclick: () => newItem() }, t("Créer ton premier élément", "Create Your First Item")));

  return h("div", { class: "page rx-home" },
    h("h1", { class: "rx-title" }, t("Accueil", "Home")),
    hero,
    sharingBanners(),
    empty,
    live.length ? h("div", { class: "rx-pair" }, recentsCard, vaultsCard) : null,
    live.length ? favCard : null);
}

function openItem(s: Summary): void {
  ui.page = { kind: "list", filter: { kind: "all" }, title: t("Tous les éléments", "All Items") };
  if (s.trashed) ui.page = { kind: "list", filter: { kind: "trash" }, title: t("Supprimés récemment", "Recently Deleted") };
  else if (s.archived) ui.page = { kind: "list", filter: { kind: "archive" }, title: t("Archive", "Archive") };
  ui.selected = s.id;
  ui.query = "";
  renderSidebar();
  renderMain();
}

// ---- lists -----------------------------------------------------------------------------------

function listed(): Summary[] {
  if (ui.page.kind !== "list") return [];
  const f = ui.page.filter;
  const q = ui.query.trim().toLowerCase();
  return ui.items
    .filter((i) => {
      switch (f.kind) {
        case "trash":
          return i.trashed;
        case "archive":
          return i.archived && !i.trashed;
        case "ids":
          return f.ids.includes(i.id) && !i.trashed;
        default:
          if (i.trashed || i.archived) return false;
      }
      switch (f.kind) {
        case "favorites":
          return i.favorite;
        case "vault":
          return i.vaultId === f.id;
        case "category":
          return i.itemType === f.key;
        case "tag":
          return i.tags.includes(f.tag);
        default:
          return true;
      }
    })
    .filter((i) => !q || i.title.toLowerCase().includes(q) || i.subtitle.toLowerCase().includes(q) || (i.primaryUrl ?? "").toLowerCase().includes(q) || i.tags.some((x) => x.toLowerCase().includes(q)))
    .sort((a, b) => (f.kind === "trash" ? (b.trashedAt ?? 0) - (a.trashedAt ?? 0) : a.title.localeCompare(b.title, undefined, { sensitivity: "base" })));
}

function secondLine(s: Summary): string {
  return s.subtitle || category(s.itemType).singular;
}

function itemRow(s: Summary, inCard = false): HTMLElement {
  const vault = ui.vaults.length > 1 ? ui.vaults.find((v) => v.id === s.vaultId)?.name : undefined;
  const row: HTMLElement = h(
    "button",
    {
      class: "row item-row" + (!inCard && ui.selected === s.id ? " selected" : ""),
      role: inCard ? undefined : "option",
      "aria-selected": inCard ? undefined : String(ui.selected === s.id),
    },
    itemArt(s, 36, s.favorite),
    h("span", { class: "row-text" }, h("span", { class: "row-title" }, s.title || t("Sans titre", "Untitled")), h("span", { class: "row-sub" }, [secondLine(s), vault].filter(Boolean).join(" · "))),
    inCard ? icon("chevron_right", 18, "chev") : null,
  );
  row.addEventListener("click", () => {
    if (inCard) return openItem(s);
    ui.selected = s.id;
    for (const r of document.querySelectorAll(".list .item-row")) r.classList.toggle("selected", r === row);
    void renderDetail();
  });
  return row;
}

const listEl = h("div", { class: "list", role: "listbox" });

function listPane(p: { filter: Filter; title: string }): HTMLElement {
  const search = h("input", {
    class: "search-input",
    type: "search",
    placeholder: t("Titre, site, identifiant, tag", "Title, website, username, tag"),
    value: ui.query,
    "aria-label": t("Rechercher", "Search"),
    oninput: () => {
      ui.query = search.value;
      renderList();
    },
  });
  const items = listed();
  const head = h(
    "div",
    { class: "list-head" },
    h("div", { class: "list-title-row" }, h("h1", { class: "list-title" }, p.title),
      p.filter.kind === "trash" && items.length
        ? h("button", { class: "bar-text destructive", onclick: () => emptyTrash() }, t("Vider", "Empty"))
        : h("button", { class: "round small", title: t("Nouvel élément", "New Item"), onclick: () => newItem() }, icon("add", 18))),
    h("div", { class: "list-count tertiary" }, countLabel(items.length)),
    h("label", { class: "search" }, icon("search", 18, "secondary"), search),
    p.filter.kind === "trash" ? h("p", { class: "footnote" }, t("Les éléments restent ici 30 jours avant d'être supprimés.", "Items stay here for 30 days before they are deleted.")) : null,
  );
  renderList();
  return h("section", { class: "list-pane" }, head, listEl);
}

function renderList(): void {
  const items = listed();
  listEl.setAttribute("aria-label", ui.page.kind === "list" ? ui.page.title : "");
  if (!items.length) {
    listEl.replaceChildren(h("div", { class: "empty" }, ui.query ? t(`Aucun résultat pour « ${ui.query} ».`, `No results for “${ui.query}”.`) : t("Aucun élément.", "No items.")));
    return;
  }
  listEl.replaceChildren(...items.map((s) => itemRow(s)));
}

function emptyTrash(): void {
  const trashed = ui.items.filter((i) => i.trashed);
  confirmSheet(t(`Supprimer définitivement ${countLabel(trashed.length)} ? Cette action est irréversible.`, `Permanently delete ${countLabel(trashed.length)}? This cannot be undone.`), t("Supprimer", "Delete"), async () => {
    for (const i of trashed) await call("delete_item", { vaultId: i.vaultId, itemId: i.id }).catch(() => {});
    await refresh(null);
  });
}

/** After a change: reload, keep (or set) the selection, redraw. */
async function refresh(select: string | null | undefined): Promise<void> {
  await reload();
  if (select !== undefined) ui.selected = select;
  if (ui.page.kind === "list" && ui.selected && !listed().some((i) => i.id === ui.selected)) ui.selected = listed()[0]?.id ?? null;
  renderSidebar();
  renderMain();
}

// ---- item --------------------------------------------------------------------------------------

const detailEl = h("main", { class: "detail" });

async function renderDetail(): Promise<void> {
  stopTimers();
  const sel = ui.items.find((i) => i.id === ui.selected);
  if (!sel) {
    detailEl.replaceChildren(h("div", { class: "empty" }, t("Aucun élément sélectionné", "No Item Selected")));
    return;
  }
  let item: Item;
  try {
    item = await call<Item>("item", { vaultId: sel.vaultId, itemId: sel.id });
  } catch (e) {
    detailEl.replaceChildren(h("div", { class: "empty" }, message(e)));
    return;
  }
  if (ui.selected !== item.id) return;
  ui.recents = [item.id, ...ui.recents.filter((x) => x !== item.id)].slice(0, 20);
  const args = { vaultId: item.vaultId, itemId: item.id };
  const cat = category(item.itemType);

  const star = h("button", { class: "bar-icon" + (item.favorite ? " starred" : ""), title: item.favorite ? t("Retirer des favoris", "Unfavorite") : t("Ajouter aux favoris", "Favorite") }, icon(item.favorite ? "star_fill" : "star", 22));
  star.addEventListener("click", async () => {
    await call("set_favorite", { ...args, favorite: !item.favorite });
    await refresh(item.id);
  });
  const more = h("button", { class: "bar-icon", title: t("Actions", "Actions"), "aria-label": t("Actions", "Actions") }, icon("more_circle", 22));
  more.addEventListener("click", () => actions(more, item));
  const toolbar = h(
    "div",
    { class: "toolbar" },
    h("div", { class: "pill" }, ...(item.trashed ? [more] : ui.vaults.find((v) => v.id === item.vaultId)?.sharedRole === "read" ? [star, more] : [star, h("button", { class: "bar-text", onclick: () => void editItem(item, false) }, t("Modifier", "Edit")), more])),
  );

  const vault = ui.vaults.find((v) => v.id === item.vaultId);
  const chips = h("div", { class: "chips" });
  if (vault) chips.append(h("span", { class: "vault-chip" }, monogram(vault.name.slice(0, 1).toUpperCase(), vaultColor(vault.color), 16), vault.name));
  if (item.archived) chips.append(h("span", { class: "chip gray" }, t("Archivé", "Archived")));
  if (item.trashed) chips.append(h("span", { class: "chip red" }, t("Dans la corbeille", "In Trash")));

  // RX quick actions (ItemDetailView): "Ouvrir" for an item with a site, "Partager".
  const quick = (ic: IconName, label: string, onclick: () => void) =>
    h("button", { class: "quick", onclick }, h("span", { class: "quick-disc" }, icon(ic, 20)), h("span", { class: "quick-label" }, label));
  const site = item.urls[0]?.url;
  const quicks = keep(
    site && openable(site) ? quick("globe", t("Ouvrir", "Open"), () => void openUrl(site)) : null,
    !item.trashed && sharing.zonesReady ? quick("share", t("Partager", "Share"), () => sendItemSheet(item)) : null,
  );

  // The item's colour washes in from the top corners (IdentityTint), the category's until its icon is read.
  const dark = matchMedia("(prefers-color-scheme: dark)").matches;
  detailEl.style.setProperty("--wash", identityWash(categoryIdentity(item.itemType), dark));
  const iconIndex = siteIcons.get(item.id);
  if (iconIndex !== undefined) void iconImage(iconIndex).then(async (img) => {
    if (!img || ui.selected !== item.id) return;
    const c = await identityColor(item.itemType, img.src);
    if (ui.selected === item.id) detailEl.style.setProperty("--wash", identityWash(c, dark));
  });

  const sections = item.sections.map((s) => ({ ...s, fields: s.fields.filter((f) => f.hasValue) })).filter((s) => s.fields.length);
  detailEl.replaceChildren(
    toolbar,
    h("div", { class: "detail-scroll" },
      h("header", { class: "item-head" }, itemArt(item, 76),
        h("h2", {}, item.title || t("Sans titre", "Untitled")), h("div", { class: "secondary item-sub" }, [cat.singular, sel.subtitle].filter(Boolean).join(" · ")),
        chips),
      quicks.length ? h("div", { class: "quicks" }, ...quicks) : null,
      ...sections.flatMap((s) => [h("div", { class: "caps" }, sectionLabel(s, cat.singular)), h("div", { class: "card" }, ...s.fields.map((f) => fieldRow(f, args)))]),
      ...(item.urls.length
        ? [h("div", { class: "caps" }, t("Sites web", "Websites")),
           h("div", { class: "card" }, ...item.urls.map((u) => urlRow(u.label || t("site web", "website"), u.url)))]
        : []),
      item.notes ? h("div", { class: "caps" }, t("Notes", "Notes")) : null,
      item.notes ? h("div", { class: "card notes" }, item.notes) : null,
      item.tags.length ? h("div", { class: "caps" }, "Tags") : null,
      item.tags.length ? h("div", { class: "chips" }, ...item.tags.map((x) => h("span", { class: "chip" }, x))) : null,
      item.trashed ? null : wifiCard(item),
      item.trashed ? null : attachmentsSection(item),
      h("div", { class: "meta" },
        timelineFooter(item),
        h("div", { class: "tertiary" }, t("Créé le ", "Created ") + dateTime(item.createdAt)),
        item.passwordHistoryCount > 0 ? h("button", { class: "bar-text", onclick: () => history(item) }, t("Historique des mots de passe", "Password History")) : null),
    ),
  );
}

const fileSize = (n: number): string =>
  n < 1024 ? t(`${n} octets`, `${n} bytes`) : n < 1024 * 1024 ? `${(n / 1024).toFixed(0)} ${t("Ko", "KB")}` : `${(n / 1024 / 1024).toFixed(1).replace(".", t(",", "."))} ${t("Mo", "MB")}`;

function attachmentError(e: unknown): string {
  switch ((e as UiError)?.code) {
    case "TooLarge":
      return t("Ce fichier dépasse 20 Mo, la taille maximale d'une pièce jointe.", "This file is over 20 MB, the largest attachment allowed.");
    case "Unreadable":
      return t("Impossible de lire ce fichier.", "Can't read this file.");
    case "NotFound":
      return t("Ce fichier n'est pas encore arrivé sur cet appareil. Réessaie après la synchronisation.", "This file hasn't reached this device yet. Try again after syncing.");
    case "NoPreview":
      return t("Pas d'aperçu pour ce type de fichier. Exporte-le pour l'ouvrir dans une autre app.", "No preview for this kind of file. Export it to open it in another app.");
    default:
      return message(e);
  }
}

/** Pièces jointes, as on the Mac item page: open, export, delete; add a file. */
function attachmentsSection(item: Item): HTMLElement {
  const args = { vaultId: item.vaultId, itemId: item.id };
  const open = async (a: Attachment) => {
    try {
      await call("open_attachment", { ...args, attachmentId: a.id });
    } catch (e) {
      toast(attachmentError(e));
    }
  };
  const exportFile = async (a: Attachment) => {
    try {
      if (await call<boolean>("export_attachment", { ...args, attachmentId: a.id })) toast(t("Fichier enregistré.", "File saved."));
    } catch (e) {
      toast(attachmentError(e));
    }
  };
  const remove = (a: Attachment) =>
    confirmSheet(t(`Supprimer « ${a.name} » ? Le fichier est effacé de l'élément sur tous tes appareils.`, `Delete “${a.name}”? The file is removed from the item on all your devices.`), t("Supprimer le fichier", "Delete File"), async () => {
      try {
        await call("remove_attachment", { ...args, attachmentId: a.id });
        await refresh(item.id);
      } catch (e) {
        toast(attachmentError(e));
      }
    });
  const rows = item.attachments.map((a) => {
    const moreBtn = h("span", { class: "more", role: "button", tabindex: 0, title: t("Actions sur le fichier", "File actions"), "aria-label": t("Actions sur le fichier", "File actions") }, icon("more", 20));
    moreBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      menu(moreBtn, [
        { label: t("Ouvrir", "Open"), icon: "open_in_new", action: () => void open(a) },
        { label: t("Exporter…", "Export…"), icon: "share", action: () => void exportFile(a) },
        "separator",
        { label: t("Supprimer…", "Delete…"), icon: "trash", destructive: true, action: () => remove(a) },
      ]);
    });
    return h("button", { class: "field-row attachment-row", onclick: () => void open(a), title: t("Ouvrir", "Open") }, icon("paperclip", 20, "accent"),
      h("span", { class: "field-text" }, h("span", { class: "row-title" }, a.name), h("span", { class: "row-sub" }, fileSize(a.size))), moreBtn);
  });
  const full = item.attachments.length >= 32;
  const add = h("button", { class: "add-row", disabled: full, onclick: async () => {
    try {
      const saved = await call<Item | null>("add_attachment", args);
      if (saved) {
        const added = saved.attachments.find((a) => !item.attachments.some((b) => b.id === a.id));
        await refresh(item.id);
        toast(t(`Fichier ajouté : ${added?.name ?? ""}`, `File added: ${added?.name ?? ""}`));
      }
    } catch (e) {
      toast(attachmentError(e));
    }
  } }, icon("add_circle", 20), t("Ajouter un fichier…", "Add a File…"));
  return h("div", {}, h("div", { class: "caps" }, t("Pièces jointes", "Attachments")), h("div", { class: "card" }, ...rows, add));
}

/** Only web links open (a bare host gets https://), as on the iPhone; the
 * backend checks again before Windows sees the address. */
function openable(text: string): boolean {
  const s = text.trim();
  if (!s || /[\s\\]/.test(s)) return false;
  try {
    const u = new URL(s.includes("://") ? s : "https://" + s);
    return (u.protocol === "https:" || u.protocol === "http:") && !!u.hostname && !u.username && !u.password;
  } catch {
    return false;
  }
}

async function openUrl(url: string): Promise<void> {
  try {
    await call("open_url", { url });
  } catch (e) {
    toast(message(e));
  }
}

/** A website: a click copies it, the button and the menu open it in the browser. */
function urlRow(label: string, url: string): HTMLElement {
  const copy = async () => {
    await navigator.clipboard.writeText(url).catch(() => {});
    toast(t("Copié", "Copied"));
  };
  const canOpen = openable(url);
  const open = canOpen
    ? h("span", { class: "more open-link", role: "button", tabindex: 0, title: t("Ouvrir dans le navigateur", "Open in Browser"), "aria-label": t("Ouvrir dans le navigateur", "Open in Browser"),
        onclick: (ev: Event) => (ev.stopPropagation(), void openUrl(url)) }, icon("open_in_new", 20))
    : null;
  const moreBtn = h("span", { class: "more", role: "button", tabindex: 0, title: t("Actions", "Actions"), "aria-label": t("Actions", "Actions") }, icon("more", 20));
  moreBtn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const entries: MenuEntry[] = [{ label: t("Copier", "Copy"), icon: "copy", action: () => void copy() }];
    if (canOpen) entries.push({ label: t("Ouvrir dans le navigateur", "Open in Browser"), icon: "open_in_new", action: () => void openUrl(url) });
    menu(moreBtn, entries);
  });
  return h("button", { class: "field-row url-row", onclick: copy, title: t("Copier", "Copy") },
    h("span", { class: "field-text" }, h("span", { class: "field-label" }, label), h("span", { class: "field-value accent-text" }, url)), open, moreBtn);
}

function fieldRow(f: Field, args: { vaultId: string; itemId: string }): HTMLElement {
  if (f.kind === "url" && f.value) return urlRow(f.label, f.value);
  const valueEl = h("span", { class: "field-value" });
  const text = h("span", { class: "field-text" }, h("span", { class: "field-label" }, f.label), valueEl);
  const copy = async () => {
    try {
      const secs = await call<number>("copy_field", { ...args, fieldId: f.id });
      toast(f.secret ? t(`Copié · effacé dans ${secs} s`, `Copied · cleared in ${secs} s`) : t("Copié", "Copied"));
    } catch (e) {
      toast(message(e));
    }
  };
  if (f.kind === "otp") {
    const left = h("span", { class: "otp-left" });
    valueEl.classList.add("otp");
    const tick = async () => {
      try {
        const c = await call<{ code: string; remaining: number }>("totp", { ...args, fieldId: f.id });
        const half = Math.floor(c.code.length / 2);
        valueEl.textContent = `${c.code.slice(0, half)} • ${c.code.slice(half)}`;
        left.textContent = String(c.remaining);
        left.classList.toggle("soon", c.remaining <= 5);
      } catch {
        valueEl.textContent = t("Code indisponible", "Code unavailable");
      }
    };
    void tick();
    timers.push(window.setInterval(tick, 1000));
    return h("button", { class: "field-row", onclick: copy, title: t("Copier", "Copy") }, text, left);
  }
  let shown = false;
  if (f.secret) valueEl.textContent = "••••••••••";
  else valueEl.textContent = f.value ?? "";
  if (f.strength !== null && f.strength !== undefined) {
    const lv = f.strength;
    const color = lv <= 1 ? "var(--red)" : lv === 2 ? "var(--orange)" : "var(--green)";
    const segs = h("span", { class: "segs" });
    for (let i = 0; i < 4; i++) {
      const s = h("span");
      if (i < lv) s.style.background = color;
      segs.append(s);
    }
    text.append(h("span", { class: "meter" }, segs, h("span", { class: "meter-label" }, strengthWords()[lv]!)));
  }
  const reveal = async () => {
    if (shown) {
      valueEl.textContent = "••••••••••";
      valueEl.classList.remove("mono");
      shown = false;
      return;
    }
    try {
      const v = await call<string>("reveal_field", { ...args, fieldId: f.id });
      valueEl.replaceChildren(f.kind === "password" ? colored(v) : document.createTextNode(v));
      valueEl.classList.toggle("mono", f.kind === "password");
      shown = true;
    } catch (e) {
      toast(message(e));
    }
  };
  const moreBtn = h("span", { class: "more", role: "button", tabindex: 0, title: t("Actions", "Actions"), "aria-label": t("Actions", "Actions") }, icon("more", 20));
  moreBtn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const entries: MenuEntry[] = [{ label: t("Copier", "Copy"), icon: "copy", action: () => void copy() }];
    if (f.secret) entries.push({ label: shown ? t("Masquer", "Conceal") : t("Révéler", "Reveal"), icon: shown ? "eye_off" : "eye", action: () => void reveal() });
    entries.push({
      label: t("Afficher en grand", "Show in Large Type"),
      icon: "large_type",
      action: async () => largeType(f.secret ? await call<string>("reveal_field", { ...args, fieldId: f.id }) : (f.value ?? "")),
    });
    menu(moreBtn, entries);
  });
  return h("button", { class: "field-row", onclick: copy, title: t("Copier", "Copy") }, text, moreBtn);
}

function largeType(value: string): void {
  const s = sheet(t("Afficher en grand", "Large Type"), { cancel: t("Fermer", "Close") });
  s.dialog.classList.add("wide");
  s.body.append(h("div", { class: "large-type" }, ...[...value].map((ch, i) => {
    const cls = /[0-9]/.test(ch) ? "d" : /[\p{L}]/u.test(ch) ? "" : "s";
    return h("span", { class: "lt-cell" }, h("span", { class: "lt-char " + cls }, ch), h("span", { class: "lt-index" }, String(i + 1)));
  })));
}

async function history(item: Item): Promise<void> {
  const entries = await call<{ index: number; replacedAt: number }[]>("password_history", { vaultId: item.vaultId, itemId: item.id });
  const s = sheet(t("Historique des mots de passe", "Password History"), { cancel: t("Fermer", "Close") });
  s.body.append(
    h("p", { class: "footnote" }, t("Les mots de passe que cet élément a remplacés, du plus récent au plus ancien.", "The passwords this item replaced, newest first.")),
    h("div", { class: "card" }, ...entries.sort((a, b) => b.replacedAt - a.replacedAt).map((e) => {
      const v = h("span", { class: "field-value" }, "••••••••••");
      let shown = false;
      const value = () => call<string>("history_value", { vaultId: item.vaultId, itemId: item.id, index: e.index });
      return h("div", { class: "field-row static" },
        h("span", { class: "field-text" }, h("span", { class: "field-label" }, t("Remplacé le ", "Replaced ") + dateTime(e.replacedAt)), v),
        h("button", { class: "bar-icon", title: t("Révéler", "Reveal"), onclick: async () => {
          shown = !shown;
          if (shown) v.replaceChildren(colored(await value()));
          else v.textContent = "••••••••••";
          v.classList.toggle("mono", shown);
        } }, icon("eye", 20)),
        h("button", { class: "bar-icon", title: t("Copier", "Copy"), onclick: async () => {
          const secs = await call<number>("copy_secret", { text: await value() });
          toast(t(`Copié · effacé dans ${secs} s`, `Copied · cleared in ${secs} s`));
        } }, icon("copy", 20)));
    })),
  );
}

function actions(anchor: HTMLElement, item: Item): void {
  const args = { vaultId: item.vaultId, itemId: item.id };
  const run = async (cmd: string, extra: Record<string, unknown> = {}, select?: string | null) => {
    try {
      await call(cmd, { ...args, ...extra });
      await refresh(select);
    } catch (e) {
      toast(message(e));
    }
  };
  if (item.trashed) {
    menu(anchor, [
      { label: t("Restaurer", "Restore"), icon: "restore", action: () => void run("restore_item", {}, null) },
      { label: t("Supprimer définitivement", "Delete Permanently"), icon: "trash", destructive: true,
        action: () => confirmSheet(t(`Supprimer définitivement « ${item.title} » ? Cette action est irréversible.`, `Permanently delete “${item.title}”? This cannot be undone.`),
          t("Supprimer", "Delete"), () => void run("delete_item", {}, null)) },
    ]);
    return;
  }
  const entries: MenuEntry[] = [
    { label: item.favorite ? t("Retirer des favoris", "Unfavorite") : t("Ajouter aux favoris", "Favorite"), icon: item.favorite ? "star_fill" : "star",
      action: () => void run("set_favorite", { favorite: !item.favorite }) },
  ];
  const username = item.sections.flatMap((s) => s.fields).find((f) => f.id === "username" || f.kind === "email");
  if (username?.value) entries.push({ label: t("Copier l'identifiant", "Copy Username"), icon: "copy", action: () => void call("copy_field", { ...args, fieldId: username.id }).then(() => toast(t("Copié", "Copied"))) });
  if (ui.vaults.length > 1) entries.push({ label: t("Déplacer…", "Move…"), icon: "folder", action: () => moveSheet(item) });
  if (sharing.zonesReady) entries.push({ label: t("Envoyer une copie…", "Send a Copy…"), icon: "share", action: () => sendItemSheet(item) });
  entries.push(
    { label: t("Dupliquer", "Duplicate"), icon: "duplicate", action: async () => {
      try {
        const copy = await call<Item>("duplicate_item", { ...args, suffix: t(" (copie)", " (copy)") });
        await refresh(copy.id);
      } catch (e) {
        toast(message(e));
      }
    } },
    { label: item.archived ? t("Désarchiver", "Unarchive") : t("Archiver", "Archive"), icon: "archive", action: () => void run("set_archived", { archived: !item.archived }) },
    "separator",
    { label: t("Supprimer", "Delete"), icon: "trash", destructive: true,
      action: () => confirmSheet(t(`Mettre « ${item.title} » dans Supprimés récemment ?`, `Move “${item.title}” to Recently Deleted?`), t("Supprimer", "Delete"), () => void run("trash_item", {}, null)) },
  );
  menu(anchor, entries);
}

function moveSheet(item: Item): void {
  const s = sheet(t("Déplacer vers", "Move to"));
  s.body.append(h("div", { class: "card list-card" }, ...ui.vaults.filter((v) => v.id !== item.vaultId).map((v) =>
    h("button", { class: "row", onclick: async () => {
      s.close();
      try {
        await call("move_item", { itemId: item.id, fromVault: item.vaultId, toVault: v.id });
        await refresh(item.id);
      } catch (e) {
        toast(message(e));
      }
    } }, monogram(v.name.slice(0, 1).toUpperCase(), vaultColor(v.color), 30), h("span", { class: "row-text" }, h("span", { class: "row-title" }, v.name))))));
}

// ---- new item and editor ---------------------------------------------------------------------

function newItem(): void {
  if (!ui.vaults.length) return;
  let vaultId = ui.page.kind === "list" && ui.page.filter.kind === "vault" ? ui.page.filter.id : ui.vaults[0]!.id;
  const s = sheet(t("Nouvel élément", "New Item"), { wide: true });
  const chips = h("div", { class: "chips" });
  const drawChips = () => {
    chips.replaceChildren(...ui.vaults.map((v) => {
      const c = h("button", { class: "chip" + (v.id === vaultId ? " on" : ""), type: "button", onclick: () => ((vaultId = v.id), drawChips()) }, v.name);
      c.style.setProperty("--chip", vaultColor(v.color));
      return c;
    }));
  };
  drawChips();
  s.body.append(
    h("h1", { class: "picker-title" }, t("Que veux-tu ajouter ?", "What do you want to add?")),
    ...(ui.vaults.length > 1 ? [chips] : []),
    h("div", { class: "picker" }, ...categories().map((c) =>
      h("button", { class: "picker-cell card", type: "button", onclick: async () => {
        try {
          const item = await call<Item>("new_item", { vaultId, itemType: c.key, title: "" });
          s.close();
          editItem(item, true);
        } catch (e) {
          toast(message(e));
        }
      } }, art(c.key, 48), h("span", {}, c.singular)))),
  );
}

const TEXT_KINDS = new Set(["text", "concealed", "password", "url", "email", "phone", "menu", "otp", "mnemonic", "number", "money"]);
/** The kinds a custom field can have (the Apple apps' grid, without "Lieu"). */
const customKinds = (): { kind: string; label: string; icon: IconName }[] => [
  { kind: "text", label: t("Texte", "Text"), icon: "text_fields" },
  { kind: "concealed", label: t("Masqué", "Hidden"), icon: "eye_off" },
  { kind: "password", label: t("Mot de passe", "Password"), icon: "password" },
  { kind: "date", label: "Date", icon: "calendar" },
  { kind: "url", label: "URL", icon: "globe" },
  { kind: "email", label: "Email", icon: "mail" },
  { kind: "phone", label: t("Téléphone", "Phone"), icon: "call" },
];
const RULES = (): [string, string][] => [
  ["domain", t("Domaine", "Domain")],
  ["exactHost", t("Hôte exact", "Exact Host")],
  ["exactUrl", t("URL exacte", "Exact URL")],
  ["never", t("Jamais", "Never")],
];

/** A field of the editor: its row, and the value to send once touched. */
interface FieldControl {
  row: HTMLElement;
  /** Undefined until the user changes the field (an unrevealed secret stays). */
  value: () => FieldInput | undefined;
}

const twoDigits = (n: number) => String(n).padStart(2, "0");

/** Month names of the system's language, as the Apple apps take them from the locale. */
function monthNames(): string[] {
  const f = new Intl.DateTimeFormat(t("fr-FR", "en-US"), { month: "long" });
  return Array.from({ length: 12 }, (_, i) => {
    const name = f.format(new Date(2026, i, 1));
    return name.charAt(0).toUpperCase() + name.slice(1);
  });
}

function editRow(id: string, label: Node | string, body: Node, extra?: Node | null): HTMLElement {
  return h("div", { class: "edit-row" }, h("span", { class: "field-text" }, typeof label === "string" ? h("label", { class: "field-label", for: id }, label) : label, body), extra ?? null);
}

/** One control per field kind: text, menu, date, month-year, address; the
 * other kinds (passkey, file, place, barcode, SSH key, link) show read only. */
function fieldControl(f: Field, labelNode?: Node): FieldControl {
  const id = "f-" + f.id;
  let touched = false;
  const label = labelNode ?? f.label;
  if (TEXT_KINDS.has(f.kind)) {
    const secret = f.secret && f.kind !== "otp";
    if (f.kind === "menu" && f.options.length) {
      const select = h("select", { id }, h("option", { value: "" }, "—"), ...f.options.map((o) => h("option", { value: o }, o)));
      select.value = f.value ?? "";
      if (f.value && !f.options.includes(f.value)) select.append(h("option", { value: f.value }, f.value));
      select.value = f.value ?? "";
      select.addEventListener("change", () => (touched = true));
      return { row: editRow(id, label, select), value: () => (touched ? { type: "text", value: select.value } : undefined) };
    }
    const input = h("input", {
      id,
      type: secret ? "password" : f.kind === "email" ? "email" : "text",
      value: secret ? "" : (f.value ?? ""),
      placeholder: secret && f.hasValue ? t("Inchangé", "Unchanged") : typeof label === "string" ? label : "",
      autocomplete: "off",
      spellcheck: false,
      inputMode: f.kind === "number" ? "numeric" : f.kind === "phone" ? "tel" : f.kind === "url" ? "url" : undefined,
    });
    input.addEventListener("input", () => (touched = true));
    let extra: Node | undefined;
    if (f.kind === "password") {
      extra = h("button", { class: "bar-icon", type: "button", title: t("Générer un mot de passe", "Generate Password"), "aria-label": t("Générer un mot de passe", "Generate Password"),
        onclick: (ev: Event) => {
          ev.preventDefault();
          generator((p) => {
            input.type = "text";
            input.classList.add("mono");
            input.value = p;
            touched = true;
          });
        } }, icon("wand", 22));
    } else if (secret) {
      extra = h("button", { class: "bar-icon", type: "button", title: t("Afficher le mot de passe", "Show Password"), onclick: () => {
        input.type = input.type === "password" ? "text" : "password";
      } }, icon("eye", 20));
    }
    const row = h("label", { class: "edit-row", for: id }, h("span", { class: "field-text" }, typeof label === "string" ? h("span", { class: "field-label" }, label) : label, input), extra ?? null);
    return { row, value: () => (touched ? { type: "text", value: input.value } : undefined) };
  }
  if (f.kind === "date") {
    let v = f.data?.type === "date" ? { ...f.data } : null;
    const box = h("div", { class: "inline-editor" });
    const draw = () => {
      if (!v) {
        box.replaceChildren(h("button", { class: "bar-text add-value", type: "button", id, onclick: () => {
          const d = new Date();
          v = { type: "date", year: d.getFullYear(), month: d.getMonth() + 1, day: d.getDate() };
          touched = true;
          draw();
          (box.querySelector("input") as HTMLInputElement | null)?.focus();
        } }, t("Ajouter une date", "Add Date")));
        return;
      }
      const input = h("input", { id, type: "date", value: `${String(v.year).padStart(4, "0")}-${twoDigits(v.month)}-${twoDigits(v.day)}` });
      input.addEventListener("change", () => {
        const m = /^(\d{4,})-(\d{2})-(\d{2})$/.exec(input.value);
        if (!m) return;
        v = { type: "date", year: Number(m[1]), month: Number(m[2]), day: Number(m[3]) };
        touched = true;
      });
      box.replaceChildren(input, h("button", { class: "bar-icon", type: "button", title: t("Effacer", "Erase"), "aria-label": t("Effacer", "Erase"), onclick: () => {
        v = null;
        touched = true;
        draw();
      } }, icon("close", 18)));
    };
    draw();
    return { row: editRow(id, label, box), value: () => (touched ? (v ?? { type: "empty" }) : undefined) };
  }
  if (f.kind === "monthYear") {
    let v = f.data?.type === "monthYear" ? { ...f.data } : null;
    const box = h("div", { class: "inline-editor" });
    const draw = () => {
      if (!v) {
        box.replaceChildren(h("button", { class: "bar-text add-value", type: "button", id, onclick: () => {
          const d = new Date();
          v = { type: "monthYear", year: d.getFullYear(), month: d.getMonth() + 1 };
          touched = true;
          draw();
        } }, t("Choisir le mois et l'année", "Choose Month and Year")));
        return;
      }
      const month = h("select", { id, "aria-label": t("Mois", "Month") }, ...monthNames().map((n, i) => h("option", { value: String(i + 1) }, n)));
      month.value = String(v.month);
      const now = new Date().getFullYear();
      const years = new Set<number>();
      for (let y = now - 30; y <= now + 20; y++) years.add(y);
      years.add(v.year);
      const year = h("select", { "aria-label": t("Année", "Year") }, ...[...years].sort((a, b) => a - b).map((y) => h("option", { value: String(y) }, String(y))));
      year.value = String(v.year);
      const update = () => {
        v = { type: "monthYear", year: Number(year.value), month: Number(month.value) };
        touched = true;
      };
      month.addEventListener("change", update);
      year.addEventListener("change", update);
      box.replaceChildren(month, year, h("button", { class: "bar-icon", type: "button", title: t("Effacer", "Erase"), "aria-label": t("Effacer", "Erase"), onclick: () => {
        v = null;
        touched = true;
        draw();
      } }, icon("close", 18)));
    };
    draw();
    return { row: editRow(id, label, box), value: () => (touched ? (v ?? { type: "empty" }) : undefined) };
  }
  if (f.kind === "address") {
    const a = f.data?.type === "address" ? f.data : { line1: "", line2: "", postalCode: "", city: "", region: "", country: "" };
    const part = (key: keyof typeof a, placeholder: string, cls = "") => {
      const input = h("input", { class: cls, value: a[key] as string, placeholder, "aria-label": placeholder, autocomplete: "off", id: key === "line1" ? id : undefined });
      input.addEventListener("input", () => (touched = true));
      return input;
    };
    const parts = {
      line1: part("line1", t("Ligne 1", "Line 1")),
      line2: part("line2", t("Ligne 2", "Line 2")),
      postalCode: part("postalCode", t("Code postal", "Postal Code"), "postal"),
      city: part("city", t("Ville", "City")),
      region: part("region", t("Région", "Region")),
      country: part("country", t("Pays", "Country")),
    };
    const box = h("div", { class: "address-editor" }, parts.line1, parts.line2, h("div", { class: "address-pair" }, parts.postalCode, parts.city), parts.region, parts.country);
    return {
      row: editRow(id, label, box),
      value: () =>
        touched
          ? { type: "address", line1: parts.line1.value, line2: parts.line2.value, postalCode: parts.postalCode.value, city: parts.city.value, region: parts.region.value, country: parts.country.value }
          : undefined,
    };
  }
  // Read only here: shown so the editor never hides what the item holds.
  const shown = f.secret ? (f.hasValue ? "••••••••••" : "") : (f.value ?? "");
  return { row: editRow(id, label, h("span", { class: "field-value secondary" }, shown || "—")), value: () => undefined };
}

/** Tags as chips, "Ajouter un tag" with Return, and suggestions from the vault. */
function tagEditor(initial: string[]): { el: HTMLElement; tags: () => string[] } {
  let tags = [...initial];
  const chips = h("div", { class: "chips tag-chips" });
  const input = h("input", { id: "f-tags", class: "tag-input", placeholder: t("Ajouter un tag", "Add Tag"), "aria-label": t("Ajouter un tag", "Add Tag"), autocomplete: "off" });
  const suggestions = h("div", { class: "chips suggestions" });
  const add = (raw: string) => {
    const tag = raw.trim().replace(/,$/, "").trim();
    if (tag && !tags.some((x) => x.toLowerCase() === tag.toLowerCase())) tags.push(tag);
    input.value = "";
    draw();
  };
  const draw = () => {
    chips.replaceChildren(...tags.map((tag) =>
      h("button", { class: "chip removable", type: "button", title: t(`Retirer le tag ${tag}`, `Remove Tag ${tag}`), "aria-label": t(`Retirer le tag ${tag}`, `Remove Tag ${tag}`),
        onclick: () => ((tags = tags.filter((x) => x !== tag)), draw()) }, tag, icon("close", 14))), input);
    const known = [...new Set(ui.items.flatMap((i) => i.tags))].filter((x) => !tags.some((y) => y.toLowerCase() === x.toLowerCase())).sort((a, b) => a.localeCompare(b)).slice(0, 6);
    suggestions.replaceChildren(...known.map((tag) => h("button", { class: "chip suggestion", type: "button", onclick: () => add(tag) }, icon("add", 14), tag)));
  };
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      add(input.value);
    } else if (e.key === "Backspace" && !input.value && tags.length) {
      tags.pop();
      draw();
      input.focus();
    }
  });
  draw();
  return { el: h("div", {}, chips, suggestions), tags: () => (input.value.trim() ? [...tags, input.value.trim()] : tags) };
}

/** The websites: one row each (address, matching rule, remove), the first one primary. */
function urlsEditor(initial: { label: string; url: string; rule: string }[]): { el: HTMLElement; urls: () => { label: string; url: string; rule: string }[] } {
  const rows: { label: string; input: HTMLInputElement; rule: string }[] = initial.map((u) => ({ label: u.label, input: h("input"), rule: u.rule }));
  rows.forEach((r, i) => (r.input.value = initial[i]!.url));
  const card = h("div", { class: "card" });
  const draw = () => {
    const many = rows.length > 1;
    card.replaceChildren(...rows.map((r, i) => {
      const id = i === 0 ? "f-url" : `f-url-${i}`;
      r.input.id = id;
      r.input.placeholder = "https://";
      r.input.spellcheck = false;
      r.input.inputMode = "url";
      const ruleBtn = h("button", { class: "bar-icon", type: "button", title: t("Correspondance pour le remplissage", "Matching for AutoFill"), "aria-label": t("Correspondance", "Matching") }, icon("options", 20));
      ruleBtn.addEventListener("click", () => {
        const entries: MenuEntry[] = RULES().map(([key, name]) => ({ label: name, icon: key === r.rule ? "check" : "globe", action: () => (r.rule = key) }));
        if (many && i > 0) entries.push("separator", { label: t("Site principal", "Main Website"), icon: "star", action: () => (rows.unshift(...rows.splice(i, 1)), draw()) });
        menu(ruleBtn, entries);
      });
      const remove = h("button", { class: "bar-icon destructive", type: "button", title: t("Retirer ce site web", "Remove This Website"), "aria-label": t("Retirer ce site web", "Remove This Website"),
        onclick: () => (rows.splice(i, 1), draw()) }, icon("remove_circle", 20));
      return editRow(id, many && i === 0 ? t("site web principal", "Primary website") : t("site web", "Website"), r.input, h("span", { class: "row-tools" }, ruleBtn, remove));
    }),
    h("button", { class: "add-row", type: "button", onclick: () => {
      rows.push({ label: "", input: h("input"), rule: "domain" });
      draw();
      rows[rows.length - 1]!.input.focus();
    } }, icon("add_circle", 20), rows.length ? t("ajouter un autre site web", "add another website") : t("ajouter un site web", "add a website")));
  };
  if (!rows.length) rows.push({ label: "", input: h("input"), rule: "domain" });
  draw();
  return { el: card, urls: () => rows.map((r) => ({ label: r.label, url: r.input.value, rule: r.rule })) };
}

const isCustomSection = (s: Section) => s.id === "custom";
const sectionLabel = (s: Section, fallback: string) => (isCustomSection(s) && (s.label === "Champs perso" || !s.label) ? t("Champs perso", "Custom fields") : s.label || fallback);

function editItem(item: Item, isNew: boolean): void {
  const cat = category(item.itemType);
  const title = h("input", { id: "f-title", class: "title-input", value: item.title, placeholder: cat.singular, "aria-label": t("Titre", "Title") });
  const err = h("div", { class: "error", role: "alert" });
  let dirty = false;
  const controls = new Map<string, FieldControl>();
  const sections: Node[] = [];
  for (const sec of item.sections) {
    if (isCustomSection(sec)) continue;
    const rows: Node[] = [];
    for (const f of sec.fields) {
      const c = fieldControl(f);
      controls.set(f.id, c);
      rows.push(c.row);
    }
    if (rows.length) sections.push(h("div", { class: "caps" }, sectionLabel(sec, cat.singular)), h("div", { class: "card" }, ...rows));
  }

  // Custom fields ("Champs perso"): label, value, remove; added from "ajouter plus".
  interface Custom { id?: string; kind: string; label: HTMLInputElement; control: FieldControl; }
  const customs: Custom[] = [];
  const customCard = h("div", { class: "card" });
  const customHead = h("div", { class: "caps" }, t("Champs perso", "Custom fields"));
  const drawCustom = () => {
    customHead.hidden = customCard.hidden = customs.length === 0;
    customCard.replaceChildren(...customs.map((c) => {
      const remove = h("button", { class: "bar-icon destructive", type: "button", title: t(`Retirer ${c.label.value || c.label.placeholder}`, `Remove ${c.label.value || c.label.placeholder}`),
        onclick: () => {
          customs.splice(customs.indexOf(c), 1);
          dirty = true;
          drawCustom();
        } }, icon("remove_circle", 20));
      const row = c.control.row;
      row.classList.add("custom-row");
      row.querySelector(".field-text")?.prepend(c.label);
      row.querySelector(":scope > .field-text > .field-label")?.remove();
      return h("div", { class: "custom-wrap" }, remove, row);
    }));
  };
  const addCustom = (f: Field, fresh: boolean) => {
    const label = h("input", { class: "custom-label", value: fresh ? "" : f.label, placeholder: fresh ? customKinds().find((k) => k.kind === f.kind)?.label ?? "" : t("Libellé", "Label"), "aria-label": t("Libellé", "Label") });
    label.addEventListener("input", () => (dirty = true));
    customs.push({ id: fresh ? undefined : f.id, kind: f.kind, label, control: fieldControl(f, h("span")) });
    drawCustom();
  };
  for (const f of item.sections.find(isCustomSection)?.fields ?? []) addCustom(f, false);
  let fresh = 0;
  const more = h("button", { class: "add-row", type: "button" }, icon("add_circle", 20), t("ajouter plus", "add more"));
  more.addEventListener("click", () =>
    menu(more, customKinds().map((k) => ({
      label: k.label,
      icon: k.icon,
      action: () => {
        fresh++;
        addCustom({ id: `new-${fresh}`, label: "", kind: k.kind, value: null, secret: k.kind === "password" || k.kind === "concealed", hasValue: false, strength: null, options: [] }, true);
        dirty = true;
        customs[customs.length - 1]!.label.focus();
      },
    })), "left"));
  drawCustom();

  const urls = urlsEditor(item.urls);
  const notes = h("textarea", { id: "f-notes", placeholder: t("Ajoute des notes sur cet élément.", "Add notes about this item."), rows: 4 });
  notes.value = item.notes;
  const grow = () => {
    notes.style.height = "auto";
    notes.style.height = Math.min(notes.scrollHeight + 2, 420) + "px";
  };
  notes.addEventListener("input", grow);
  const tags = tagEditor(item.tags);
  const travelHidden = h("input", { type: "checkbox", class: "switch", checked: item.travelHidden, "aria-label": t("Caché en voyage", "Hidden in Travel Mode") });
  const travelGuard = h("input", { type: "checkbox", class: "switch", checked: item.travelGuard, disabled: item.travelHidden, "aria-label": t("Protection renforcée en voyage", "Extra Protection in Travel Mode") });
  travelHidden.addEventListener("change", () => (travelGuard.disabled = travelHidden.checked));

  const save = async (sh: Sheet) => {
    const fields: Record<string, FieldInput> = {};
    for (const [id, c] of controls) {
      const v = c.value();
      if (v !== undefined) fields[id] = v;
    }
    try {
      const saved = await call<Item>("save_item", {
        edit: {
          vaultId: item.vaultId,
          itemId: item.id,
          title: title.value.trim(),
          notes: notes.value,
          urls: urls.urls(),
          tags: tags.tags(),
          fields,
          custom: customs.map((c) => ({ id: c.id, label: c.label.value, kind: c.kind, value: c.control.value() })),
          travelHidden: travelHidden.checked,
          travelGuard: travelGuard.checked && !travelHidden.checked,
          newType: isNew ? item.itemType : undefined,
        },
      });
      sh.close();
      if (ui.page.kind !== "list") ui.page = { kind: "list", filter: { kind: "all" }, title: t("Tous les éléments", "All Items") };
      await refresh(saved.id);
      toast(t("Enregistré", "Saved"));
    } catch (e) {
      const er = e as UiError;
      if (er.code === "Validation") {
        const id = er.detail.split(":")[0]!;
        const label = id === "title" ? t("Titre", "Title") : (item.sections.flatMap((x) => x.fields).find((x) => x.id === id)?.label ?? id);
        err.textContent = er.detail.includes("required") || id === "title" ? t(`« ${label} » est obligatoire.`, `“${label}” is required.`) : t(`« ${label} » n'est pas valide.`, `“${label}” is not valid.`);
        (document.getElementById(id === "title" ? "f-title" : "f-" + id) as HTMLElement | null)?.focus();
      } else err.textContent = message(e);
    }
  };
  const s = sheet(isNew ? t("Nouvel élément", "New Item") : t("Modification", "Editing"), {
    action: t("Enregistrer", "Save"),
    wide: true,
    onAction: save,
    confirmCancel: () => dirty,
  });
  s.dialog.classList.add("editor");
  s.body.addEventListener("input", () => (dirty = true));
  s.body.addEventListener("change", () => (dirty = true));
  s.body.append(
    h("div", { class: "card edit-head" }, art(item.itemType, 44), title),
    ...sections,
    customHead,
    customCard,
    h("div", { class: "card list-card" }, more),
    h("div", { class: "caps" }, t("Sites web", "Websites")),
    urls.el,
    h("div", { class: "caps" }, t("Notes", "Notes")),
    h("div", { class: "card" }, notes),
    h("div", { class: "caps" }, "Tags"),
    h("div", { class: "card pad-s" }, tags.el),
    h("div", { class: "caps" }, "Travel Mode"),
    h("div", { class: "card list-card" },
      h("label", { class: "toggle-row" }, h("span", { class: "row-text" }, h("span", {}, t("Caché en voyage", "Hidden in Travel Mode")),
        h("span", { class: "row-sub" }, t("Quitte cet appareil en Travel Mode, revient au retour.", "Leaves this device in Travel Mode, comes back when you return."))), travelHidden),
      h("label", { class: "toggle-row" }, h("span", { class: "row-text" }, h("span", {}, t("Protection renforcée en voyage", "Extra Protection in Travel Mode")),
        h("span", { class: "row-sub" }, t("En Travel Mode : mot de passe maître et Windows Hello pour l'afficher, jamais proposé ailleurs.", "In Travel Mode: master password and Windows Hello to show it, never offered elsewhere."))), travelGuard)),
    err,
  );
  requestAnimationFrame(grow);
  title.focus();
}

// ---- generator ---------------------------------------------------------------------------------

function generator(into: ((p: string) => void) | null): void {
  let mode = 0;
  const lengths = [20, 5, 6];
  const ranges: [number, number][] = [[8, 100], [3, 10], [4, 12]];
  let digits = true;
  let symbols = true;
  let capitalize = true;
  let value = "";
  const out = h("div", { class: "generated", "aria-live": "polite" });
  const meterBox = h("div", { class: "meter-row center-row" });
  const options = h("div", { class: "card" });
  const segments = h("div", { class: "segmented", role: "tablist" });
  const regen = async () => {
    const recipe =
      mode === 0 ? { kind: "characters", length: lengths[0], digits, symbols } : mode === 1 ? { kind: "words", count: lengths[1], french: t("fr", "en") === "fr", capitalize } : { kind: "pin", length: lengths[2] };
    try {
      const g = await call<{ password: string; bits: number }>("generate_password", { recipe });
      value = g.password;
      out.replaceChildren(colored(value));
      meterBox.replaceChildren(meter(g.bits));
    } catch (e) {
      out.textContent = message(e);
    }
  };
  const toggle = (label: string, on: boolean, set: (v: boolean) => void) => {
    const input = h("input", { type: "checkbox", class: "switch", checked: on, "aria-label": label });
    input.addEventListener("change", () => (set(input.checked), void regen()));
    return h("label", { class: "toggle-row" }, h("span", {}, label), input);
  };
  const drawOptions = () => {
    const [min, max] = ranges[mode]!;
    const lenLabel = h("span", {});
    const slider = h("input", { type: "range", min: String(min), max: String(max), value: String(lengths[mode]), "aria-label": t("Longueur", "Length") });
    const label = () =>
      (lenLabel.textContent = mode === 0 ? t(`${lengths[0]} caractères`, `${lengths[0]} characters`) : mode === 1 ? t(`${lengths[1]} mots`, `${lengths[1]} words`) : t(`${lengths[2]} chiffres`, `${lengths[2]} digits`));
    slider.addEventListener("input", () => {
      lengths[mode] = Number(slider.value);
      label();
      void regen();
    });
    label();
    options.replaceChildren(h("div", { class: "slider-row" }, lenLabel, slider));
    if (mode === 0) options.append(toggle(t("Chiffres", "Numbers"), digits, (v) => (digits = v)), toggle(t("Symboles", "Symbols"), symbols, (v) => (symbols = v)));
    if (mode === 1) options.append(toggle(t("Majuscules", "Capitalize"), capitalize, (v) => (capitalize = v)));
  };
  const drawSegments = () =>
    segments.replaceChildren(...[t("Caractères", "Characters"), t("Mots", "Words"), "PIN"].map((label, i) =>
      h("button", { class: i === mode ? "on" : "", role: "tab", "aria-selected": String(i === mode), type: "button", onclick: () => ((mode = i), drawSegments(), drawOptions(), void regen()) }, label)));
  drawSegments();
  drawOptions();
  const s = sheet(t("Générateur", "Generator"), {
    cancel: t("Fermer", "Close"),
    action: into ? t("Utiliser", "Use") : undefined,
    onAction: (sh) => {
      into?.(value);
      sh.close();
    },
  });
  s.body.append(
    segments,
    h("div", { class: "card gen-card" }, out, meterBox),
    h("div", { class: "buttons-row" },
      h("button", { class: "capsule", type: "button", onclick: () => void regen() }, t("Régénérer", "Regenerate")),
      h("button", { class: "capsule prominent", type: "button", onclick: async () => {
        const secs = await call<number>("copy_secret", { text: value });
        toast(t(`Copié · effacé dans ${secs} s`, `Copied · cleared in ${secs} s`));
      } }, t("Copier", "Copy"))),
    options,
  );
  void regen();
}

// ---- Watchtower ----------------------------------------------------------------------------------

function dial(score: number | undefined): SVGSVGElement {
  // RX ScoreGauge: the upper half circle, 16 thick with round caps, red to green along the arc,
  // the number under it. Box 230 x 125, as on the Mac.
  const w = 230, hgt = 150;
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${hgt}`);
  svg.setAttribute("width", String(w));
  svg.setAttribute("height", String(hgt));
  svg.setAttribute("class", "dial");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", t("Score de sécurité", "Security Score") + (score === undefined ? "" : ` ${score}/100, ${scoreLabel(score)}`));
  const cx = w / 2, cy = 117, r = Math.min(w / 2, 125) - 8;
  const grad = document.createElementNS(SVG, "linearGradient");
  grad.setAttribute("id", "dial-grad");
  grad.setAttribute("gradientUnits", "userSpaceOnUse");
  grad.setAttribute("x1", String(cx - r));
  grad.setAttribute("x2", String(cx + r));
  for (const [o, c] of [[0, "var(--red)"], [0.4, "var(--orange)"], [0.6, "var(--yellow)"], [0.8, "var(--green)"], [1, "var(--green)"]] as const) {
    const s = document.createElementNS(SVG, "stop");
    s.setAttribute("offset", String(o));
    s.style.stopColor = c;
    grad.append(s);
  }
  const defs = document.createElementNS(SVG, "defs");
  defs.append(grad);
  svg.append(defs);
  const arc = (fraction: number) => {
    const a = Math.PI * (1 - fraction);
    return `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r * Math.cos(a)} ${cy - r * Math.sin(a)}`;
  };
  const path = (d: string, cls: string, stroke?: string) => {
    const p = document.createElementNS(SVG, "path");
    p.setAttribute("d", d);
    p.setAttribute("class", cls);
    if (stroke) p.setAttribute("stroke", stroke);
    svg.append(p);
  };
  path(arc(1), "track");
  if (score) path(arc(Math.min(score, 99.9) / 100), "fill", "url(#dial-grad)");
  const text = (s: string, y: number, cls: string, fill?: string) => {
    const el = document.createElementNS(SVG, "text");
    el.setAttribute("x", String(cx));
    el.setAttribute("y", String(y));
    el.setAttribute("class", cls);
    el.setAttribute("text-anchor", "middle");
    if (fill) el.style.fill = fill;
    el.textContent = s;
    svg.append(el);
  };
  text(score === undefined ? "–" : String(score), cy - 8, "dial-figure");
  text(score === undefined ? t("Analyse…", "Analyzing…") : scoreLabel(score), cy + 26, "dial-word", score === undefined ? undefined : scoreColor(score));
  return svg;
}

function unavailable(card: WatchCard, r: Report): string | null {
  switch (card.source) {
    case "breaches":
      if (r.pwned === "checked" || r.pwned === "partial") return null;
      if (!r.checkBreaches || r.pwned === "disabled") return t("Vérification des fuites désactivée.", "Breach check turned off.");
      return checkingBreaches ? t("Vérification des fuites…", "Checking for breaches…") : t("En attente du réseau.", "Waiting for the network.");
    case "sites":
      if (r.sitesChecked) return null;
      return r.checkBreaches
        ? t("Catalogue des sites pas encore téléchargé.", "Site catalog not downloaded yet.")
        : t("Active « Vérifier les fuites » pour télécharger le catalogue des sites.", "Turn on “Check for breaches” to download the site catalog.");
    case "breachCatalog":
      if (r.breachCatalog) return null;
      return r.checkBreaches
        ? t("Catalogue des fuites pas encore téléchargé.", "Breach list not downloaded yet.")
        : t("Active « Vérifier les fuites » pour télécharger le catalogue des sites piratés.", "Turn on “Check for breaches” to download the list of breached sites.");
    default:
      return null;
  }
}

function watchtowerPage(): HTMLElement {
  const r = ui.report;
  if (!r) void loadReport();
  const levels = r?.strength ?? [];
  const total = levels.reduce((a, b) => a + b, 0);
  const colors = ["var(--red)", "var(--orange)", "var(--yellow)", "#00C7BE", "var(--green)"];
  const names = [t("Trop courts", "Too short"), t("Faibles", "Weak"), t("Moyens", "Fair"), t("Bons", "Good"), t("Excellents", "Excellent")];
  const strength = h("div", { class: "card pad" },
    h("div", { class: "card-head" }, h("span", { class: "bold" }, t("Force globale des mots de passe", "Overall Password Strength")),
      h("span", { class: "secondary" }, plural(total, t("1 mot de passe", "1 password"), t("%d mots de passe", "%d passwords")))),
    total === 0
      ? h("p", { class: "secondary" }, t("Aucun mot de passe à analyser pour l'instant.", "No passwords to analyze yet."))
      : h("div", {},
          h("div", { class: "bar" }, ...levels.map((n, i) => {
            if (!n) return null;
            const s = h("span");
            s.style.flex = String(n);
            s.style.background = colors[i]!;
            return s;
          })),
          h("div", { class: "legend" }, ...levels.map((n, i) => (n ? h("span", {}, h("i", { style: `background:${colors[i]}` }), `${names[i]} `, h("b", {}, String(n))) : null)))),
  );
  const cards = r
    ? watchCards().map((card) => {
        const ids = [...new Set(r.checks.filter((c) => card.checks.includes(c.check)).flatMap((c) => c.itemIds))];
        const note = unavailable(card, r);
        const alert = ALERT_IDS.has(card.id) && !note && ids.length > 0;
        const figure = h("span", { class: "wt-figure" }, note ? "–" : String(ids.length));
        if (!alert && !note && ids.length) figure.style.color = card.color;
        const el = h("div", { class: "card wt-card" + (alert ? " alert" : "") },
          h("div", { class: "wt-top" }, figure, tile(card.icon as IconName, alert ? "rgba(255,255,255,.22)" : card.color, 28)),
          h("div", { class: "bold" }, card.title),
          h("p", {}, note ?? card.message),
          h("button", { class: "wt-link", disabled: ids.length === 0, onclick: () => go({ kind: "list", filter: { kind: "ids", ids }, title: card.title }) },
            t("Voir les éléments", "Show Items"), icon("chevron_right", 16)));
        return el;
      })
    : [];
  return h(
    "div",
    { class: "page" },
    h("h1", { class: "large-title" }, "Watchtower"),
    h("p", { class: "secondary wt-status" }, r ? plural(r.itemsAnalyzed, t("1 élément analysé", "1 item analyzed"), t("%d éléments analysés", "%d items analyzed")) + (r.pwned === "checked" ? t(" · fuites vérifiées", " · breaches checked") : "")
      : t("Analyse…", "Analyzing…")),
    // RX top row (RXMacWatchtower): the gauge card beside the alert and the three counts.
    h("div", { class: "wt-top-row" },
      h("div", { class: "rx-card gauge-card" }, dial(r?.score)),
      h("div", { class: "wt-side" }, ...(r ? [wtAlert(r), h("div", { class: "stat-tiles" },
        statTile(r, "weak", t("Faibles", "Weak"), "#FF7A45", "lock"),
        statTile(r, "reused", t("Réutilisés", "Reused"), "#A35BF0", "duplicate"),
        statTile(r, "2fa", t("2FA disponible", "2FA Available"), "#14B8A6", "two_factor"))] : []))),
    strength,
    r ? breachSetting(r) : null,
    h("h2", { class: "wt-section" }, t("Améliorer", "Improve")),
    h("div", { class: "wt-grid" }, ...cards),
  );
}

const cardIds = (r: Report, id: string): string[] => {
  const card = watchCards().find((c) => c.id === id);
  return card ? [...new Set(r.checks.filter((c) => card.checks.includes(c.check)).flatMap((c) => c.itemIds))] : [];
};

/** The RX alert card: red with the compromised count, green when nothing is exposed, plain when breaches were not checked. */
function wtAlert(r: Report): HTMLElement {
  const card = watchCards().find((c) => c.id === "compromised")!;
  const ids = cardIds(r, "compromised");
  const note = unavailable(card, r);
  const kind = note ? "plain" : ids.length ? "red" : "green";
  const title = note ? t("Fuites non vérifiées", "Breaches Not Checked") : ids.length
    ? plural(ids.length, t("1 mot de passe compromis", "1 compromised password"), t("%d mots de passe compromis", "%d compromised passwords"))
    : t("Aucun problème", "No Issues");
  const body = note ?? (ids.length ? card.message : t("Aucun mot de passe exposé ou compromis.", "No exposed or compromised passwords."));
  return h("button", { class: "wt-alert " + kind, disabled: !ids.length, onclick: () => go({ kind: "list", filter: { kind: "ids", ids }, title: card.title }) },
    h("span", { class: "alert-disc" }, icon(kind === "green" ? "shield_lock" : "warning", 20)),
    h("span", { class: "row-text" }, h("span", { class: "alert-title" }, title), h("span", { class: "alert-body" }, body)),
    ids.length ? icon("chevron_right", 16) : null);
}

function statTile(r: Report, id: string, label: string, color: string, ic: IconName): HTMLElement {
  const ids = cardIds(r, id);
  const disc = h("span", { class: "stat-disc" }, icon(ic, 16));
  disc.style.background = color;
  return h("button", { class: "stat-tile", disabled: !ids.length, onclick: () => go({ kind: "list", filter: { kind: "ids", ids }, title: label }) },
    disc, h("span", { class: "stat-count" }, String(ids.length)), h("span", { class: "stat-label" }, label));
}

/** "Vérifier les fuites", with what is sent (the iPhone's BreachSettingCard). */
function breachSetting(r: Report): HTMLElement {
  const toggle = h("input", { type: "checkbox", class: "switch", id: "check-breaches", checked: r.checkBreaches, "aria-label": t("Vérifier les fuites", "Check for Breaches") });
  toggle.addEventListener("change", async () => {
    try {
      await call("set_check_breaches", { on: toggle.checked });
      ui.report = null;
      renderMain();
      void loadReport();
    } catch (e) {
      toast(message(e));
    }
  });
  const sent = h("p", { class: "footnote", hidden: true }, t("Pour chaque mot de passe, Cleon envoie à Have I Been Pwned les 5 premiers caractères de son empreinte SHA-1, partagés avec des centaines d'autres, et compare le reste ici. La liste des sites piratés est téléchargée en entier et gardée une semaine. Les sites qui proposent la double authentification ou les passkeys viennent du catalogue fourni avec l'app. Désactivé, aucune requête réseau.",
    "For each password, Cleon sends Have I Been Pwned the first 5 characters of its SHA-1 hash, shared with hundreds of others, and compares the rest here. The list of breached sites is downloaded whole and kept for a week. Sites that offer two-factor authentication or passkeys come from the catalog shipped with the app. When off, no network request."));
  const info = h("button", { class: "bar-text small-link", type: "button", onclick: () => (sent.hidden = !sent.hidden) }, t("Ce qui est envoyé", "What is sent"));
  return h("div", { class: "card list-card breach-card" },
    h("label", { class: "toggle-row", for: "check-breaches" }, tile("compromised", "var(--red)", 30),
      h("span", { class: "row-text" }, h("span", { class: "bold" }, t("Vérifier les fuites", "Check for Breaches")), h("span", { class: "row-sub" }, t("Tes mots de passe ne quittent jamais l'appareil.", "Your passwords never leave this device."))), toggle),
    h("div", { class: "breach-info" }, info, checkingBreaches ? h("span", { class: "row-sub" }, t("Vérification des fuites…", "Checking for breaches…")) : null),
    sent);
}

// ---- settings --------------------------------------------------------------------------------------

const settingsPages = (): { key: string; title: string }[][] => [
  [{ key: "general", title: t("Général", "General") }, { key: "security", title: t("Sécurité", "Security") }, { key: "autofill", title: t("Remplissage automatique", "AutoFill") }, { key: "sync", title: "Sync" }],
  [{ key: "accounts", title: t("Comptes", "Accounts") }, { key: "vaults", title: t("Coffres", "Vaults") }, { key: "contacts", title: "Contacts" }, { key: "family", title: t("Famille", "Family") },
   { key: "devices", title: t("Appareils", "Devices") }, { key: "travel", title: "Travel Mode" }, { key: "crypto", title: "Crypto" }, { key: "developer", title: t("Agents", "Agents") }],
  [{ key: "about", title: t("À propos", "About") }],
];

function settingsArt(key: string, size = 26): HTMLElement {
  const img = h("img", { class: "settings-art", src: `assets/settings/${key}.png`, alt: "", draggable: false });
  img.style.width = img.style.height = size + "px";
  return img;
}

function openSettings(start = "general"): void {
  const s = sheet(t("Réglages", "Settings"), { cancel: t("Fermer", "Close"), wide: true });
  s.dialog.classList.add("settings");
  const side = h("div", { class: "settings-side" });
  const pane = h("div", { class: "settings-pane" });
  const show = async (key: string) => {
    for (const b of side.querySelectorAll("button")) b.classList.toggle("active", b.dataset.key === key);
    pane.replaceChildren(...(await settingsPage(key, () => show(key))));
  };
  side.append(...settingsPages().map((group) => h("div", { class: "card list-card" }, ...group.map((p) => {
    const b = h("button", { class: "nav", onclick: () => void show(p.key) }, settingsArt(p.key), h("span", { class: "nav-label" }, p.title));
    b.dataset.key = p.key;
    return b;
  }))));
  s.body.append(h("div", { class: "settings-grid" }, side, pane));
  void show(start);
}

/** The Home hero's wallpaper (RXWallpaperSettings, Mac): theme chips, the tone, a grid of thumbnails. Applied at once. */
let wallpaperTheme: string | null = null;
function wallpaperPicker(redraw: () => void): Node[] {
  const current = currentWallpaper();
  const m = /^wp-([a-z]+)-([1-6])(?:-(noir|clair))?$/.exec(current);
  const theme = wallpaperThemes().find((x) => x.key === (wallpaperTheme ?? m?.[1])) ?? wallpaperThemes()[0]!;
  const tone = (theme.key === m?.[1] ? (m?.[3] ?? "") : "") as Tone;
  const chips = h("div", { class: "wp-chips" }, ...wallpaperThemes().map((x) =>
    h("button", { class: "wp-chip" + (x.key === theme.key ? " on" : ""), onclick: () => { wallpaperTheme = x.key; redraw(); } }, x.name)));
  const pick = (name: string) => {
    setWallpaper(name);
    if (ui.page.kind === "home") renderMain();
    redraw();
  };
  const tones = theme.tones
    ? h("div", { class: "segmented wp-tones" }, ...([["", t("Naturel", "Natural")], ["noir", t("Noir", "Black")], ["clair", t("Clair", "Light")]] as [Tone, string][]).map(([v, label]) =>
        h("button", { class: v === tone ? "on" : "", onclick: () => pick(wallpaperName(theme.key, Number(m?.[1] === theme.key ? m[2] : 1), v)) }, label)))
    : null;
  const grid = h("div", { class: "wp-grid" }, ...[1, 2, 3, 4, 5, 6].map((n) => {
    const name = wallpaperName(theme.key, n, theme.tones ? tone : "");
    return h("button", { class: "wp-tile" + (name === current ? " on" : ""), title: `${theme.name} ${n}`, onclick: () => pick(name) },
      h("img", { src: wallpaperUrl(name, true), alt: "", draggable: false }), name === current ? h("span", { class: "wp-check", "aria-hidden": "true" }, "✓") : null);
  }));
  return [h("div", { class: "caps" }, t("Fond d'écran de l'accueil", "Home Wallpaper")), h("div", { class: "card pad wp-card" }, chips, tones, grid)];
}

async function settingsPage(key: string, redraw: () => void): Promise<Node[]> {
  const title = settingsPages().flat().find((p) => p.key === key)?.title ?? "";
  const head = h("h2", { class: "settings-title" }, title);
  const row = (label: string, value: string) => h("div", { class: "row static" }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, label)), h("span", { class: "secondary" }, value));
  const note = (text: string) => [head, h("div", { class: "card pad notyet" }, settingsArt(key, 44), h("p", { class: "secondary" }, text))];
  switch (key) {
    case "general": {
      const status = await call<Status>("status");
      return [head, ...wallpaperPicker(redraw), h("div", { class: "caps" }, t("Général", "General")), h("div", { class: "card list-card" }, row(t("Verrouillage automatique", "Auto-Lock"), t(`${status.autoLockMinutes} minutes`, `${status.autoLockMinutes} minutes`)),
        row(t("Langue", "Language"), t("Français (système)", "English (system)")),
        iconsToggle(status.siteIcons, redraw)),
        h("p", { class: "footnote" }, t("Cleon se verrouille aussi quand la session Windows se verrouille.", "Cleon also locks when the Windows session locks.")),
        h("div", { class: "caps" }, t("Importer", "Import")),
        h("div", { class: "card list-card" }, h("button", { class: "row", id: "open-import", onclick: () => importSheet() }, tile("import", "var(--blue)", 28),
          h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Importer…", "Import…")), h("span", { class: "row-sub" }, t("Apple, 1Password, Bitwarden, navigateurs et 8 autres.", "Apple, 1Password, Bitwarden, browsers and 8 more."))), icon("chevron_right", 18, "chev"))),
        h("div", { class: "caps" }, t("Sauvegarde", "Backup")),
        h("div", { class: "card list-card" },
          h("button", { class: "row", id: "open-backup", onclick: () => backupSheet() }, tile("lock", "var(--accent)", 28), h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Sauvegarde chiffrée…", "Encrypted Backup…"))), icon("chevron_right", 18, "chev")),
          h("button", { class: "row", id: "open-restore", onclick: () => restoreSheet() }, tile("restore", "var(--green)", 28), h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Restaurer…", "Restore…"))), icon("chevron_right", 18, "chev")),
          h("button", { class: "row", id: "open-csv", onclick: () => csvSheet() }, tile("description", "var(--red)", 28), h("span", { class: "row-text" }, h("span", { class: "row-title destructive" }, t("Export CSV non chiffré…", "Unencrypted CSV Export…"))), icon("chevron_right", 18, "chev"))),
        h("p", { class: "footnote" }, t("Restaurer n'écrase rien. Le CSV sert seulement à changer de gestionnaire.", "Restoring overwrites nothing. Use the CSV only to switch managers."))];
    }
    case "security": {
      const status = await call<Status>("status");
      const hello = await call<HelloStatus>("hello_status").catch(() => null);
      const available = hello?.availability === "available";
      const toggle = h("input", { type: "checkbox", class: "switch", id: "hello-toggle", checked: !!hello?.wanted, disabled: !available && !hello?.wanted, "aria-label": t(`Déverrouiller avec ${HELLO}`, `Unlock with ${HELLO}`) });
      toggle.addEventListener("change", async () => {
        if (!toggle.checked) {
          await call("disable_hello").catch((e) => toast(message(e)));
          redraw();
          return;
        }
        toggle.checked = false;
        enableHello(redraw);
      });
      const unlock = [
        h("div", { class: "caps" }, t("Déverrouillage", "Unlock")),
        h("div", { class: "card list-card" },
          h("label", { class: "toggle-row", for: "hello-toggle" }, h("span", { class: "row-text" }, h("span", {}, t(`Déverrouiller avec ${HELLO}`, `Unlock with ${HELLO}`))), toggle),
          row(t("Mot de passe maître", "Master Password"), t("Tous les 14 jours", "Every 14 days"))),
        h("p", { class: "footnote" }, available || hello?.wanted
          ? t("Aussi demandé après un redémarrage.", "Also asked after a restart.")
          : t(`${HELLO} n'est pas configuré sur cet appareil.`, `${HELLO} is not set up on this device.`)),
      ];
      return [head, ...unlock, h("div", { class: "card list-card spaced" },
        h("button", { class: "row", onclick: () => changePassword() }, tile("key", "#E09400", 28), h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Changer le mot de passe maître", "Change Master Password"))), icon("chevron_right", 18, "chev")),
        h("button", { class: "row", onclick: () => void lockNow() }, tile("lock", "var(--accent)", 28), h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Verrouiller maintenant", "Lock Now"))))),
        h("p", { class: "footnote" }, t(`Les clés de cet appareil sont scellées par ${status.protection === "dpapi" ? "Windows (DPAPI)" : status.protection}. La fenêtre est exclue des captures d'écran.`,
          `This device's keys are sealed by ${status.protection === "dpapi" ? "Windows (DPAPI)" : status.protection}. The window is excluded from screen captures.`)),
        h("div", { class: "caps" }, t("Presse-papiers", "Clipboard")),
        h("div", { class: "card list-card" }, row(t("Effacer après", "Clear After"), "90 s")),
        h("p", { class: "footnote" }, t("Un secret copié reste hors de l'historique Windows (Win+V) et du presse-papiers cloud.", "A copied secret stays out of Windows clipboard history (Win+V) and the cloud clipboard."))];
    }
    case "accounts": {
      const acc = await call<Account>("account");
      const name = h("input", { value: acc.name, placeholder: t("Ton prénom", "Your first name") });
      return [head, h("div", { class: "caps" }, t("Profil", "Profile")), h("div", { class: "card" }, name),
        h("button", { class: "bar-text", onclick: async () => {
          await call("set_profile_name", { name: name.value });
          await refresh(undefined);
          toast(t("Enregistré", "Saved"));
        } }, t("Enregistrer le nom", "Save Name")),
        h("div", { class: "caps" }, t("Compte Cleon", "Cleon Account")),
        h("div", { class: "card list-card" }, row(t("Identifiant", "ID"), acc.accountId)),
        h("p", { class: "footnote" }, t("Cet identifiant est imprimé sur ton Emergency Kit.", "This ID is printed on your Emergency Kit."))];
    }
    case "devices": {
      return devicesPage(head, redraw);
    }
    case "vaults":
      return [head, h("div", { class: "card list-card" },
        ...ui.vaults.map((v) => h("button", { class: "row", onclick: () => vaultEditor(v, redraw) }, monogram(v.name.slice(0, 1).toUpperCase(), vaultColor(v.color), 30),
          h("span", { class: "row-text" }, h("span", { class: "row-title" }, v.name), h("span", { class: "row-sub" }, countLabel(v.itemCount))), icon("chevron_right", 18, "chev"))),
        h("button", { class: "row", onclick: () => vaultEditor(null, redraw) }, icon("add", 22, "accent"), h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Nouveau coffre", "New Vault")))))];
    case "about":
      return [head, h("div", { class: "about" }, appIcon(80), h("div", { class: "bold big-text" }, "Cleon"), h("div", { class: "secondary" }, "Version 0.1.0")),
        h("div", { class: "card list-card" }, row(t("Licence", "License"), "AGPL-3.0"), row(t("Code source", "Source Code"), "github.com/soma-intelligence/onepass"),
          row(t("Icônes de l'interface", "Interface Icons"), "Material Symbols, Apache-2.0")),
        h("p", { class: "footnote" }, t("Chiffré de bout en bout. Ton coffre ne quitte pas ce PC sans ton mot de passe maître et ta Secret Key.", "End-to-end encrypted. Your vault never leaves this PC without your master password and Secret Key."))];
    case "autofill":
      return note(t("Le remplissage dans les navigateurs (extension et pont natif) arrive sur Windows. En attendant, copie une valeur depuis l'élément : elle est effacée du presse-papiers après 90 secondes.",
        "Filling in browsers (extension and native bridge) is coming to Windows. Meanwhile, copy a value from the item: it is cleared from the clipboard after 90 seconds."));
    case "sync":
      return syncPage(head, redraw);
    case "contacts":
      return contactsPage(head, redraw);
    case "family":
      return familyPage(head, redraw);
    case "travel":
      return travelPage(head, redraw);
    case "crypto":
      return note(t("Les portefeuilles crypto se rangent déjà comme éléments. Le suivi des soldes arrive sur Windows.", "Crypto wallets can already be stored as items. Balance tracking is coming to Windows."));
    default:
      return note(t("Les agents (serveur MCP, agent SSH) demandent un canal de contrôle que la version Windows n'ouvre pas encore.", "Agents (MCP server, SSH agent) need a control channel the Windows version does not open yet."));
  }
}

// ---- backup, restore, import, plaintext export ---------------------------------------------

/** The children worth appending (a condition may leave null). */
const keep = (...xs: (Node | null | undefined | false)[]): Node[] => xs.filter((x): x is Node => !!x);

interface Saved {
  saved: boolean;
  cloud: boolean;
  fileName: string;
}
interface ArchiveInfo {
  fileName: string;
  kind: "backup" | "export";
  createdAt: number;
  newerVersion: boolean;
  hasPassphrase: boolean;
  signed: boolean;
  forThisAccount: boolean;
}
interface TypeCount {
  itemType: string;
  count: number;
}
interface RestoreSummary {
  kind: "backup" | "export";
  createdAt: number;
  vaultsCreated: number;
  items: number;
  byType: TypeCount[];
  skipped: number;
  signatureVerified: boolean;
  epochMissing: boolean;
}
interface ImportDuplicate {
  index: number;
  incoming: Summary;
  existing: Summary;
  differences: string[];
  exact: boolean;
  suggested: "merge" | "skip" | "import";
}
interface ImportSummary {
  format: string;
  items: number;
  byType: TypeCount[];
  warnings: { code: string; count: number }[];
  skipped: number;
  updated: number;
  added: number;
  fixed: number;
  converted: number;
  archivedDuplicates: number;
  unchanged: number;
  duplicates: ImportDuplicate[];
  merged: number;
  skippedDuplicates: number;
  separate: number;
}

/** Saved, or held back because the folder syncs to a cloud (the Apple apps' warning). */
async function afterSave(r: Saved, done: string, cloudBody: string, onSaved: () => void): Promise<void> {
  if (r.saved) {
    toast(done);
    onSaved();
    return;
  }
  if (!r.cloud) return;
  const s = sheet("", {
    action: t("Enregistrer quand même", "Save Anyway"),
    onAction: async (sh) => {
      sh.close();
      try {
        if (await call<boolean>("save_pending")) {
          toast(done);
          onSaved();
        }
      } catch (e) {
        toast(message(e));
      }
    },
  });
  s.dialog.classList.add("alert");
  s.dialog.addEventListener("close", () => void call("discard_pending").catch(() => {}));
  s.body.append(h("p", { class: "alert-title" }, t("Cet emplacement est synchronisé dans le cloud", "This location syncs to the cloud")), h("p", { class: "alert-text" }, cloudBody));
}

function backupError(e: unknown): string {
  const err = e as UiError;
  if (err?.code === "Validation" && err.detail.startsWith("passphrase")) return t("Trop facile à deviner : allonge-la ou ajoute des mots.", "Too easy to guess: make it longer or add words.");
  if (err?.code === "InvalidInput" && err.detail.includes("passphrase")) return t("Phrase de passe illisible.", "Unreadable passphrase.");
  return message(e);
}

/** Sauvegarde chiffrée: master password, passphrase twice, then where to save. */
function backupSheet(): void {
  const pw = secretInput("bk-pw", t("Mot de passe maître", "Master Password"), "current-password");
  const a = secretInput("bk-pass", t("Phrase de passe de la sauvegarde", "Backup Passphrase"), "new-password");
  const b = secretInput("bk-pass2", t("Confirmer la phrase de passe", "Confirm the passphrase"), "new-password");
  const advice = t("Choisis une phrase longue que tu n'utilises nulle part ailleurs, par exemple plusieurs mots. Cleon refuse une phrase trop facile à deviner.",
    "Choose a long passphrase you don't use anywhere else, several words for example. Cleon refuses a passphrase that is too easy to guess.");
  const foot = h("p", { class: "footnote" }, advice);
  const err = h("div", { class: "error", role: "alert" });
  const check = () => {
    const mismatch = !!b.input.value && a.input.value !== b.input.value;
    foot.textContent = mismatch ? t("Les deux phrases de passe ne correspondent pas.", "The two passphrases don't match.") : advice;
    foot.classList.toggle("error-text", mismatch);
    action.disabled = !pw.input.value || !a.input.value || a.input.value !== b.input.value;
  };
  const s = sheet(t("Sauvegarde chiffrée", "Encrypted Backup"), {
    action: t("Exporter", "Export"),
    onAction: async (sh) => {
      err.textContent = "";
      action.disabled = true;
      action.textContent = "…";
      try {
        const r = await call<Saved>("export_backup", { password: pw.input.value, passphrase: a.input.value });
        if (r.saved || r.cloud) {
          pw.input.value = a.input.value = b.input.value = "";
          sh.close();
        }
        await afterSave(r, t("Sauvegarde enregistrée.", "Backup saved."),
          t("Le fichier sera copié sur les serveurs de ce service et sur tes autres appareils. Il reste chiffré, mais sa sécurité ne tient plus qu'à ta phrase de passe.",
            "The file will be copied to this service's servers and to your other devices. It stays encrypted, but its security then rests on your passphrase alone."), () => {});
      } catch (e) {
        err.textContent = backupError(e);
      } finally {
        action.textContent = t("Exporter", "Export");
        check();
      }
    },
  });
  const action = s.dialog.querySelector(".bar-text.bold") as HTMLButtonElement;
  for (const x of [pw, a, b]) x.input.addEventListener("input", check);
  check();
  s.body.append(
    h("p", { class: "secondary sheet-intro" }, t("Une archive Cleon chiffrée de tout ce que cet appareil contient, coffres et éléments à la corbeille compris. Elle s'ouvre avec la phrase de passe choisie ici ou avec ton compte.",
      "An encrypted Cleon archive of everything this device holds, vaults and items in the trash included. It opens with the passphrase chosen here or with your account.")),
    pw.box, a.box, b.box, foot, err,
    h("p", { class: "footnote" }, t("Garde aussi ta phrase de passe : sans elle ni ton compte, la sauvegarde ne s'ouvre pas.", "Keep your passphrase too: without it or your account, the backup won't open.")),
    h("p", { class: "footnote" }, t("Choisis un emplacement hors ligne, par exemple une clé USB.", "Choose an offline location, such as a USB drive.")),
  );
  pw.input.focus();
}

/** "12 connexions · 3 cartes bancaires": counts by type, most common first. */
function countsLine(byType: TypeCount[]): HTMLElement {
  return h("div", { class: "count-tiles" }, ...byType.map((c) => {
    const cat = category(c.itemType);
    return h("div", { class: "count-tile card" }, art(c.itemType, 30), h("span", { class: "figure small" }, String(c.count)), h("span", { class: "row-sub" }, c.count === 1 ? cat.singular : cat.plural));
  }));
}

function restoreError(e: unknown): string {
  const err = e as UiError;
  const d = err?.detail ?? "";
  if (err?.code === "Integrity") return t("Cette sauvegarde a été modifiée ou abîmée : sa signature ou son contenu ne correspond pas. Rien n'a été restauré.", "This backup was changed or damaged: its signature or its content does not match. Nothing was restored.");
  if (err?.code === "WrongPassword" || (err?.code === "InvalidInput" && /"passphrase"/.test(d))) return t("Phrase de passe incorrecte.", "Wrong passphrase.");
  if (d.includes("archive passphrase")) return t("Cette sauvegarde vient d'un autre compte : saisis sa phrase de passe.", "This backup comes from another account: enter its passphrase.");
  if (d.includes("archive of another account")) return t("Cette sauvegarde appartient à un autre compte et n'a pas de phrase de passe : elle ne s'ouvre qu'avec ce compte.", "This backup belongs to another account and has no passphrase: it opens only with that account.");
  if (d.includes("newer version")) return t("Cette sauvegarde vient d'une version plus récente de Cleon. Mets l'app à jour, puis réessaie.", "This backup comes from a newer version of Cleon. Update the app, then try again.");
  if (err?.code === "InvalidInput") return t("Ce fichier n'est pas une sauvegarde Cleon.", "This file is not a Cleon backup.");
  if (err?.code === "TooLarge" || err?.code === "Unreadable") return t("Ce fichier n'a pas pu être lu, ou il est trop gros.", "This file could not be read, or it is too large.");
  return message(e);
}

/** Restaurer une sauvegarde: choose the .onepass file, check its header, preview, restore. */
function restoreSheet(preloaded?: ArchiveInfo): void {
  const content = h("div", {});
  const err = h("div", { class: "error", role: "alert" });
  let info: ArchiveInfo | null = null;
  let passphrase: string | undefined;
  let preview: RestoreSummary | null = null;
  const s = sheet(t("Restaurer une sauvegarde", "Restore a Backup"), {
    action: t("Restaurer", "Restore"),
    wide: true,
    onAction: async (sh) => {
      if (!preview || preview.items === 0) return;
      err.textContent = "";
      action.disabled = true;
      try {
        const done = await call<RestoreSummary>("restore_backup", { passphrase: passphrase ?? null });
        await refresh(undefined);
        showDone(done, sh);
      } catch (e) {
        err.textContent = restoreError(e);
        action.disabled = false;
      }
    },
  });
  s.dialog.addEventListener("close", () => void call("forget_file").catch(() => {}));
  const action = s.dialog.querySelector(".bar-text.bold") as HTMLButtonElement;
  action.disabled = true;
  const signatureLine = (i: ArchiveInfo): string =>
    preview?.signatureVerified
      ? t("Signature de ton compte vérifiée", "Your account's signature verified")
      : i.forThisAccount
        ? t("Signée par ton compte : la signature est vérifiée à l'ouverture", "Signed by your account: the signature is checked when it opens")
        : i.signed
          ? t("Signée par un autre compte : seule la phrase de passe protège ce fichier", "Signed by another account: only the passphrase protects this file")
          : t("Non signée : seule la phrase de passe protège ce fichier", "Not signed: only the passphrase protects this file");
  const draw = () => {
    if (!info) {
      content.replaceChildren(
        h("p", { class: "secondary sheet-intro" }, t("Choisis un fichier .onepass : une sauvegarde chiffrée de ce compte, ou une sauvegarde d'un autre compte avec sa phrase de passe. Rien de ce qui est déjà dans Cleon n'est remplacé.",
          "Choose a .onepass file: an encrypted backup of this account, or another account's backup with its passphrase. Nothing already in Cleon is replaced.")),
        h("button", { class: "capsule prominent", type: "button", id: "pick-backup", onclick: () => void pick() }, t("Choisir une sauvegarde…", "Choose a Backup…")),
      );
      return;
    }
    const i = info;
    const file = h("div", { class: "card list-card" },
      h("div", { class: "row static" }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Fichier", "File"))), h("span", { class: "secondary" }, i.fileName)),
      h("div", { class: "row static" }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, "Type")), h("span", { class: "secondary" }, i.kind === "backup" ? t("Sauvegarde du compte", "Account backup") : t("Export Cleon", "Cleon export"))),
      h("div", { class: "row static" }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Créée le", "Created"))), h("span", { class: "secondary" }, dateTime(i.createdAt))),
      h("div", { class: "row static" }, icon(i.forThisAccount || preview?.signatureVerified ? "shield_check" : "warning", 20, i.forThisAccount ? "green" : "orange"), h("span", { class: "row-text" }, h("span", { class: "row-sub" }, signatureLine(i)))));
    const parts: (Node | null)[] = [h("div", { class: "caps" }, t("Fichier", "File")), file];
    if (!i.forThisAccount && !preview) {
      const pass = secretInput("rs-pass", t("Phrase de passe de la sauvegarde", "Backup Passphrase"), "off");
      const open = h("button", { class: "capsule", type: "button", onclick: async () => {
        passphrase = pass.input.value;
        await load();
      } }, t("Ouvrir", "Open"));
      pass.input.addEventListener("keydown", (e) => e.key === "Enter" && open.click());
      parts.push(h("div", { class: "caps" }, t("Phrase de passe", "Passphrase")), pass.box, h("div", { class: "buttons-row" }, open),
        h("p", { class: "footnote" }, t("Cette sauvegarde n'est pas pour ce compte : elle s'ouvre avec la phrase de passe choisie à l'export.", "This backup is not for this account: it opens with the passphrase chosen when it was exported.")));
      queueMicrotask(() => pass.input.focus());
    }
    if (preview) {
      const p = preview;
      parts.push(h("div", { class: "caps" }, t("Contenu", "Contents")),
        p.items === 0 ? h("p", { class: "secondary" }, t("Tout ce que contient cette sauvegarde est déjà dans Cleon.", "Everything in this backup is already in Cleon.")) : countsLine(p.byType),
        p.vaultsCreated ? h("p", { class: "secondary" }, plural(p.vaultsCreated, t("1 coffre sera créé", "1 vault will be created"), t("%d coffres seront créés", "%d vaults will be created"))) : null,
        p.skipped ? h("p", { class: "secondary" }, plural(p.skipped, t("1 élément déjà présent, laissé tel quel", "1 item already here, left as it is"), t("%d éléments déjà présents, laissés tels quels", "%d items already here, left as they are"))) : null,
        h("p", { class: "footnote" }, t("Les éléments gardent leur identifiant, ceux de la corbeille et les archivés compris. Une restauration signée par ton compte est enregistrée pour tes autres appareils.",
          "Items keep their identifier, deleted and archived ones included. A restore signed by your account is recorded for your other devices.")));
    }
    content.replaceChildren(...keep(...parts));
    action.disabled = !preview || preview.items === 0;
  };
  const load = async () => {
    err.textContent = "";
    try {
      preview = await call<RestoreSummary>("preview_restore", { passphrase: passphrase ?? null });
    } catch (e) {
      err.textContent = restoreError(e);
      preview = null;
    }
    draw();
  };
  const accept = async (i: ArchiveInfo) => {
    info = i;
    preview = null;
    passphrase = undefined;
    err.textContent = "";
    if (i.newerVersion) err.textContent = t("Cette sauvegarde vient d'une version plus récente de Cleon. Mets l'app à jour, puis réessaie.", "This backup comes from a newer version of Cleon. Update the app, then try again.");
    else if (!i.forThisAccount && !i.hasPassphrase) err.textContent = t("Cette sauvegarde appartient à un autre compte et n'a pas de phrase de passe : elle ne s'ouvre qu'avec ce compte.", "This backup belongs to another account and has no passphrase: it opens only with that account.");
    else if (i.forThisAccount) return load();
    draw();
  };
  const pick = async () => {
    try {
      const i = await call<ArchiveInfo | null>("pick_backup");
      if (i) await accept(i);
    } catch (e) {
      err.textContent = restoreError(e);
    }
  };
  const showDone = (d: RestoreSummary, sh: Sheet) => {
    action.hidden = true;
    (sh.dialog.querySelector(".sheet-bar .bar-text") as HTMLElement).textContent = t("Terminé", "Done");
    content.replaceChildren(...keep(
      h("div", { class: "done-head" }, icon("check_circle", 44, "green"), h("h2", {}, plural(d.items, t("1 élément restauré", "1 item restored"), t("%d éléments restaurés", "%d items restored")))),
      countsLine(d.byType),
      d.skipped ? h("p", { class: "secondary" }, plural(d.skipped, t("1 élément était déjà là.", "1 item was already here."), t("%d éléments étaient déjà là.", "%d items were already here."))) : null,
      d.epochMissing ? h("p", { class: "warning-text" }, t("Les éléments sont restaurés, mais la restauration n'a pas pu être enregistrée pour tes autres appareils. Synchronise, puis restaure à nouveau ce fichier.",
        "The items are restored, but the restore could not be recorded for your other devices. Sync, then restore this file again.")) : null,
    ));
    err.textContent = "";
  };
  s.body.append(content, err);
  if (preloaded) void accept(preloaded);
  else draw();
}

/** Export CSV non chiffré: warnings, "Je comprends…", the vaults, the master password. */
function csvSheet(): void {
  const understood = h("input", { type: "checkbox", class: "switch", id: "csv-ok", "aria-label": t("Je comprends que ce fichier n'est pas chiffré", "I understand this file is not encrypted") });
  const chosen = new Set(ui.vaults.map((v) => v.id));
  const pw = secretInput("csv-pw", t("Mot de passe maître", "Master Password"), "current-password");
  const err = h("div", { class: "error", role: "alert" });
  const check = () => (action.disabled = !understood.checked || !pw.input.value || chosen.size === 0);
  const s = sheet(t("Export non chiffré", "Unencrypted Export"), {
    action: t("Exporter", "Export"),
    onAction: async (sh) => {
      err.textContent = "";
      action.disabled = true;
      try {
        const all = chosen.size === ui.vaults.length;
        const r = await call<Saved>("export_csv", { password: pw.input.value, vaultIds: all ? [] : [...chosen] });
        if (r.saved || r.cloud) {
          pw.input.value = "";
          sh.close();
        }
        await afterSave(r, t("Fichier enregistré.", "File saved."), t("Le fichier, en clair, sera copié sur les serveurs de ce service et sur tes autres appareils.", "The file, unencrypted, will be copied to this service's servers and to your other devices."),
          () => toast(t("Supprime le fichier dès que tu n'en as plus besoin, corbeille comprise.", "Delete the file as soon as you no longer need it, and empty the Trash.")));
      } catch (e) {
        err.textContent = message(e);
      } finally {
        check();
      }
    },
  });
  const action = s.dialog.querySelector(".bar-text.bold") as HTMLButtonElement;
  action.classList.add("destructive");
  understood.addEventListener("change", check);
  pw.input.addEventListener("input", check);
  check();
  s.body.append(
    h("div", { class: "card pad warning-card" }, icon("warning", 26, "red"),
      h("div", {}, h("p", { class: "bold red-text" }, t("Ce fichier n'est pas chiffré. Toute personne ou app qui y accède lit tous tes mots de passe, codes et notes. Un tableur peut exécuter une cellule qui commence par « = ». Les passkeys et les lieux n'y figurent pas.",
        "This file is not encrypted. Anyone or any app that can open it reads all your passwords, codes and notes. A spreadsheet may run a cell that starts with \"=\". Passkeys and locations are not in it.")),
        h("p", { class: "secondary" }, t("Pour une copie de sécurité, préfère la sauvegarde chiffrée. N'utilise ce fichier que pour passer à un autre gestionnaire, puis supprime-le.",
          "For a safety copy, use the encrypted backup. Use this file only to move to another password manager, then delete it.")))),
    h("div", { class: "card list-card spaced" }, h("label", { class: "toggle-row", for: "csv-ok" }, h("span", {}, t("Je comprends que ce fichier n'est pas chiffré", "I understand this file is not encrypted")), understood)),
    h("div", { class: "caps" }, t("Coffres", "Vaults")),
    h("div", { class: "card list-card" }, ...ui.vaults.map((v) => {
      const box = h("input", { type: "checkbox", class: "switch", checked: true, "aria-label": v.name });
      box.addEventListener("change", () => (box.checked ? chosen.add(v.id) : chosen.delete(v.id), check()));
      return h("label", { class: "toggle-row" }, h("span", { class: "row-text" }, h("span", {}, v.name)), box);
    })),
    h("div", { class: "caps" }, t("Mot de passe maître", "Master Password")), pw.box,
    h("p", { class: "footnote" }, t("Les éléments de la corbeille ne sont pas exportés.", "Items in Recently Deleted are not exported.")),
    err,
  );
}

interface ImportSource {
  id: string;
  name: string;
  formats: string[];
  hint: string;
  group: 0 | 1 | 2;
}
const importSources = (): ImportSource[] => [
  { id: "apple", name: t("Mots de passe d'Apple", "Apple Passwords"), formats: ["safari-csv"], group: 0, hint: t("App Mots de passe : Fichier > Exporter tous les mots de passe vers un fichier.", "Passwords app: File > Export All Passwords to File.") },
  { id: "1password", name: "1Password", formats: ["1pux", "1password-csv"], group: 0, hint: t("Fichier > Exporter, puis le format 1PUX (ou CSV).", "File > Export, then the 1PUX format (or CSV).") },
  { id: "bitwarden", name: "Bitwarden", formats: ["bitwarden-json", "bitwarden-csv"], group: 0, hint: t("Outils > Exporter le coffre, en .json non chiffré ou en .csv.", "Tools > Export Vault, as unencrypted .json or .csv.") },
  { id: "nordpass", name: "NordPass", formats: ["nordpass-csv"], group: 0, hint: t("Réglages > Importer et exporter > Exporter les éléments (.csv).", "Settings > Import and Export > Export Items (.csv).") },
  { id: "dashlane", name: "Dashlane", formats: ["dashlane-zip", "dashlane-csv"], group: 0, hint: t("Réglages > Exporter les données > CSV (le .zip ou un des fichiers .csv).", "Settings > Export Data > CSV (the .zip or one of the .csv files).") },
  { id: "lastpass", name: "LastPass", formats: ["lastpass-csv"], group: 0, hint: t("Options avancées > Exporter > fichier CSV LastPass.", "Advanced Options > Export > LastPass CSV File.") },
  { id: "protonpass", name: "Proton Pass", formats: ["protonpass-csv"], group: 0, hint: t("Réglages > Exporter, au format CSV.", "Settings > Export, as CSV.") },
  { id: "keeper", name: "Keeper", formats: ["keeper-csv"], group: 0, hint: t("Réglages > Exporter > fichier .csv.", "Settings > Export > .csv file.") },
  { id: "enpass", name: "Enpass", formats: ["enpass-json"], group: 0, hint: t("Fichier > Exporter, au format .json.", "File > Export, as .json.") },
  { id: "roboform", name: "RoboForm", formats: ["roboform-csv"], group: 0, hint: t("Options > Exporter les identifiants et les notes (.csv).", "Options > Export logins and notes (.csv).") },
  { id: "keepass", name: "KeePass, KeePassXC", formats: ["keepass-xml"], group: 0, hint: t("Fichier > Exporter en XML KeePass 2 (le .kdbx ne se lit pas directement).", "File > Export as KeePass 2 XML (a .kdbx file can't be read directly).") },
  { id: "chrome", name: "Google Chrome", formats: ["chrome-csv"], group: 1, hint: t("Gestionnaire de mots de passe Google > Paramètres > Exporter les mots de passe.", "Google Password Manager > Settings > Export passwords.") },
  { id: "edge", name: "Microsoft Edge", formats: ["chrome-csv"], group: 1, hint: t("Paramètres > Mots de passe > ⋯ > Exporter les mots de passe.", "Settings > Passwords > ⋯ > Export passwords.") },
  { id: "brave", name: "Brave", formats: ["chrome-csv"], group: 1, hint: t("brave://password-manager/settings > Exporter les mots de passe.", "brave://password-manager/settings > Export passwords.") },
  { id: "opera", name: "Opera", formats: ["chrome-csv"], group: 1, hint: t("Réglages > Mots de passe > ⋯ > Exporter les mots de passe.", "Settings > Passwords > ⋯ > Export Passwords.") },
  { id: "arc", name: "Arc", formats: ["chrome-csv"], group: 1, hint: t("arc://password-manager/settings > Exporter les mots de passe.", "arc://password-manager/settings > Export passwords.") },
  { id: "vivaldi", name: "Vivaldi", formats: ["chrome-csv"], group: 1, hint: t("Réglages > Confidentialité > Mots de passe > Exporter.", "Settings > Privacy > Passwords > Export.") },
  { id: "firefox", name: "Firefox", formats: ["firefox-csv"], group: 1, hint: t("about:logins > ⋯ > Exporter les identifiants.", "about:logins > ⋯ > Export Logins.") },
  { id: "safari", name: "Safari", formats: ["safari-csv"], group: 1, hint: t("Fichier > Exporter les données de navigation, avec les mots de passe (.zip ou .csv).", "File > Export Browsing Data, with passwords (.zip or .csv).") },
  { id: "cxf", name: t("Autre gestionnaire (Credential Exchange)", "Other Password Manager (Credential Exchange)"), formats: ["cxf"], group: 2, hint: t("Fichier .json au format d'échange d'identifiants (CXF).", "A .json file in Credential Exchange Format (CXF).") },
  { id: "otpauth", name: t("Codes à usage unique", "One-Time Codes"), formats: ["otpauth"], group: 2, hint: t("Liens otpauth:// (Google Authenticator et autres), un par ligne.", "otpauth:// links (Google Authenticator and others), one per line.") },
  { id: "wifi", name: t("Réseaux Wi-Fi (codes QR)", "Wi-Fi Networks (QR Codes)"), formats: ["wifi-qr"], group: 2, hint: t("Texte des codes QR Wi-Fi (WIFI:S:...), un par ligne.", "Wi-Fi QR code text (WIFI:S:...), one per line.") },
  { id: "onepass-csv", name: t("Cleon (export CSV)", "Cleon (CSV Export)"), formats: ["onepass-csv"], group: 2, hint: t("Le fichier CSV en clair exporté par Cleon.", "The plain-text CSV file exported by Cleon.") },
];

function formatName(format: string): string {
  const names: Record<string, string> = {
    "1pux": "1Password (1PUX)",
    "1password-csv": "1Password (CSV)",
    "bitwarden-json": "Bitwarden (JSON)",
    "bitwarden-csv": "Bitwarden (CSV)",
    "chrome-csv": t("Chrome et navigateurs Chromium (CSV)", "Chrome and Chromium Browsers (CSV)"),
    "safari-csv": t("Mots de passe d'Apple, Safari (CSV)", "Apple Passwords, Safari (CSV)"),
    "firefox-csv": "Firefox (CSV)",
    "lastpass-csv": "LastPass (CSV)",
    "dashlane-csv": "Dashlane (CSV)",
    "dashlane-zip": "Dashlane (ZIP)",
    "protonpass-csv": "Proton Pass (CSV)",
    "keepass-xml": "KeePass (XML)",
    "cxf": "Credential Exchange",
    "otpauth": t("Codes à usage unique", "One-Time Codes"),
    "wifi-qr": t("Réseaux Wi-Fi (codes QR)", "Wi-Fi Networks (QR Codes)"),
    "onepass-csv": t("Cleon (export CSV)", "Cleon (CSV Export)"),
    "nordpass-csv": "NordPass (CSV)",
    "keeper-csv": "Keeper (CSV)",
    "enpass-json": "Enpass (JSON)",
    "roboform-csv": "RoboForm (CSV)",
  };
  return names[format] ?? format;
}

function importError(e: unknown): string {
  const err = e as UiError;
  const what = (/what: "([^"]*)"/.exec(err?.detail ?? "")?.[1] ?? err?.detail ?? "").toLowerCase();
  if (err?.code === "TooLarge") return t("Ce fichier est trop gros pour être importé.", "This file is too large to import.");
  if (err?.code === "Unreadable") return t("Impossible de lire ce fichier.", "Can't read this file.");
  if (err?.code !== "InvalidInput") return message(e);
  if (what.startsWith("encrypted bitwarden")) return t("Cet export Bitwarden est chiffré. Refais l'export en JSON non chiffré (ou en CSV), puis réessaie.", "This Bitwarden export is encrypted. Export again as unencrypted JSON (or CSV), then try again.");
  if (what.startsWith("encrypted dashlane")) return t("Cet export Dashlane est chiffré. Refais l'export en CSV, puis réessaie.", "This Dashlane export is encrypted. Export again as CSV, then try again.");
  if (what.startsWith("keepass kdbx")) return t("Les bases KeePass (.kdbx) ne se lisent pas directement. Exporte-la en XML KeePass 2, puis réessaie.", "KeePass databases (.kdbx) can't be read directly. Export it as KeePass 2 XML, then try again.");
  if (what.startsWith("onepass archive")) return t("C'est une archive Cleon chiffrée : elle ne s'importe pas ici.", "This is an encrypted Cleon archive. It can't be imported here.");
  if (what === "import format") return t("Format d'import inconnu.", "Unknown import format.");
  if (what === "import file too large" || what.startsWith("too many") || what.endsWith("too large")) return t("Ce fichier est trop gros pour être importé.", "This file is too large to import.");
  return t("Ce fichier ne correspond pas au format choisi, ou il est abîmé.", "This file doesn't match the chosen format, or it's damaged.");
}

function warningLine(code: string, n: number): string {
  const p = (one: string, many: string) => plural(n, one.replace("%d", "1"), many);
  switch (code) {
    case "field_moved":
      return p(t("%d valeur rangée dans la section Importé", "%d value placed in the Imported section"), t("%d valeurs rangées dans la section Importé", "%d values placed in the Imported section"));
    case "login_to_password":
      return p(t("%d identifiant sans nom d'utilisateur, gardé comme mot de passe", "%d login without a username, kept as a password"), t("%d identifiants sans nom d'utilisateur, gardés comme mots de passe", "%d logins without a username, kept as passwords"));
    case "to_secure_note":
      return p(t("%d élément gardé comme note sécurisée", "%d item kept as a secure note"), t("%d éléments gardés comme notes sécurisées", "%d items kept as secure notes"));
    case "totp_moved":
      return p(t("%d code à usage unique rangé dans la section Importé", "%d one-time code placed in the Imported section"), t("%d codes à usage unique rangés dans la section Importé", "%d one-time codes placed in the Imported section"));
    case "attachment_skipped":
      return p(t("%d pièce jointe non importée", "%d attachment not imported"), t("%d pièces jointes non importées", "%d attachments not imported"));
    case "unsupported_entry":
      return p(t("%d entrée d'un type non pris en charge, ignorée", "%d entry of an unsupported type, skipped"), t("%d entrées d'un type non pris en charge, ignorées", "%d entries of an unsupported type, skipped"));
    case "bad_date":
      return p(t("%d date illisible, gardée en texte", "%d unreadable date, kept as text"), t("%d dates illisibles, gardées en texte", "%d unreadable dates, kept as text"));
    case "passkey_needs_cxf":
      return p(t("%d clé d'accès absente du fichier : importe-la depuis 1Password avec l'échange d'identifiants", "%d passkey not in the file: import it from 1Password with Credential Exchange"),
        t("%d clés d'accès absentes du fichier : importe-les depuis 1Password avec l'échange d'identifiants", "%d passkeys not in the file: import them from 1Password with Credential Exchange"));
    case "skipped":
      return p(t("%d ligne vide, dossier ou élément supprimé ignoré", "%d empty row, folder or deleted item skipped"), t("%d lignes vides, dossiers ou éléments supprimés ignorés", "%d empty rows, folders or deleted items skipped"));
    default:
      return p(t("%d élément importé avec une remarque", "%d item imported with a note"), t("%d éléments importés avec une remarque", "%d items imported with a note"));
  }
}

const aspectWord = (a: string): string =>
  ({
    title: t("titre", "title"), username: t("identifiant", "username"), password: t("mot de passe", "password"), websites: t("sites", "websites"), totp: t("code de vérification", "verification code"),
    passkeys: "passkeys", notes: "notes", fields: t("champs", "fields"), attachments: t("pièces jointes", "attachments"), tags: "tags",
  })[a] ?? a;

/** Importer: choose the file (or the source first), check the preview, choose the vault, import. */
function importSheet(): void {
  const content = h("div", {});
  const err = h("div", { class: "error", role: "alert" });
  let source: ImportSource | null = null;
  let fileName = "";
  let format = "";
  let vaultId = (ui.page.kind === "list" && ui.page.filter.kind === "vault" ? ui.page.filter.id : ui.vaults[0]?.id) ?? "";
  let preview: ImportSummary | null = null;
  const choices = new Map<number, "merge" | "skip" | "import">();
  let query = "";
  const s = sheet(t("Importer", "Import"), {
    action: t("Importer", "Import"),
    wide: true,
    onAction: async (sh) => {
      if (!preview || preview.items === 0 || !vaultId) return;
      err.textContent = "";
      action.disabled = true;
      action.textContent = t("Import en cours…", "Importing…");
      try {
        const decisions = [...choices].map(([index, choice]) => ({ index, choice }));
        const done = await call<ImportSummary>("import_items", { format, vaultId, decisions });
        await refresh(undefined);
        showDone(done, sh);
      } catch (e) {
        err.textContent = importError(e);
        action.disabled = false;
      } finally {
        action.textContent = t("Importer", "Import");
      }
    },
  });
  s.dialog.classList.add("import-sheet");
  s.dialog.addEventListener("close", () => void call("forget_file").catch(() => {}));
  const action = s.dialog.querySelector(".bar-text.bold") as HTMLButtonElement;
  action.title = t("Importer (Ctrl+Entrée)", "Import (Ctrl+Enter)");
  const sync = () => (action.disabled = !preview || preview.items === 0 || !vaultId);
  sync();

  const pick = async () => {
    err.textContent = "";
    try {
      const picked = await call<{ fileName: string; format: string | null } | null>("pick_import");
      if (!picked) return;
      if (picked.format === "onepass") {
        const info = await call<ArchiveInfo>("pending_archive");
        s.close();
        restoreSheet(info);
        return;
      }
      if (picked.format === "pdf-text") {
        err.textContent = t("Les PDF d'identifiants ne s'importent pas encore sur Windows : exporte un CSV depuis l'app d'origine.", "Credentials PDFs can't be imported on Windows yet: export a CSV from the original app.");
        return;
      }
      const chosen = source && picked.format && source.formats.includes(picked.format) ? picked.format : source ? source.formats[0]! : picked.format;
      if (!chosen) {
        err.textContent = t("Format non reconnu. Choisis la source de l'export dans la liste.", "Unrecognized format. Choose where the export came from in the list.");
        return;
      }
      fileName = picked.fileName;
      format = chosen;
      choices.clear();
      await load();
    } catch (e) {
      err.textContent = importError(e);
    }
  };
  const load = async () => {
    err.textContent = "";
    try {
      preview = await call<ImportSummary>("preview_import", { format, vaultId });
      for (const d of preview.duplicates) if (!choices.has(d.index)) choices.set(d.index, d.suggested);
    } catch (e) {
      preview = null;
      err.textContent = importError(e);
    }
    draw();
  };
  const drawSources = (): Node[] => {
    const grid = h("div", { class: "source-groups" });
    const fill = () => {
      const q = query.trim().toLowerCase();
      const groups = [t("Gestionnaires de mots de passe", "Password Managers"), t("Navigateurs", "Browsers"), t("Autres formats", "Other Formats")];
      grid.replaceChildren(...groups.flatMap((g, gi) => {
        const list = importSources().filter((x) => x.group === gi && (!q || x.name.toLowerCase().includes(q)));
        if (!list.length) return [];
        return [h("div", { class: "caps" }, g), h("div", { class: "source-grid" }, ...list.map((x) =>
          h("button", { class: "source-tile card" + (source?.id === x.id ? " on" : ""), type: "button", onclick: () => ((source = source?.id === x.id ? null : x), draw()) },
            monogram(x.name.slice(0, 1).toUpperCase(), "var(--accent)", 30, true), h("span", {}, x.name))))];
      }));
    };
    const search = h("input", { class: "search-input", type: "search", value: query, placeholder: t("Rechercher une source", "Search Sources"), "aria-label": t("Rechercher une source", "Search Sources") });
    search.addEventListener("input", () => ((query = search.value), fill()));
    fill();
    const steps = source
      ? h("div", { class: "card pad source-hint" }, h("div", { class: "bold" }, t(`Exporte depuis ${source.name}`, `Export from ${source.name}`)),
          h("ol", {}, ...source.hint.split(" > ").map((step) => h("li", {}, step))),
          h("button", { class: "capsule prominent", type: "button", onclick: () => void pick() }, t("Choisir le fichier", "Choose File")))
      : null;
    return keep(
      h("button", { class: "drop-zone", type: "button", id: "pick-import", onclick: () => void pick() }, icon("import", 34, "accent"),
        h("span", { class: "bold" }, t("Choisis ton export", "Choose Your Export")), h("span", { class: "secondary" }, t("Cleon reconnaît le format d'après le contenu du fichier.", "Cleon recognizes the format from the file's contents."))),
      h("div", { class: "caps" }, t("Ou choisis la source", "Or Choose the Source")),
      h("label", { class: "search" }, icon("search", 18, "secondary"), search),
      steps,
      grid,
      h("p", { class: "footnote" }, t("Le fichier est lu sur cet appareil, jamais envoyé ni gardé. Supprime l'export une fois l'import fait : il contient tes mots de passe en clair.",
        "The file is read on this device, never sent or kept. Delete the export once the import is done, because it contains your passwords in plain text.")),
    );
  };
  const drawPreview = (p: ImportSummary): Node[] => {
    const vault = h("select", { id: "import-vault", "aria-label": t("Coffre", "Vault") }, ...ui.vaults.map((v) => h("option", { value: v.id }, v.name)));
    vault.value = vaultId;
    vault.addEventListener("change", () => {
      vaultId = vault.value;
      void load();
    });
    const nodes: Node[] = [
      h("p", { class: "secondary sheet-intro" }, t("Vérifie ce que contient le fichier avant de l'importer", "Check What's in the File Before Importing")),
      h("div", { class: "card list-card" }, h("div", { class: "row static" }, icon("description", 26, "accent"), h("span", { class: "row-text" }, h("span", { class: "row-title" }, fileName), h("span", { class: "row-sub" }, formatName(format))), icon("shield_check", 20, "green"))),
      h("div", { class: "caps" }, t("Contenu", "Contents")),
      p.items === 0 ? h("p", { class: "secondary" }, t("Aucun élément à importer dans ce fichier.", "There's nothing to import in this file.")) : countsLine(p.byType),
    ];
    const notes = [...p.warnings.map((w) => warningLine(w.code, w.count)), ...(p.skipped ? [warningLine("skipped", p.skipped)] : [])];
    if (notes.length) nodes.push(h("div", { class: "card pad" }, ...notes.map((n) => h("div", { class: "warning-line" }, icon("info", 16, "secondary"), n))));
    nodes.push(h("p", { class: "footnote" }, t("Chaque élément est ajouté avec un nouvel identifiant : rien de ce qui est déjà dans Cleon n'est remplacé. Le dossier d'origine devient un tag.",
      "Each item is added with a new ID, so nothing already in Cleon is replaced. The original folder becomes a tag.")));
    nodes.push(h("div", { class: "caps" }, t("Destination", "Destination")), h("div", { class: "card list-card" }, h("label", { class: "row static", for: "import-vault" }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Coffre", "Vault"))), vault)));
    nodes.push(h("p", { class: "footnote" }, t(`${p.updated} mis à jour, ${p.added} créés, ${p.converted} convertis depuis une note, ${p.archivedDuplicates} doublons exacts archivés, ${p.unchanged} inchangés`,
      `${p.updated} updated, ${p.added} created, ${p.converted} converted from a note, ${p.archivedDuplicates} exact duplicates archived, ${p.unchanged} unchanged`)));
    if (p.duplicates.length) {
      const n = p.duplicates.length;
      const plan = h("p", { class: "footnote" });
      const drawPlan = () => {
        const c = [...choices.values()];
        plan.textContent = t(`${c.filter((x) => x === "merge").length} à fusionner, ${c.filter((x) => x === "skip").length} à ignorer, ${c.filter((x) => x === "import").length} gardés à part`,
          `${c.filter((x) => x === "merge").length} to merge, ${c.filter((x) => x === "skip").length} to skip, ${c.filter((x) => x === "import").length} kept as separate items`);
      };
      const rows = h("div", { class: "card list-card" });
      const drawRows = () => {
        rows.replaceChildren(...p.duplicates.map((d) => {
          const seg = h("div", { class: "segmented small", role: "radiogroup", "aria-label": t("Choix", "Choice") }, ...(["merge", "skip", "import"] as const).map((c) =>
            h("button", { type: "button", class: choices.get(d.index) === c ? "on" : "", role: "radio", "aria-checked": String(choices.get(d.index) === c),
              onclick: () => (choices.set(d.index, c), drawRows(), drawPlan()) }, c === "merge" ? t("Fusionner", "Merge") : c === "skip" ? t("Ignorer", "Skip") : t("Importer", "Import"))));
          return h("div", { class: "row static dup-row" }, art(d.incoming.itemType, 32),
            h("span", { class: "row-text" }, h("span", { class: "row-title" }, d.incoming.title), h("span", { class: "row-sub" }, t(`Dans le coffre : ${d.existing.title}`, `In the vault: ${d.existing.title}`)),
              h("span", { class: "row-sub" }, d.exact ? t("Copie exacte", "Exact copy") : t(`Diffère : ${d.differences.map(aspectWord).join(", ")}`, `Differs: ${d.differences.map(aspectWord).join(", ")}`))), seg);
        }));
      };
      drawRows();
      drawPlan();
      const all = (c: "merge" | "skip" | null) => {
        for (const d of p.duplicates) choices.set(d.index, c ?? d.suggested);
        drawRows();
        drawPlan();
      };
      nodes.push(
        h("div", { class: "caps" }, plural(n, t("1 doublon possible", "1 possible duplicate"), t("%d doublons possibles", "%d possible duplicates"))),
        h("p", { class: "footnote" }, t("Ces éléments du fichier ressemblent à des éléments déjà dans ce coffre. Les copies exactes sont ignorées et les autres fusionnées, sauf si tu choisis autrement.",
          "These items of the file look like items already in this vault. Exact copies are skipped and the others merged, unless you choose otherwise.")),
        h("div", { class: "buttons-row left" },
          h("button", { class: "capsule", type: "button", onclick: () => all("merge") }, t("Tout fusionner", "Merge all")),
          h("button", { class: "capsule", type: "button", onclick: () => all("skip") }, t("Tout ignorer", "Skip all")),
          h("button", { class: "capsule", type: "button", onclick: () => all(null) }, t("Suggestions", "Suggested"))),
        rows, plan);
    }
    nodes.push(h("div", { class: "buttons-row left" }, h("button", { class: "bar-text", type: "button", onclick: () => ((preview = null), (fileName = ""), draw()) }, t("Choisir un autre fichier", "Choose Another File"))));
    return nodes;
  };
  const draw = () => {
    content.replaceChildren(...(preview && fileName ? drawPreview(preview) : drawSources()));
    sync();
  };
  const showDone = (d: ImportSummary, sh: Sheet) => {
    action.hidden = true;
    (sh.dialog.querySelector(".sheet-bar .bar-text") as HTMLElement).textContent = t("Terminé", "Done");
    const vaultName = ui.vaults.find((v) => v.id === vaultId)?.name ?? "";
    content.replaceChildren(...keep(
      h("div", { class: "done-head" }, icon("check_circle", 44, "green"), h("h2", {}, t("Import terminé", "Import complete"))),
      h("p", { class: "secondary center-text" }, d.items === 1 ? t(`1 élément importé dans « ${vaultName} »`, `1 item imported into “${vaultName}”`) : t(`${d.items} éléments importés dans « ${vaultName} »`, `${d.items} items imported into “${vaultName}”`)),
      d.duplicates.length || d.merged || d.skippedDuplicates
        ? h("p", { class: "secondary center-text" }, t(`Doublons possibles : ${d.merged} fusionnés, ${d.skippedDuplicates} ignorés, ${d.separate} gardés à part`, `Possible duplicates: ${d.merged} merged, ${d.skippedDuplicates} skipped, ${d.separate} kept as separate items`))
        : null,
      countsLine(d.byType),
      h("p", { class: "footnote" }, t("Les éléments rangés autrement que dans la source sont dans la section « Importé » de chaque élément.", "Values stored differently from the source are in each item's \"Imported\" section.")),
    ));
    toast(d.items === 1 ? t(`1 élément importé dans « ${vaultName} »`, `1 item imported into “${vaultName}”`) : t(`${d.items} éléments importés dans « ${vaultName} »`, `${d.items} items imported into “${vaultName}”`));
  };
  s.body.append(content, err);
  draw();
}

/** "Activer Windows Hello": the master password, then Windows Hello confirms. */
function enableHello(after: () => void): void {
  const pw = secretInput("hello-pw", t("Mot de passe maître", "Master Password"), "current-password");
  const err = h("div", { class: "error", role: "alert" });
  const s = sheet(t(`Activer ${HELLO}`, `Turn On ${HELLO}`), {
    action: t("Activer", "Turn On"),
    onAction: async (sh) => {
      err.textContent = "";
      if (!pw.input.value) return;
      try {
        await call("enable_hello", { password: pw.input.value });
        pw.input.value = "";
        sh.close();
        toast(t(`${HELLO} activé`, `${HELLO} turned on`));
        after();
      } catch (e) {
        err.textContent = (e as UiError).code === "HelloNotConfirmed"
          ? t(`${HELLO} n'a pas été confirmé : rien n'a été activé.`, `${HELLO} wasn't confirmed, so nothing was turned on.`)
          : message(e);
      }
    },
  });
  s.body.append(pw.box, err, h("p", { class: "footnote" }, t(`Saisis ton mot de passe maître, puis confirme avec ${HELLO}.`, `Enter your master password, then confirm with ${HELLO}.`)));
  pw.input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") (s.dialog.querySelector(".bar-text.bold") as HTMLButtonElement | null)?.click();
  });
  pw.input.focus();
}

function changePassword(): void {
  const cur = secretInput("cp-current", t("Mot de passe actuel", "Current Password"), "current-password");
  const a = secretInput("cp-new", t("Nouveau mot de passe", "New Password"), "new-password");
  const b = secretInput("cp-new2", t("Confirme le nouveau", "Confirm New Password"), "new-password");
  const err = h("div", { class: "error", role: "alert" });
  const s = sheet(t("Mot de passe maître", "Master Password"), {
    action: t("Changer", "Change"),
    onAction: async (sh) => {
      err.textContent = "";
      if (a.input.value !== b.input.value) {
        err.textContent = t("Les deux saisies doivent être identiques.", "Both entries must match.");
        return;
      }
      try {
        await call("change_password", { current: cur.input.value, new: a.input.value });
        sh.close();
        toast(t("Mot de passe maître changé", "Master password changed"));
      } catch (e) {
        err.textContent = message(e);
      }
    },
  });
  s.body.append(cur.box, a.box, b.box, err,
    h("p", { class: "footnote" }, t("Ta Secret Key ne change pas. Tes autres appareils te demanderont le nouveau mot de passe.", "Your Secret Key does not change. Your other devices will ask for the new password.")));
  cur.input.focus();
}

function vaultEditor(v: Vault | null, after?: () => void): void {
  const name = h("input", { id: "v-name", value: v?.name ?? "", placeholder: t("Nom du coffre", "Vault Name") });
  let color = v?.color ?? "blue";
  const swatches = h("div", { class: "swatches" });
  const draw = () =>
    swatches.replaceChildren(...Object.entries(VAULT_COLORS).map(([key, hex]) => {
      const b = h("button", { class: "swatch" + (key === color ? " on" : ""), type: "button", title: key, "aria-label": key, onclick: () => ((color = key), draw()) });
      b.style.background = hex;
      return b;
    }));
  draw();
  const err = h("div", { class: "error", role: "alert" });
  const s = sheet(v ? v.name : t("Nouveau coffre", "New Vault"), {
    action: t("Enregistrer", "Save"),
    onAction: async (sh) => {
      if (!name.value.trim()) {
        err.textContent = t("Donne un nom au coffre.", "Give the vault a name.");
        return;
      }
      try {
        await call("save_vault", { vaultId: v?.id ?? null, name: name.value, color });
        sh.close();
        await refresh(undefined);
        after?.();
      } catch (e) {
        err.textContent = message(e);
      }
    },
  });
  s.body.append(h("div", { class: "card" }, name), h("div", { class: "caps" }, t("Couleur", "Color")), h("div", { class: "card" }, swatches), err);
  if (v) s.body.append(...vaultShareSection(v, () => s.close()));
  if (v && ui.vaults.length > 1) {
    s.body.append(h("div", { class: "card list-card spaced" }, h("button", { class: "row", onclick: () => {
      if (v.itemCount > 0) {
        err.textContent = t("Déplace ou supprime d'abord ses éléments.", "Move or delete its items first.");
        return;
      }
      confirmSheet(t(`Supprimer le coffre « ${v.name} » ?`, `Delete the vault “${v.name}”?`), t("Supprimer", "Delete"), async () => {
        try {
          await call("delete_vault", { vaultId: v.id });
          s.close();
          if (ui.page.kind === "list" && ui.page.filter.kind === "vault") ui.page = { kind: "home" };
          await refresh(undefined);
          after?.();
        } catch (e) {
          err.textContent = message(e);
        }
      });
    } }, h("span", { class: "row-text" }, h("span", { class: "row-title destructive" }, t("Supprimer le coffre", "Delete Vault"))))));
  }
  name.focus();
}

// ---- site icons ---------------------------------------------------------------------------

/** Item id → icon number in the bundled icon pack; icon number → image. */
const siteIcons = new Map<string, number>();
const iconImages = new Map<number, Promise<{ src: string; mono: boolean } | null>>();

async function loadSiteIcons(): Promise<void> {
  try {
    const found = await call<Record<string, number>>("site_icons", { items: ui.items.map((i) => ({ id: i.id, url: i.primaryUrl, title: i.title })) });
    siteIcons.clear();
    for (const [id, n] of Object.entries(found)) siteIcons.set(id, n);
  } catch {
    siteIcons.clear();
  }
}

function iconImage(n: number): Promise<{ src: string; mono: boolean } | null> {
  let p = iconImages.get(n);
  if (!p) {
    p = call<{ src: string; mono: boolean }>("icon_image", { index: n }).catch(() => null);
    iconImages.set(n, p);
  }
  return p;
}

/** The item's site icon when the pack has one, its category art otherwise. */
function itemArt(s: { id: string; itemType: string }, size: number, favorite = false): HTMLElement {
  const box = art(s.itemType, size, favorite);
  const n = siteIcons.get(s.id);
  if (n === undefined) return box;
  void iconImage(n).then((img) => {
    if (!img) return;
    const el = box.querySelector("img")!;
    el.src = img.src;
    box.classList.add("site-icon");
    box.classList.toggle("mono-icon", img.mono);
  });
  return box;
}

// ---- timeline ------------------------------------------------------------------------------

interface TimelineEvent {
  kind: string;
  at: number;
  detail: string;
}

function timelineText(e: TimelineEvent): string {
  const d = e.detail;
  switch (e.kind) {
    case "created":
      return t("Élément créé", "Item created");
    case "imported":
      return d ? t(`Importé depuis ${d}`, `Imported from ${d}`) : t("Importé", "Imported");
    case "field_added":
      return t(`Champ « ${d} » ajouté`, `Field “${d}” added`);
    case "field_removed":
      return t(`Champ « ${d} » supprimé`, `Field “${d}” removed`);
    case "field_changed":
      return d === "notes" ? t("Notes modifiées", "Notes changed") : d === "tags" ? t("Tags modifiés", "Tags changed") : t(`« ${d} » modifié`, `“${d}” changed`);
    case "password_changed":
      return t("Mot de passe modifié", "Password changed");
    case "title_changed":
      return t("Titre modifié", "Title changed");
    case "website_added":
      return t(`Site web ajouté : ${d}`, `Website added: ${d}`);
    case "website_removed":
      return t(`Site web retiré : ${d}`, `Website removed: ${d}`);
    case "moved":
      return t(`Déplacé vers ${d}`, `Moved to ${d}`);
    case "favorited":
      return t("Ajouté aux favoris", "Added to Favorites");
    case "unfavorited":
      return t("Retiré des favoris", "Removed from Favorites");
    case "archived":
      return t("Archivé", "Archived");
    case "unarchived":
      return t("Désarchivé", "Unarchived");
    case "trashed":
      return t("Mis dans Supprimés récemment", "Moved to Recently Deleted");
    case "restored":
      return t("Restauré", "Restored");
    case "passkey_added":
      return t(`Passkey ajoutée pour ${d}`, `Passkey added for ${d}`);
    case "passkey_removed":
      return t(`Passkey supprimée pour ${d}`, `Passkey removed for ${d}`);
    case "attachment_added":
      return t(`Pièce jointe ajoutée : ${d}`, `Attachment added: ${d}`);
    default:
      return t("Modifié", "Modified");
  }
}

const timelineIcon = (kind: string): IconName =>
  (({
    created: "add_circle", imported: "import", field_added: "add_box", field_removed: "minus_box", password_changed: "key", title_changed: "title",
    website_added: "globe", website_removed: "globe", moved: "folder", favorited: "star", unfavorited: "star", archived: "archive", unarchived: "archive",
    trashed: "trash", restored: "restore", passkey_added: "passkey", passkey_removed: "passkey", attachment_added: "paperclip",
  }) as Record<string, IconName>)[kind] ?? "edit";

function relative(at: number): string {
  const secs = Math.round(at - Date.now() / 1000);
  const f = new Intl.RelativeTimeFormat(t("fr", "en"), { numeric: "auto" });
  const abs = Math.abs(secs);
  if (abs < 60) return f.format(0, "second");
  if (abs < 3600) return f.format(Math.round(secs / 60), "minute");
  if (abs < 86400) return f.format(Math.round(secs / 3600), "hour");
  if (abs < 86400 * 30) return f.format(Math.round(secs / 86400), "day");
  if (abs < 86400 * 365) return f.format(Math.round(secs / 86400 / 30), "month");
  return f.format(Math.round(secs / 86400 / 365), "year");
}

/** The item's footer: "Modifié le …" opens what happened to it, as on the Mac. */
function timelineFooter(item: Item): HTMLElement {
  const list = h("div", { class: "timeline", hidden: true });
  const chevron = icon("chevron_down", 16, "accent folded");
  const head = h("button", { class: "bar-text timeline-head", "aria-expanded": "false" }, t("Modifié le ", "Modified ") + dateTime(item.updatedAt), chevron);
  head.addEventListener("click", async () => {
    const open = list.hidden;
    list.hidden = !open;
    head.setAttribute("aria-expanded", String(open));
    chevron.classList.toggle("folded", !open);
    if (!open || list.childElementCount) return;
    try {
      const events = await call<TimelineEvent[]>("item_timeline", { vaultId: item.vaultId, itemId: item.id });
      list.replaceChildren(...events.map((e, i) =>
        h("div", { class: "timeline-row" + (i === 0 ? " first" : "") }, h("span", { class: "timeline-dot" }), icon(timelineIcon(e.kind), 18, "secondary"),
          h("span", { class: "timeline-text" }, timelineText(e)), h("span", { class: "tertiary timeline-when", title: dateTime(e.at) }, relative(e.at)))));
    } catch (e) {
      list.replaceChildren(h("p", { class: "secondary" }, message(e)));
    }
  });
  return h("div", { class: "timeline-box" }, head, list);
}

// ---- Wi-Fi QR code -------------------------------------------------------------------------

function qrSvg(modules: boolean[], width: number, size: number): SVGSVGElement {
  const svg = document.createElementNS(SVG, "svg");
  const quiet = 3;
  const n = width + quiet * 2;
  svg.setAttribute("viewBox", `0 0 ${n} ${n}`);
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("shape-rendering", "crispEdges");
  svg.setAttribute("class", "qr");
  const bg = document.createElementNS(SVG, "rect");
  bg.setAttribute("width", String(n));
  bg.setAttribute("height", String(n));
  bg.setAttribute("fill", "#fff");
  svg.append(bg);
  let d = "";
  modules.forEach((dark, i) => {
    if (dark) d += `M${(i % width) + quiet} ${Math.floor(i / width) + quiet}h1v1h-1z`;
  });
  const p = document.createElementNS(SVG, "path");
  p.setAttribute("d", d);
  p.setAttribute("fill", "#121F45");
  svg.append(p);
  return svg;
}

/** The router's "join this network" code: hidden until touched, hidden again after 30 s. */
function wifiCard(item: Item): HTMLElement | null {
  const ssid = item.sections.flatMap((s) => s.fields).find((f) => f.id === "ssid")?.value;
  if (item.itemType !== "router" || !ssid) return null;
  const area = h("button", { class: "qr-area masked", type: "button", "aria-label": t(`Code QR du réseau ${ssid}`, `QR code for network ${ssid}`) });
  const caption = h("p", { class: "secondary center-text" }, t("Touche le code pour l'afficher.", "Tap the code to show it."));
  let timer: number | undefined;
  let data: { modules: boolean[]; width: number } | null = null;
  const mask = () => {
    area.classList.add("masked");
    area.replaceChildren(icon("qr_code", 120, "secondary"));
    caption.textContent = t("Touche le code pour l'afficher.", "Tap the code to show it.");
    data = null;
  };
  mask();
  area.addEventListener("click", async () => {
    if (data) return mask();
    try {
      data = await call<{ ssid: string; modules: boolean[]; width: number }>("wifi_qr", { vaultId: item.vaultId, itemId: item.id });
      area.classList.remove("masked");
      area.replaceChildren(qrSvg(data.modules, data.width, 220));
      caption.textContent = t(`Scanne ce code pour rejoindre « ${ssid} ».`, `Scan this code to join “${ssid}”.`);
      window.clearTimeout(timer);
      timer = window.setTimeout(mask, 30000);
      timers.push(timer);
    } catch (e) {
      toast(message(e));
    }
  });
  const large = h("button", { class: "bar-text", type: "button", onclick: async () => {
    try {
      const q = await call<{ modules: boolean[]; width: number }>("wifi_qr", { vaultId: item.vaultId, itemId: item.id });
      const s = sheet(t("Afficher en grand", "Show Large"), { cancel: t("Fermer", "Close") });
      s.body.append(h("div", { class: "qr-large" }, qrSvg(q.modules, q.width, 420)), h("p", { class: "secondary center-text" }, t(`Scanne ce code pour rejoindre « ${ssid} ».`, `Scan this code to join “${ssid}”.`)));
      window.setTimeout(() => s.close(), 30000);
    } catch (e) {
      toast(message(e));
    }
  } }, t("Afficher en grand", "Show Large"));
  return h("div", { class: "card pad qr-card spaced" }, area, caption, large);
}

// ---- duplicates -----------------------------------------------------------------------------

interface DuplicateGroup {
  id: string;
  confidence: "sure" | "review";
  signals: string[];
  domain: string | null;
  copies: { summary: Summary; vaultName: string; writable: boolean; differences: string[]; hasTotp: boolean; attachmentCount: number; fieldCount: number }[];
  conflicts: string[];
}

function signalText(s: string, domain: string | null): string {
  switch (s) {
    case "sameTotp":
      return t("Même code de vérification", "Same verification code");
    case "sameCard":
      return t("Même numéro de carte", "Same card number");
    case "sameDocument":
      return t("Même numéro de document", "Same document number");
    case "sameLogin":
      return t(`Même identifiant sur ${domain ?? ""}`, `Same username on ${domain ?? ""}`);
    default:
      return t("Même titre et même identifiant", "Same title and username");
  }
}

/** Doublons possibles (a sidebar page under Watchtower, as on the Mac). */
function duplicatesPage(): HTMLElement {
  const groups = ui.duplicates;
  const sure = groups.filter((g) => g.confidence === "sure");
  const review = groups.filter((g) => g.confidence === "review");
  const selected = new Set(sure.map((g) => g.id));
  const run = async (cmd: string, args: Record<string, unknown>, done?: string) => {
    try {
      const r = await call<number | null>(cmd, args);
      if (done) toast(done.replace("%d", String(r ?? 0)));
      await refresh(undefined);
    } catch (e) {
      toast(message(e));
    }
  };
  const groupMenu = (anchor: HTMLElement, g: DuplicateGroup) =>
    menu(anchor, [
      { label: t("Pas des doublons", "Not Duplicates"), icon: "close", action: () => void run("resolve_duplicates", { groupId: g.id, action: "dismiss" }) },
      { label: t("Archiver les autres", "Archive Others"), icon: "archive", action: () => void run("resolve_duplicates", { groupId: g.id, action: "archive" }) },
      "separator",
      { label: t("Supprimer les autres", "Delete Others"), icon: "trash", destructive: true, action: () =>
        confirmSheet(t("Supprimer les autres copies ? Elles vont dans Supprimés récemment, d'où tu peux les restaurer.", "Delete the other copies? They go to Recently Deleted, where you can restore them."), t("Supprimer les autres", "Delete Others"),
          () => void run("resolve_duplicates", { groupId: g.id, action: "trash" })) },
    ]);
  const groupHead = (g: DuplicateGroup) => {
    const first = g.copies[0]!.summary;
    const vaults = [...new Set(g.copies.map((c) => c.vaultName))].join(", ");
    return h("span", { class: "row-text" }, h("span", { class: "row-title bold" }, first.title),
      h("span", { class: "row-sub" }, [first.subtitle, plural(g.copies.length, t("1 copie", "1 copy"), t("%d copies", "%d copies")), vaults].filter(Boolean).join(" · ")),
      h("span", { class: "row-sub tertiary" }, g.signals.map((s) => signalText(s, g.domain)).join(" · ")));
  };
  const more = (g: DuplicateGroup) => {
    const b = h("button", { class: "bar-icon", type: "button", title: t("Plus d'actions", "More Actions"), "aria-label": t("Plus d'actions", "More Actions") }, icon("more_circle", 22));
    b.addEventListener("click", (e) => (e.stopPropagation(), groupMenu(b, g)));
    return b;
  };
  const sureRows = sure.map((g) => {
    const box = h("input", { type: "checkbox", class: "check-box", checked: true, "aria-label": t("Inclure dans la fusion", "Include in Merge") });
    box.addEventListener("change", () => (box.checked ? selected.add(g.id) : selected.delete(g.id), (mergeAll.textContent = t(`Fusionner la sélection (${selected.size})`, `Merge Selected (${selected.size})`))));
    return h("div", { class: "row static dup-group" }, box, itemArt(g.copies[0]!.summary, 36), groupHead(g), more(g));
  });
  const mergeAll = h("button", { class: "capsule prominent", type: "button", onclick: () => void run("merge_sure_duplicates", { groupIds: [...selected] }, t("%d groupe(s) fusionné(s)", "%d group(s) merged")) },
    t(`Fusionner la sélection (${selected.size})`, `Merge Selected (${selected.size})`));
  const reviewCards = review.map((g) =>
    h("div", { class: "card pad dup-review" },
      h("div", { class: "dup-review-head" }, itemArt(g.copies[0]!.summary, 36), groupHead(g), more(g)),
      h("p", { class: "secondary" }, g.conflicts.length === 1
        ? t(`« ${g.conflicts[0]} » diffère.`, `“${g.conflicts[0]}” differs.`)
        : t(`Les copies diffèrent sur ${g.conflicts.length} points : ${g.conflicts.join(", ")}.`, `The copies differ on ${g.conflicts.length} points: ${g.conflicts.join(", ")}.`)),
      h("div", { class: "dup-copies" }, ...g.copies.map((c, i) =>
        h("button", { class: "dup-copy card", type: "button", onclick: () => openItem(c.summary) }, h("span", { class: "row-title" }, c.summary.title + (i === 0 ? t(" (gardé)", " (kept)") : "")),
          h("span", { class: "row-sub" }, `${c.vaultName} · ${t("Modifié", "Edited")} ${relative(c.summary.updatedAt)}${c.writable ? "" : " · " + t("Lecture seule", "Read Only")}`),
          c.differences.length ? h("span", { class: "row-sub tertiary" }, t(`Diffère : ${c.differences.map(aspectWord).join(", ")}`, `Differs: ${c.differences.map(aspectWord).join(", ")}`)) : null))),
      h("div", { class: "buttons-row left" },
        h("button", { class: "capsule prominent", type: "button", onclick: () => void run("merge_duplicates", { groupId: g.id }) }, t("Fusionner", "Merge")),
        h("button", { class: "capsule", type: "button", onclick: () => void run("resolve_duplicates", { groupId: g.id, action: "dismiss" }) }, t("Ce ne sont pas des doublons", "These Aren't Duplicates"))),
      h("p", { class: "footnote" }, t("Rien n'est perdu : l'autre mot de passe passe dans l'historique, les autres copies sont archivées intactes.", "Nothing is lost: the other password goes to the history, the other copies are archived intact."))));
  return h("div", { class: "page" },
    h("h1", { class: "large-title" }, t("Doublons possibles", "Possible Duplicates")),
    h("p", { class: "secondary" }, t(`Sans risque : ${sure.length} · À vérifier : ${review.length}`, `Safe to merge: ${sure.length} · To check: ${review.length}`)),
    ...(groups.length === 0
      ? [h("div", { class: "empty-state" }, icon("duplicates", 48, "secondary"), h("h2", {}, t("Aucun doublon", "No Duplicates")),
          h("p", { class: "secondary" }, t("Les éléments qui se ressemblent beaucoup apparaîtront ici.", "Items that look very much alike show up here.")))]
      : []),
    ...(sure.length
      ? [h("div", { class: "caps" }, t("Fusion sûre", "Safe to Merge")),
         h("p", { class: "footnote" }, t("Même élément : une copie ajoute seulement des infos. La fusion les garde toutes.", "Same item: one copy only adds details. The merge keeps them all.")),
         h("div", { class: "card list-card" }, ...sureRows), h("div", { class: "buttons-row left" }, mergeAll)]
      : []),
    ...(review.length
      ? [h("div", { class: "caps" }, t("À vérifier", "To Check")),
         h("p", { class: "footnote" }, t("Les copies se contredisent. Cleon garde la copie la plus complète et met l'autre mot de passe dans l'historique.", "The copies disagree. Cleon keeps the most complete copy and puts the other password in the history.")),
         ...reviewCards]
      : []),
  );
}

// ---- Travel Mode ------------------------------------------------------------------------------

interface TravelView {
  active: boolean;
  exiting: boolean;
  enteredAt: number | null;
  hiddenCount: number;
  hiddenItemCount: number;
  vaults: { vaultId: string; name: string; leaves: boolean }[];
  hidden: { itemId: string; title: string; vaultName: string }[];
  guarded: { itemId: string; title: string; vaultName: string }[];
}

function travelError(e: unknown): string {
  const d = (e as UiError)?.detail ?? "";
  if (d.includes("unsynced changes")) return t("Synchronise d'abord : les coffres qui partent doivent être à jour sur le serveur pour revenir. Active la synchronisation dans Réglages > Sync, puis réessaie.",
    "Sync first: the vaults that leave must be up to date on the server to come back. Turn on sync in Settings > Sync, then try again.");
  if (d.includes("nothing leaves")) return t("Rien ne quitterait cet appareil.", "Nothing would leave this device.");
  return message(e);
}

async function travelPage(head: HTMLElement, redraw: () => void): Promise<Node[]> {
  const v = await call<TravelView>("travel_status");
  const err = h("div", { class: "error", role: "alert" });
  const leaving = v.vaults.filter((x) => x.leaves).map((x) => x.name);
  const status = v.active
    ? h("div", { class: "row static" }, tile("airplane", "var(--blue)", 30), h("span", { class: "row-text" }, h("span", { class: "row-title bold" }, v.exiting ? t("Retour en cours", "Coming back") : t("Travel Mode activé", "Travel Mode on")),
        v.enteredAt ? h("span", { class: "row-sub" }, t(`Depuis le ${dateTime(v.enteredAt)}, ${plural(v.hiddenCount, "1 coffre", "%d coffres")} hors de cet appareil`, `Since ${dateTime(v.enteredAt)}, ${plural(v.hiddenCount, "1 vault", "%d vaults")} off this device`)) : null))
    : h("div", { class: "row static" }, tile("airplane", "#8E8E93", 30), h("span", { class: "row-text" }, h("span", { class: "row-title bold" }, t("Travel Mode désactivé", "Travel Mode off"))));
  const button = v.active
    ? h("button", { class: "capsule prominent", type: "button", onclick: async () => {
        try {
          await call("exit_travel");
          await refresh(null);
          toast(t("De retour sur cet appareil", "Back on This Device"));
          redraw();
        } catch (e) {
          err.textContent = travelError(e);
        }
      } }, v.exiting ? t("Terminer le retour", "Finish Coming Back") : t("Désactiver le Travel Mode", "Turn Off Travel Mode"))
    : h("button", { class: "capsule prominent", type: "button", onclick: () => {
        const lines = [
          leaving.length ? t(`Ces coffres quittent cet appareil jusqu'à ton retour : ${leaving.join(", ")}.`, `These vaults leave this device until you come back: ${leaving.join(", ")}.`) : "",
          v.hidden.length ? plural(v.hidden.length, t("1 élément caché part aussi.", "1 hidden item leaves too."), t("%d éléments cachés partent aussi.", "%d hidden items leave too.")) : "",
          v.guarded.length ? plural(v.guarded.length, t("1 élément reste, protégé par mot de passe maître et Windows Hello.", "1 item stays, protected by master password and Windows Hello."), t("%d éléments restent, protégés par mot de passe maître et Windows Hello.", "%d items stay, protected by master password and Windows Hello.")) : "",
        ].filter(Boolean);
        confirmSheet(t("Activer le Travel Mode ?", "Turn on Travel Mode?") + " " + (lines.join(" ") || t("Rien ne quitterait cet appareil.", "Nothing would leave this device.")), t("Activer", "Turn On"), async () => {
          try {
            await call("enter_travel");
            await refresh(null);
            redraw();
          } catch (e) {
            err.textContent = travelError(e);
          }
        });
      } }, t("Activer le Travel Mode", "Turn On Travel Mode"));
  const vaultRows = v.vaults.map((x) => {
    const box = h("input", { type: "checkbox", class: "switch", checked: !x.leaves, disabled: v.active, "aria-label": t(`Sûr en voyage : ${x.name}`, `Safe for Travel: ${x.name}`) });
    box.addEventListener("change", async () => {
      try {
        await call("set_vault_travel_safe", { vaultId: x.vaultId, safe: box.checked });
        await refresh(undefined);
        redraw();
      } catch (e) {
        err.textContent = message(e);
      }
    });
    const vault = ui.vaults.find((u) => u.id === x.vaultId);
    return h("label", { class: "toggle-row" }, monogram(x.name.slice(0, 1).toUpperCase(), vaultColor(vault?.color ?? "blue"), 28, true),
      h("span", { class: "row-text grow" }, h("span", {}, x.name), h("span", { class: "row-sub" }, x.leaves ? t("Quitte l'appareil", "Leaves the device") : t("Reste sur l'appareil", "Stays on the device"))), box);
  });
  const itemRows = [
    ...v.hidden.map((i) => h("div", { class: "row static" }, icon("eye_off", 20, "secondary"), h("span", { class: "row-text" }, h("span", { class: "row-title" }, i.title), h("span", { class: "row-sub" }, i.vaultName)))),
    ...v.guarded.map((i) => h("div", { class: "row static" }, icon("shield_lock", 20, "secondary"), h("span", { class: "row-text" }, h("span", { class: "row-title" }, i.title), h("span", { class: "row-sub" }, i.vaultName)))),
  ];
  return [head,
    h("div", { class: "card list-card" }, status), h("div", { class: "buttons-row left" }, button), err,
    h("p", { class: "footnote" }, t("Les coffres retirés restent sur le serveur et sont vérifiés au retour. Cleon refuse de retirer un coffre qui ne serait pas encore synchronisé.",
      "Removed vaults stay on the server and are checked on return. Cleon refuses to remove a vault that isn't synced yet.")),
    h("div", { class: "caps" }, t("Éléments", "Items")),
    itemRows.length ? h("div", { class: "card list-card" }, ...itemRows) : h("p", { class: "secondary" }, t("Aucun élément marqué.", "No marked items.")),
    h("p", { class: "footnote" }, t("Se règle dans chaque élément : Caché en voyage, ou Protection renforcée en voyage.", "Set in each item: Hidden in Travel Mode, or Extra Protection in Travel Mode.")),
    ...(v.active ? [] : [h("div", { class: "caps" }, t("Sûr en voyage", "Safe for Travel")), h("div", { class: "card list-card" }, ...vaultRows), h("p", { class: "footnote" }, t("Sur tous tes appareils.", "On all your devices."))]),
  ];
}

function iconsToggle(on: boolean, redraw: () => void): HTMLElement {
  const box = h("input", { type: "checkbox", class: "switch", id: "site-icons", checked: on, "aria-label": t("Icônes des sites", "Website Icons") });
  box.addEventListener("change", async () => {
    try {
      await call("set_site_icons", { on: box.checked });

      await refresh(undefined);
      redraw();
    } catch (e) {
      toast(message(e));
    }
  });
  return h("label", { class: "toggle-row", for: "site-icons" }, h("span", {}, t("Icônes des sites", "Website Icons")), box);
}


// ---- sync, Emergency Kit restore, devices and pairing ---------------------------------------
// The mailbox path of the Apple apps (SyncSettings, SyncChoiceSheet, the
// RestoreStep, DevicesSettings, HostDeviceSheet, JoinCodeSteps), with their
// strings.

interface SyncView {
  backend: "local" | "pending" | "mailbox";
  server: { hosted: boolean; host: string } | null;
  state: string;
  lastSync: number | null;
  detail: string | null;
}
type SyncChoice = { kind: "hosted" } | { kind: "selfHost"; url: string; caPem: string | null };

/** "Où est rangé mon coffre ?" for the next account made here (D.2: the Cleon server by default). */
let syncChoice: SyncChoice = { kind: "hosted" };
let syncView: SyncView | null = null;
/** Redraws the open Settings > Sync page when the status changes. */
let syncRedraw: (() => void) | null = null;

const hostedName = (): string => t("Serveur Cleon", "Cleon Server");
const hostOf = (url: string): string => {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
};
const choiceName = (c: SyncChoice): string => (c.kind === "hosted" ? hostedName() : hostOf(c.url));
const serverLabel = (v: SyncView): string => (!v.server ? "" : v.server.hosted ? hostedName() : v.server.host);

/** `https`, a host, no user info, query or fragment (`MailboxEndpoints.validate`; the backend checks again). */
function validUrl(text: string): boolean {
  const s = text.trim();
  if (!s || s.length > 256 || /[\s\\]/.test(s)) return false;
  try {
    const u = new URL(s);
    return u.protocol === "https:" && !!u.hostname && !u.username && !u.password && !u.search && !u.hash && !s.includes("?") && !s.includes("#");
  } catch {
    return false;
  }
}

/** "Synchronisé il y a 3 minutes" (`SyncSettings.agoText`). */
function agoText(at: number): string {
  const secs = Date.now() / 1000 - at;
  if (secs < 45) return t("Synchronisé à l'instant", "Synced Just Now");
  const rtf = new Intl.RelativeTimeFormat(t("fr", "en"), { numeric: "always" });
  const mins = Math.round(secs / 60);
  const rel = mins < 60 ? rtf.format(-mins, "minute") : mins < 1440 ? rtf.format(-Math.round(mins / 60), "hour") : rtf.format(-Math.round(mins / 1440), "day");
  return t(`Synchronisé ${rel}`, `Synced ${rel}`);
}

/** The status line of Settings > Sync, its symbol and its tone. */
function syncLine(v: SyncView): { text: string; icon: IconName; tone: string } {
  switch (v.state) {
    case "off":
      return { text: t("Synchronisation désactivée", "Sync off"), icon: "refresh", tone: "secondary" };
    case "waitingUnlock":
      return { text: t("Déverrouille ton coffre pour continuer.", "Unlock your vault to continue."), icon: "lock", tone: "secondary" };
    case "setupOffline":
      return { text: t("Impossible de joindre le serveur. Vérifie ta connexion puis réessaie.", "Can't reach the server. Check your connection and try again."), icon: "wifi", tone: "orange" };
    case "setupFailed":
      return { text: t("La synchronisation n'a pas abouti, nouvel essai bientôt.", "Sync didn't complete. Trying again soon."), icon: "warning", tone: "red" };
    case "idle":
      return v.lastSync
        ? { text: agoText(v.lastSync), icon: "check_circle", tone: "" }
        : { text: t("En attente de la première synchronisation", "Waiting for First Sync"), icon: "refresh", tone: "" };
    case "syncing":
      return { text: t("Synchronisation en cours", "Syncing"), icon: "refresh", tone: "" };
    case "offline":
      return { text: t("Hors ligne", "Offline"), icon: "wifi", tone: "orange" };
    case "retrying":
      return { text: t("La synchronisation reprendra dans un instant", "Sync will resume in a moment"), icon: "warning", tone: "red" };
    case "clockSkew":
      return { text: t("Vérifie l'heure de l'appareil", "Check the device's time"), icon: "warning", tone: "red" };
    case "waiting":
      return { text: t("Synchronisation en attente du serveur", "Sync waiting for the server"), icon: "upload", tone: "secondary" };
    case "refused":
      return { text: t(`Données refusées : ${v.detail ?? ""}`, `Data refused: ${v.detail ?? ""}`), icon: "shield_lock", tone: "red" };
    case "unreadable":
      return { text: t("Un enregistrement du serveur est illisible", "A record from the server can't be read"), icon: "warning", tone: "red" };
    case "homeMoved":
      return { text: t("Ton coffre a changé de serveur", "Your vault moved to another server"), icon: "warning", tone: "red" };
    default:
      return { text: v.state, icon: "info", tone: "secondary" };
  }
}

function statusRow(v: SyncView): HTMLElement {
  const line = syncLine(v);
  const tint = line.tone === "red" ? "var(--red)" : line.tone === "orange" ? "var(--orange)" : line.tone === "secondary" ? "var(--secondary)" : "var(--accent)";
  const el = h("div", { class: "row static sync-status", id: "sync-status", "data-state": v.state }, icon(line.icon, 22), h("span", { class: "row-text" }, h("span", { class: "row-title" }, line.text)));
  (el.firstChild as SVGElement).style.color = tint;
  return el;
}

/** "Où est rangé mon coffre ?": the Cleon server (default) or the user's own, with "Tester". */
function syncChoiceSheet(current: SyncChoice, onDone: (c: SyncChoice) => void, title = t("Où est rangé mon coffre ?", "Where Is My Vault Kept?")): void {
  let option: "hosted" | "selfHost" = current.kind;
  const url = h("input", { id: "sync-url", placeholder: t("URL de base (https://...)", "Base URL (https://...)"), spellcheck: false, autocomplete: "off", value: current.kind === "selfHost" ? current.url : "" });
  const ca = h("textarea", { id: "sync-ca", class: "mono", rows: 4, spellcheck: false, placeholder: t("Autorité de certification en PEM (facultatif)", "Certificate authority in PEM (optional)") }) as HTMLTextAreaElement;
  if (current.kind === "selfHost") ca.value = current.caPem ?? "";
  const bad = h("p", { class: "footnote error-text" });
  const result = h("span", { class: "footnote secondary", id: "sync-test-result" });
  const test = h("button", { class: "capsule", type: "button", id: "sync-test" }, t("Tester", "Test"));
  const selfBox = h("div", { class: "self-host" }, h("div", { class: "card" }, h("div", { class: "field-box" }, url), h("div", { class: "field-box" }, ca)), h("div", { class: "buttons-row left" }, test, result), bad);
  const rows = h("div", { class: "card list-card" });
  const pem = () => ca.value.trim() || null;
  const s = sheet(title, {
    action: t("Terminé", "Done"),
    onAction: (sh) => {
      if (option === "selfHost") {
        if (!validUrl(url.value)) {
          bad.textContent = t("L'adresse doit commencer par https://.", "The address must start with https://.");
          return;
        }
        onDone({ kind: "selfHost", url: url.value.trim(), caPem: pem() });
      } else {
        onDone({ kind: "hosted" });
      }
      sh.close();
    },
  });
  s.dialog.classList.add("sync-choice");
  const draw = () => {
    const row = (value: "hosted" | "selfHost", name: string, detail: string | null) =>
      h("button", { class: "row", type: "button", "aria-pressed": String(option === value), id: `sync-option-${value}`, onclick: () => ((option = value), draw()) },
        h("span", { class: "row-text" }, h("span", { class: "row-title" }, name), detail ? h("span", { class: "row-sub" }, detail) : null),
        option === value ? icon("check", 20, "accent") : null);
    rows.replaceChildren(
      row("hosted", hostedName(), t("Hébergé par Soma Labs, chiffré sur ton appareil avant l'envoi", "Hosted by Soma Labs, encrypted on your device before it's sent")),
      row("selfHost", t("Mon serveur", "My Server"), null),
    );
    selfBox.hidden = option !== "selfHost";
  };
  url.addEventListener("input", () => {
    bad.textContent = url.value && !validUrl(url.value) ? t("L'adresse doit commencer par https://.", "The address must start with https://.") : "";
    result.textContent = "";
  });
  test.addEventListener("click", async () => {
    if (!validUrl(url.value)) {
      bad.textContent = t("L'adresse doit commencer par https://.", "The address must start with https://.");
      return;
    }
    test.disabled = true;
    result.textContent = "…";
    const ok = await call<boolean>("check_server", { url: url.value.trim(), caPem: pem() }).catch(() => false);
    result.textContent = ok ? t("Le serveur répond.", "The server answers.") : t("Le serveur ne répond pas. Vérifie l'adresse.", "The server doesn't answer. Check the address.");
    test.disabled = false;
  });
  draw();
  s.body.append(rows, selfBox);
}

// ---- Settings > Sync -----------------------------------------------------------------------

async function syncPage(head: HTMLElement, redraw: () => void): Promise<Node[]> {
  const v = await call<SyncView>("sync_status");
  syncView = v;
  syncRedraw = redraw;
  const row = (label: string, value: string, id?: string) => h("div", { class: "row static", id }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, label)), h("span", { class: "secondary" }, value));
  if (v.backend === "local") {
    const on = h("button", { class: "capsule prominent", type: "button", id: "enable-sync" }, t("Activer la synchronisation", "Turn On Sync"));
    const err = h("div", { class: "error", role: "alert" });
    on.addEventListener("click", () =>
      syncChoiceSheet({ kind: "hosted" }, async (c) => {
        try {
          await call("enable_sync", { choice: c });
          redraw();
        } catch (e) {
          err.textContent = e && (e as UiError).code === "BadUrl" ? t("Cette adresse de serveur n'est pas valide. Elle doit commencer par https://.", "This server address isn't valid. It must start with https://.") : message(e);
        }
      }),
    );
    return [head, h("div", { class: "card list-card" }, statusRow(v)), h("p", { class: "footnote" }, t("Ton coffre reste sur ce PC. Avec la synchronisation, il est chiffré sur cet appareil avant d'être envoyé à tes autres appareils.", "Your vault stays on this PC. With sync, it is encrypted on this device before it goes to your other devices.")),
      h("div", { class: "buttons-row left" }, on), err];
  }
  const now = h("button", { class: "row", type: "button", id: "sync-now", disabled: v.state === "syncing" }, h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Synchroniser maintenant", "Sync Now"))));
  now.addEventListener("click", async () => {
    now.disabled = true;
    await call("sync_now").catch((e) => toast(message(e)));
    redraw();
  });
  const footer = v.state === "refused" ? t("Rien de ce que le serveur a envoyé n'a été utilisé.", "Nothing the server sent was used.")
    : v.state === "waiting" ? t("Le serveur a une version plus ancienne. Cleon renvoie la sienne, rien à faire.", "The server has an older version. Cleon sends its own back, nothing to do.")
    : t("Chiffré avant de quitter l'appareil.", "Encrypted before it leaves the device.");
  return [head, h("div", { class: "card list-card" }, row(t("Synchronisé avec", "Synced With"), serverLabel(v), "sync-backend"), statusRow(v), now), h("p", { class: "footnote" }, footer)];
}

// ---- Settings > Devices --------------------------------------------------------------------

interface DeviceInfo {
  id: string;
  name: string;
  kind: string;
  mode: string;
  addedAt: number;
  revoked: boolean;
  revokedAt: number | null;
  thisDevice: boolean;
}

const kindName = (k: string): string =>
  ({ phone: "iPhone", tablet: "iPad", mac: "Mac", vision: "Apple Vision Pro", android: "Android", windows: "Windows", linux: "Linux" } as Record<string, string>)[k] ?? t("Autre appareil", "Other device");
const modeName = (m: string): string => (m === "shared" ? t("Partagé", "Shared") : m === "public" ? "Public" : t("Personnel", "Personal"));
const shortDate = (s: number): string => new Date(s * 1000).toLocaleDateString(t("fr-FR", "en-US"), { day: "numeric", month: "short", year: "numeric" });

async function devicesPage(head: HTMLElement, redraw: () => void): Promise<Node[]> {
  const acc = await call<Account & { devices: DeviceInfo[] }>("account");
  const sv = await call<SyncView>("sync_status").catch(() => null);
  const rows = acc.devices.map((d) => {
    const sub = d.revoked
      ? t(`${kindName(d.kind)} · Retiré le ${d.revokedAt ? shortDate(d.revokedAt) : "?"}`, `${kindName(d.kind)} · Removed on ${d.revokedAt ? shortDate(d.revokedAt) : "?"}`)
      : t(`${kindName(d.kind)} · ${modeName(d.mode)} · ajouté le ${shortDate(d.addedAt)}`, `${kindName(d.kind)} · ${modeName(d.mode)} · added on ${shortDate(d.addedAt)}`);
    const b = h("button", { class: "row device-row", type: "button", "data-name": d.name },
      tile("key", d.revoked ? "#8E8E93" : "#008CB3", 28),
      h("span", { class: "row-text" }, h("span", { class: "row-title" }, d.name), h("span", { class: "row-sub" }, sub)),
      d.thisDevice ? h("span", { class: "secondary" }, t("Cet appareil", "This device")) : null,
      icon("more", 18, "chev"));
    b.addEventListener("click", () => {
      if (d.revoked) return;
      const entries: MenuEntry[] = [{ label: t("Renommer", "Rename"), icon: "edit", action: () => renameDevice(d, redraw) }];
      if (!d.thisDevice) entries.push({ label: t("Retirer cet appareil", "Remove This Device"), icon: "remove_circle", destructive: true, action: () => revokeDevice(d, redraw) });
      menu(b, entries);
    });
    return b;
  });
  // Devices restored with the Emergency Kit (spec 7.5): trusted, or refused, from here.
  const kit = await call<{ awaitingTrust: boolean; asking: { id: string; name: string; kind: string; nameInUse: boolean; rotated: boolean }[] }>("kit_devices").catch(() => null);
  const askPassword = (title: string, action: string, run: (password: string) => Promise<void>) => {
    const pw = secretInput("kit-pw", t("Mot de passe maître", "Master Password"), "current-password");
    const err = h("div", { class: "error", role: "alert" });
    const s = sheet(title, { action, onAction: async (sh) => {
      try {
        await run(pw.input.value);
        sh.close();
        redraw();
      } catch (e) {
        err.textContent = message(e);
      }
    } });
    s.body.append(pw.box, h("p", { class: "footnote" }, t("Confirme avec ton mot de passe maître.", "Confirm with your master password.")), err);
    queueMicrotask(() => pw.input.focus());
  };
  const kitRows = (kit?.asking ?? []).map((d) => h("div", { class: "row static kit-row" }, tile("restore", "var(--orange)", 28),
    h("span", { class: "row-text" }, h("span", { class: "row-title" }, d.name), h("span", { class: "row-sub" },
      d.rotated ? t("A changé les clés sans toi", "Changed the keys without you")
        : `${kindName(d.kind)} · ${t("restauré par Kit", "restored with the Kit")}${d.nameInUse ? t(" · porte le même nom qu'un de tes appareils", " · has the same name as one of your devices") : ""}`)),
    d.rotated ? null : h("button", { class: "bar-text", type: "button", onclick: () => askPassword(t(`Faire confiance à ${d.name} ?`, `Trust ${d.name}?`), t("Faire confiance", "Trust"),
      (password) => call("answer_kit_device", { id: d.id, trust: true, password })) }, t("Faire confiance", "Trust")),
    d.rotated ? null : h("button", { class: "bar-text destructive", type: "button", onclick: () => void call("answer_kit_device", { id: d.id, trust: false, password: "" }).then(redraw).catch((e) => toast(message(e))) }, t("Refuser", "Refuse"))));
  const kitSection: Node[] = kitRows.length
    ? [h("div", { class: "caps" }, t("Restaurés par Kit", "Restored with the Kit")), h("div", { class: "card list-card" }, ...kitRows),
      h("p", { class: "footnote" }, t("Un appareil restauré avec ton Emergency Kit demande ta confiance. Refuse-le si ce n'est pas toi.", "A device restored with your Emergency Kit asks for your trust. Refuse it if it isn't you."))]
    : [];
  const claim: Node[] = kit?.awaitingTrust
    ? [h("div", { class: "card list-card spaced" }, h("button", { class: "row", type: "button", id: "claim-only", onclick: () => askPassword(t("Je n'ai plus d'autre appareil", "I No Longer Have Another Device"), t("Confirmer", "Confirm"),
        (password) => call("claim_only_device", { password })) }, icon("key", 22, "accent"), h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Je n'ai plus d'autre appareil", "I No Longer Have Another Device"))))),
      h("p", { class: "footnote" }, t("Ce PC a été restauré avec ton Emergency Kit : un autre de tes appareils doit lui faire confiance. Sans autre appareil, confirme-le ici.", "This PC was restored with your Emergency Kit: another of your devices must trust it. Without another device, confirm it here."))]
    : [];
  const synced = sv?.backend === "mailbox";
  const add = h("button", { class: "row", type: "button", id: "add-device", disabled: !synced, onclick: () => hostSheet(redraw) }, icon("person_add", 22, "accent"), h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Ajouter un appareil", "Add a Device"))));
  return [head, h("div", { class: "caps" }, t("Sur ton compte", "On Your Account")), h("div", { class: "card list-card" }, ...rows), h("p", { class: "footnote" }, t("Liste signée par ton compte.", "List signed by your account.")),
    ...kitSection,
    ...claim,
    h("div", { class: "card list-card spaced" }, add),
    h("p", { class: "footnote" }, synced
      ? t("Sur le nouvel appareil : « Ajouter cet appareil », puis saisis son code.", "On the new device: “Add This Device”, then type its code.")
      : t("Connecte-toi à Internet pour finir la mise en place de la synchronisation.", "Connect to the internet to finish setting up sync."))];
}

function renameDevice(d: DeviceInfo, redraw: () => void): void {
  const input = h("input", { id: "device-name", value: d.name });
  const err = h("div", { class: "error", role: "alert" });
  const s = sheet(t("Renommer", "Rename"), {
    action: t("Renommer", "Rename"),
    onAction: async (sh) => {
      try {
        await call("rename_device", { id: d.id, name: input.value });
        sh.close();
        redraw();
      } catch (e) {
        err.textContent = message(e);
      }
    },
  });
  s.body.append(h("div", { class: "card" }, h("div", { class: "field-box" }, input)), err);
  queueMicrotask(() => input.select());
}

function revokeDevice(d: DeviceInfo, redraw: () => void): void {
  const pw = secretInput("revoke-pw", t("Mot de passe maître", "Master Password"), "current-password");
  const err = h("div", { class: "error", role: "alert" });
  const s = sheet(t(`Retirer ${d.name} ?`, `Remove ${d.name}?`), {
    action: t("Retirer cet appareil", "Remove This Device"),
    onAction: async (sh) => {
      try {
        await call("revoke_device", { id: d.id, password: pw.input.value });
        sh.close();
        toast(t(`${d.name} est retiré`, `${d.name} is removed`));
        redraw();
      } catch (e) {
        err.textContent = message(e);
      }
    },
  });
  (s.dialog.querySelector(".bar-text.bold") as HTMLElement).classList.add("destructive");
  s.body.append(h("p", { class: "secondary" }, t("Il efface ses données Cleon dès qu'il voit la liste des appareils. Tu pourras l'ajouter de nouveau plus tard.", "It erases its Cleon data as soon as it sees the device list. You can add it again later.")),
    pw.box, h("p", { class: "footnote" }, t("Confirme avec ton mot de passe maître.", "Confirm with your master password.")), err);
  queueMicrotask(() => pw.input.focus());
}

// ---- pairing ---------------------------------------------------------------------------------

interface PairView {
  role: "host" | "join";
  step: string;
  code: string | null;
  qr: { modules: boolean[]; width: number } | null;
  expiresAt: number | null;
  sas: string | null;
  peerName: string | null;
  peerKind: string | null;
  peerConfirmed: boolean;
  wrongPassword: boolean;
  error: string | null;
  detail: string | null;
}

function pairError(v: PairView): string {
  switch (v.error) {
    case "noMailbox":
      return t("Connecte-toi à Internet pour finir la mise en place de la synchronisation.", "Connect to the internet to finish setting up sync.");
    case "refused":
      return t("Ce code n'est pas valable. Vérifie-le, ou demande-en un nouveau sur ton autre appareil.", "This code isn't valid. Check it, or show a new one on your other device.");
    case "codeRejected":
      return t("Les codes n'étaient pas identiques : rien n'a été partagé.", "The codes didn't match: nothing was shared.");
    case "connectionLost":
      return t("La connexion avec ton autre appareil a été coupée.", "The connection with your other device was lost.");
    case "timeout":
      return t("Ton autre appareil n'a pas répondu à temps. Réessaie.", "Your other device didn't answer in time. Try again.");
    case "offline":
      return t("Impossible de joindre le serveur. Vérifie ta connexion puis réessaie.", "Can't reach the server. Check your connection and try again.");
    default:
      return v.detail ?? t("L'appairage n'a pas abouti", "Pairing didn't go through");
  }
}

/** The 6 digits, as `PairingCodeView` draws them. */
const sasView = (code: string): HTMLElement => h("div", { class: "sas", id: "pair-sas" }, ...code.replace(/\D/g, "").split("").map((c) => h("span", {}, c)));

/** "Ajouter un appareil" (HostDeviceSheet): the code on screen, then the 6 digits, the master password and the grant. */
function hostSheet(after: () => void): void {
  let stopped = false;
  const s = sheet(t("Ajouter un appareil", "Add a Device"), { cancel: t("Annuler", "Cancel") });
  s.dialog.classList.add("pair-sheet");
  const body = h("div", { class: "pair-body" });
  s.body.append(body);
  const sasIn = h("input", { id: "host-sas", inputmode: "numeric", maxlength: 7, placeholder: "123456", autocomplete: "off", class: "mono center-text" });
  const pw = secretInput("host-pw", t("Mot de passe maître", "Master Password"), "current-password");
  const err = h("div", { class: "error", role: "alert" });
  const approve = h("button", { class: "capsule prominent", type: "button", id: "host-approve" }, t("Les codes sont identiques", "The codes match"));
  approve.addEventListener("click", async () => {
    err.textContent = "";
    approve.disabled = true;
    try {
      await call("pair_host_approve", { sas: sasIn.value, password: pw.input.value });
      pw.input.value = "";
    } catch (e) {
      const code = (e as UiError).code;
      err.textContent = code === "SasMismatch" ? t("Ce n'est pas le code du nouvel appareil. S'il est différent, quelqu'un d'autre essaie de se connecter.", "That isn't the new device's code. If it differs, someone else is trying to connect.") : message(e);
    }
    approve.disabled = false;
  });
  const differ = h("button", { class: "bar-text destructive", type: "button", id: "host-differ", onclick: () => void call("pair_cancel").then(() => s.close()) }, t("Ils sont différents", "They're different"));
  let shown = "";
  const draw = (v: PairView) => {
    const key = v.step + (v.code ?? "") + (v.peerConfirmed ? "c" : "");
    if (key === shown) return;
    shown = key;
    const center = (...c: Child[]) => h("div", { class: "column pair-center" }, ...c);
    switch (v.step) {
      case "connecting":
        body.replaceChildren(center(h("div", { class: "spinner" }), h("p", { class: "secondary" }, t("Connexion…", "Connecting…"))));
        break;
      case "hosting": {
        const left = Math.max(0, (v.expiresAt ?? 0) - Math.floor(Date.now() / 1000));
        body.replaceChildren(center(
          h("h2", {}, t("Sur le nouvel appareil", "On the new device")),
          h("p", { class: "secondary center-text" }, t("Choisis « Ajouter cet appareil », puis saisis ce code.", "Choose “Add This Device”, then type this code.")),
          v.qr ? h("div", { class: "qr-large" }, qrSvg(v.qr.modules, v.qr.width, 220)) : null,
          h("p", { class: "footnote secondary" }, t("Ou saisis ce code", "Or type this code")),
          h("div", { class: "pair-code", id: "host-code" }, v.code ?? ""),
          h("p", { class: "footnote secondary" }, t(`Un nouveau code s'affiche toutes les 30 s. Celui-ci reste valable ${left} s.`, `A new code shows every 30 s. This one stays valid for ${left} s.`)),
          h("p", { class: "footnote secondary" }, t("Ne montre ce code qu'à ton propre appareil, devant toi.", "Show this code only to your own device, in front of you.")),
        ));
        break;
      }
      case "comparing":
      case "waitingForPeer":
        body.replaceChildren(
          h("div", { class: "card list-card" }, h("div", { class: "row static", id: "host-peer" }, tile("key", "var(--accent)", 36),
            h("span", { class: "row-text" }, h("span", { class: "row-title bold" }, v.peerName ?? ""), h("span", { class: "row-sub" }, t(`${kindName(v.peerKind ?? "")} · demande un accès ${modeName("personal")}`, `${kindName(v.peerKind ?? "")} · asks for ${modeName("personal")} access`))))),
          h("p", { class: "footnote" }, t("Il recevra tout ton compte et ta Secret Key, puis te demandera ton mot de passe maître.", "It will receive your whole account and your Secret Key, then ask for your master password.")),
          h("div", { class: "caps" }, t("Code de vérification", "Verification code")),
          h("p", { class: "secondary" }, t("Cet appareil n'est pas sur ton réseau : tape les 6 chiffres affichés sur le nouvel appareil.", "This device isn't on your network: type the 6 digits shown on the new device.")),
          h("div", { class: "card" }, h("div", { class: "field-box" }, sasIn)),
          pw.box,
          h("p", { class: "footnote" }, t("Confirme avec ton mot de passe maître.", "Confirm with your master password.")),
          err,
          v.step === "waitingForPeer"
            ? h("p", { class: "secondary", id: "host-waiting" }, t("En attente du nouvel appareil... Confirme que les codes sont identiques sur le nouvel appareil.", "Waiting for the new device... Confirm the codes match on the new device."))
            : h("div", { class: "buttons-row left" }, approve, differ),
        );
        if (v.step === "comparing") queueMicrotask(() => sasIn.focus());
        break;
      case "granting":
        body.replaceChildren(center(h("div", { class: "spinner" }), h("p", { class: "secondary" }, t("Envoi...", "Sending..."))));
        break;
      case "done":
        body.replaceChildren(center(icon("check_circle", 56, "green"), h("h2", { id: "host-done" }, t("Appareil ajouté", "Device added")), h("p", { class: "secondary center-text" }, t("Il te demande maintenant ton mot de passe maître.", "It now asks for your master password."))));
        break;
      default:
        body.replaceChildren(center(icon("warning", 56, "red"), h("h2", {}, t("L'appairage n'a pas abouti", "Pairing didn't go through")), h("p", { class: "secondary center-text", id: "host-error" }, pairError(v))));
    }
  };
  const poll = async () => {
    if (stopped || !s.dialog.isConnected) {
      stopped = true;
      return;
    }
    const st = await call<{ active: boolean; view: PairView | null }>("pair_state").catch(() => null);
    if (st?.view) draw(st.view);
    if (st?.view && (st.view.step === "done" || st.view.step === "failed")) {
      (s.dialog.querySelector(".sheet-bar .bar-text") as HTMLElement).textContent = "OK";
      after();
      return;
    }
    if (st?.view?.step === "hosting") shown = "";
    window.setTimeout(poll, 500);
  };
  s.dialog.addEventListener("close", () => {
    stopped = true;
    void call("pair_cancel");
  });
  void call("pair_host_start").then(poll).catch((e) => {
    body.replaceChildren(h("p", { class: "error" }, message(e)));
  });
}

/** "Ajouter cet appareil" (JoinCodeSteps): type the code, compare the digits, then the master password. */
function joinScreen(): HTMLElement {
  const code = h("input", { id: "join-code", placeholder: "K7QM-4XPR", autocomplete: "off", spellcheck: false, class: "mono" });
  const err = h("div", { class: "error", role: "alert" });
  const server = h("button", { class: "bar-text", type: "button", id: "join-server" });
  let choice: SyncChoice = { kind: "hosted" };
  const label = () => (server.textContent = t(`Serveur : ${choiceName(choice)}`, `Server: ${choiceName(choice)}`));
  label();
  server.addEventListener("click", () => syncChoiceSheet(choice, (c) => ((choice = c), label())));
  const go = h("button", { class: "capsule prominent", type: "submit", id: "join-go" }, t("Continuer", "Continue"));
  const pane = h("div", { class: "column left" });
  const form = h("form", {
    class: "column left",
    onsubmit: async (ev: Event) => {
      ev.preventDefault();
      err.textContent = "";
      if (!code.value.trim()) return;
      go.disabled = true;
      try {
        await call("pair_join_start", { code: code.value, server: choice });
        void follow();
      } catch (e) {
        err.textContent = (e as UiError).code === "BadCode" ? t("Ce code n'est pas valable. Vérifie-le, ou demande-en un nouveau sur ton autre appareil.", "This code isn't valid. Check it, or show a new one on your other device.") : message(e);
        go.disabled = false;
      }
    },
  },
    h("h1", { class: "big" }, t("Saisis le code", "Type the code")),
    h("p", { class: "secondary" }, t("Sur ton autre appareil : Réglages > Appareils > Ajouter un appareil. Le code à 8 caractères s'affiche sous le QR code.", "On your other device: Settings > Devices > Add a Device. The 8-character code shows under the QR code.")),
    h("label", { class: "caps", for: "join-code" }, t("Code d'appairage", "Pairing code")),
    h("div", { class: "field-box" }, code),
    err,
    h("div", { class: "buttons-row" }, go),
    server,
    h("button", { class: "bar-text", type: "button", onclick: () => mount(welcome()) }, t("Retour", "Back")),
  );
  pane.append(form);
  const pw = secretInput("join-pw", t("Mot de passe maître", "Master Password"), "current-password");
  let shown = "";
  const cancel = h("button", { class: "bar-text", type: "button", onclick: () => void call("pair_cancel").then(() => mount(welcome())) }, t("Annuler", "Cancel"));
  const follow = async (): Promise<void> => {
    const st = await call<{ active: boolean; view: PairView | null }>("pair_state").catch(() => null);
    const v = st?.view;
    if (!v) return;
    const key = v.step + (v.wrongPassword ? "!" : "");
    if (key !== shown) {
      shown = key;
      const title = (a: string, b?: string): Node[] => keep(h("h1", { class: "big" }, a), b ? h("p", { class: "secondary" }, b) : null);
      switch (v.step) {
        case "connecting":
          pane.replaceChildren(...title(t("Connexion à ton autre appareil", "Connecting to Your Other Device")), h("div", { class: "spinner" }), cancel);
          break;
        case "comparing": {
          const yes = h("button", { class: "capsule prominent", type: "button", id: "join-match", onclick: () => void call("pair_join_confirm") }, t("Les codes sont identiques", "The codes match"));
          const no = h("button", { class: "bar-text destructive", type: "button", id: "join-differ", onclick: () => void call("pair_cancel").then(() => mount(welcome())) }, t("Ils sont différents", "They're different"));
          pane.replaceChildren(...title(t("Compare les codes", "Compare the codes"), t("Le même code doit s'afficher sur ton autre appareil. S'il est différent, quelqu'un d'autre essaie de se connecter.", "The same code must show on your other device. If it differs, someone else is trying to connect.")),
            sasView(v.sas ?? ""), h("div", { class: "buttons-row" }, yes, no));
          break;
        }
        case "waitingForApproval":
          pane.replaceChildren(...title(t("En attente de ton autre appareil", "Waiting for your other device"), t("Confirme les codes sur ton autre appareil, puis valide avec ton mot de passe maître.", "Confirm the codes on your other device, then approve with your master password.")), h("div", { class: "spinner" }), cancel);
          break;
        case "password":
        case "importing": {
          const perr = h("div", { class: "error", role: "alert" }, v.wrongPassword ? t("Mot de passe incorrect. Tu peux réessayer.", "Incorrect password. You can try again.") : "");
          const ok = h("button", { class: "capsule prominent", type: "submit", id: "join-unlock", disabled: v.step === "importing" }, v.step === "importing" ? t("Déverrouillage...", "Unlocking...") : t("Déverrouiller", "Unlock"));
          const f = h("form", { class: "column left", onsubmit: (ev: Event) => {
            ev.preventDefault();
            if (!pw.input.value) return;
            void call("pair_join_password", { password: pw.input.value });
            pw.input.value = "";
          } }, ...title(t("Ton mot de passe maître", "Your master password"), t("Ton autre appareil a envoyé ton compte. Saisis ton mot de passe maître pour l'ouvrir sur ce PC.", "Your other device sent your account. Enter your master password to open it on this PC.")), pw.box, perr, h("div", { class: "buttons-row" }, ok));
          pane.replaceChildren(f);
          queueMicrotask(() => pw.input.focus());
          break;
        }
        case "done":
          if (v.error === "enrollFailed") toast(t("Ton compte est sur ce PC, mais la synchronisation n'a pas pu être mise en place : ajoute de nouveau cet appareil plus tard.", "Your account is on this PC, but sync could not be set up: add this device again later."));
          void route();
          return;
        default:
          pane.replaceChildren(...title(t("L'appairage n'a pas abouti", "Pairing didn't go through")), h("p", { class: "error", id: "join-error" }, pairError(v)), h("button", { class: "capsule", type: "button", onclick: () => void call("pair_cancel").then(() => mount(joinScreen())) }, t("Recommencer", "Start Over")));
          return;
      }
    }
    window.setTimeout(() => void follow(), 400);
  };
  queueMicrotask(() => code.focus());
  return h("div", { class: "center" }, pane);
}

// ---- Emergency Kit restore (RestoreStep) ----------------------------------------------------

function restoreScreen(): HTMLElement {
  const key = h("input", { id: "restore-key", placeholder: "A3-XXXXXX-XXXXXX-...", autocomplete: "off", spellcheck: false, class: "mono" });
  const pw = secretInput("restore-pw", t("Mot de passe maître", "Master Password"), "current-password");
  const err = h("div", { class: "error", role: "alert" });
  let choice: SyncChoice = { kind: "hosted" };
  const server = h("button", { class: "bar-text", type: "button", id: "restore-server" });
  const label = () => (server.textContent = t(`Serveur : ${choiceName(choice)}`, `Server: ${choiceName(choice)}`));
  label();
  server.addEventListener("click", () => syncChoiceSheet(choice, (c) => ((choice = c), label()), t("Mon serveur", "My Server")));
  const go = h("button", { class: "capsule prominent", type: "submit", id: "restore-go" }, t("Déverrouiller", "Unlock"));
  // The kit's QR code from an image (a scan, a screenshot of the PDF): the key and a self-host's server.
  const scan = h("button", { class: "bar-text", type: "button", id: "restore-scan" }, t("Lire le QR code du kit dans une image…", "Read the Kit's QR Code from an Image…"));
  scan.addEventListener("click", async () => {
    err.textContent = "";
    try {
      const kit = await call<{ secretKey: string; server: string | null } | null>("read_kit_image");
      if (!kit) return;
      key.value = kit.secretKey;
      if (kit.server) {
        choice = { kind: "selfHost", url: kit.server, caPem: null };
        label();
      }
      pw.input.focus();
    } catch (e) {
      err.textContent = (e as UiError).code === "NoKit" ? t("Aucun QR code d'Emergency Kit dans cette image.", "No Emergency Kit QR code in this image.") : message(e);
    }
  });
  const form = h("form", {
    class: "column left",
    onsubmit: async (ev: Event) => {
      ev.preventDefault();
      err.textContent = "";
      if (!key.value.trim() || !pw.input.value) return;
      go.disabled = true;
      go.textContent = t("Recherche du compte...", "Looking for Your Account...");
      const password = pw.input.value;
      pw.input.value = "";
      try {
        await call("restore_kit", { secretKey: key.value, password, server: choice });
        key.value = "";
        await route();
      } catch (e) {
        const code = (e as UiError).code;
        err.textContent = code === "NotFound" ? t("Aucun compte trouvé pour cette Secret Key. Vérifie-la, ou indique ton serveur.", "No account found for this Secret Key. Check it, or enter your server.")
          : code === "Offline" ? t("Impossible de joindre le serveur. Vérifie ta connexion puis réessaie.", "Can't reach the server. Check your connection and try again.")
          : code === "BadKey" ? t("Cette Secret Key n'est pas valide. Vérifie-la sur ton kit.", "This Secret Key isn't valid. Check it on your kit.")
          : code === "WrongPassword" ? t("Mot de passe incorrect. Tu peux réessayer.", "Incorrect password. You can try again.")
          : code === "OutdatedKit" ? t("Ce kit n'est plus à jour : utilise le dernier Emergency Kit imprimé.", "This kit is out of date: use the latest Emergency Kit you printed.")
          : message(e);
        go.disabled = false;
        go.textContent = t("Déverrouiller", "Unlock");
      }
    },
  },
    h("h1", { class: "big" }, t("Utiliser ton Emergency Kit", "Use Your Emergency Kit")),
    h("p", { class: "secondary" }, t("Tape la Secret Key imprimée sur ton kit. Minuscules, espaces et tirets oubliés sont acceptés.", "Type the Secret Key printed on your kit. Lowercase letters, spaces and missing dashes are fine.")),
    h("label", { class: "caps", for: "restore-key" }, "Secret Key"),
    h("div", { class: "field-box" }, key),
    scan,
    h("label", { class: "caps", for: "restore-pw" }, t("Mot de passe maître", "Master Password")),
    pw.box,
    err,
    h("div", { class: "buttons-row" }, go),
    server,
    h("button", { class: "bar-text", type: "button", onclick: () => mount(welcome()) }, t("Retour", "Back")),
  );
  queueMicrotask(() => key.focus());
  return h("div", { class: "center" }, form);
}

void listen<SyncView>("sync-status", (e) => {
  syncView = e.payload;
  const page = document.querySelector("#sync-status");
  if (page && syncRedraw) syncRedraw();
});

void listen("sync-changed", () => {
  // A round brought changes: the lists and the open item show them.
  if (document.querySelector(".shell")) void refresh(ui.selected).catch(() => {});
  else if (document.getElementById("lock-alerts")) void showLockAlerts();
});

// ---- sharing: contacts, shared vaults, sends, family, recovery ----------------------------------
// The Apple apps' Sharing and Family screens (sharing spec 5 to 14): every
// name is the contact book's local name, every role the core's.

type Role = "read" | "write" | "manage";
interface ContactInfo {
  accountId: string;
  name: string;
  level: "link" | "verified";
  state: "active" | "keysChanged" | "removed";
  verifiedAt: number;
  safetyNumber: string;
}
interface MemberInfo {
  accountId: string;
  name: string;
  role: Role;
  owner: boolean;
  level: "link" | "verified";
  keysChanged: boolean;
  keyPending: boolean;
}
interface SharedVaultInfo {
  vaultId: string;
  name: string;
  role: Role;
  owner: boolean;
  generation: number;
  members: MemberInfo[];
  identityPending: boolean;
  notConfirmed: number;
  refused: boolean;
  full: boolean;
}
interface ShareInviteInfo {
  id: string;
  vaultNameHint: string | null;
  fromName: string;
  role: Role;
  serverHost: string;
}
interface IdentityChangeInfo {
  accountId: string;
  name: string;
  child: string;
  rotatorName: string | null;
  revokedNames: string[];
  issuedAt: number;
  vaults: string[];
  offer: "code" | "inPerson" | "forked";
}
interface FamilyInfo {
  familyId: string;
  members: { accountId: string; name: string; role: "member" | "organizer"; level: string; keysChanged: boolean }[];
  vaults: string[];
  iAmOrganizer: boolean;
  needsSecondOrganizer: boolean;
}
interface HelperInfo {
  member: string;
  name: string;
  enrollmentId: string;
  delaySecs: number;
}
interface ReceivedInfo {
  sendId: string;
  fromName: string;
  title: string;
  kind: string;
  expiresAt: number;
}
interface SharingInfo {
  zonesReady: boolean;
  contacts: ContactInfo[];
  sharedVaults: SharedVaultInfo[];
  shareInvites: ShareInviteInfo[];
  identityChanges: IdentityChangeInfo[];
  family: FamilyInfo | null;
  familyInvites: { id: string; fromName: string; role: "member" | "organizer" }[];
  recoveryEnrollment: { enrollmentId: string; organizerName: string; delaySecs: number; createdAt: number; valid: boolean } | null;
  helpers: HelperInfo[];
  receivedItems: ReceivedInfo[];
  seenByFormerMembers: string[];
}
interface RecoveryAlertInfo {
  enrollmentId: string;
  organizerName: string;
  releaseAfter: number;
}
interface InviteInfo {
  role: "inviter" | "invitee" | "";
  step: "" | "creating" | "sharing" | "replying" | "waitingAnswer" | "done" | "failed";
  link: string | null;
  expiresAt: number | null;
  contact: ContactInfo | null;
  error: string | null;
  detail: string | null;
}
type RecoveryStatus =
  | { kind: "waiting"; releaseAfter: number }
  | { kind: "ready" }
  | { kind: "cancelled"; at: number }
  | { kind: "replaced" }
  | { kind: "notEnrolled" };

const EMPTY_SHARING: SharingInfo = {
  zonesReady: false, contacts: [], sharedVaults: [], shareInvites: [], identityChanges: [], family: null, familyInvites: [],
  recoveryEnrollment: null, helpers: [], receivedItems: [], seenByFormerMembers: [],
};
let sharing: SharingInfo = EMPTY_SHARING;
let recoveryAlerts: RecoveryAlertInfo[] = [];

async function loadSharing(): Promise<void> {
  sharing = await call<SharingInfo>("sharing_state").catch(() => EMPTY_SHARING);
  recoveryAlerts = await call<RecoveryAlertInfo[]>("recovery_alerts").catch(() => []);
}

const roleName = (r: Role): string => (r === "read" ? t("Lecture", "Read") : r === "write" ? t("Écriture", "Write") : t("Gestion", "Manage"));
const familyRoleName = (r: string): string => (r === "organizer" ? t("Organisateur", "Organizer") : t("Membre", "Member"));
const youName = (): string => t("Toi", "You");
const longDate = (s: number): string => new Date(s * 1000).toLocaleDateString(t("fr-FR", "en-US"), { day: "numeric", month: "long", year: "numeric" });
const shortTime = (s: number): string => new Date(s * 1000).toLocaleTimeString(t("fr-FR", "en-US"), { hour: "2-digit", minute: "2-digit" });

/** "Non vérifié" next to a contact added by link. */
const unverifiedBadge = (): HTMLElement => h("span", { class: "badge orange-badge", "data-id": "unverified" }, t("Non vérifié", "Not verified"));

/** The sharing errors of the core, in the Apple apps' words. */
function sharingMessage(e: unknown): string {
  switch ((e as UiError)?.code) {
    case "ContactNotVerified":
      return t("Vérifie d'abord ce contact en personne ou avec son numéro de sécurité.", "Verify this contact in person or with their safety number first.");
    case "ReadOnlyRole":
      return t("Tu peux seulement consulter ce coffre.", "You can only view this vault.");
    case "IdentityPending":
      return t("Un gestionnaire du coffre doit confirmer tes nouvelles clés avant que tu puisses modifier.", "A vault manager must confirm your new keys before you can make changes.");
    case "MembershipFork":
      return t("Le serveur a montré deux listes de membres différentes.", "The server showed two different member lists.");
    case "NoSync":
      return t("Le partage passe par la synchronisation : active-la dans Réglages > Sync.", "Sharing goes through sync: turn it on in Settings > Sync.");
    case "BadLink":
      return t("Ce n'est pas un lien d'invitation Cleon.", "This isn't a Cleon invitation link.");
    case "BadCode":
      return t("Saisis les 6 chiffres.", "Type the 6 digits.");
    default:
      return message(e);
  }
}

function contactRow(c: ContactInfo, onclick?: () => void, trailing?: Node | null): HTMLElement {
  const kids: Child[] = [monogram(initials(c.name), "var(--accent)", 30, true), h("span", { class: "row-text" }, h("span", { class: "row-title" }, c.name)),
    c.level === "link" ? unverifiedBadge() : null, trailing ?? null];
  return onclick
    ? h("button", { class: "row contact-row", type: "button", "data-name": c.name, onclick }, ...kids, icon("chevron_right", 18, "chev"))
    : h("div", { class: "row static contact-row", "data-name": c.name }, ...kids);
}

/** An error line under a sheet, as `SharingErrorSection` shows it. */
const errorLine = (): HTMLElement => h("div", { class: "error", role: "alert" });

// ---- banners (SharingBanners) --------------------------------------------------------------------

function recoveryAlertCard(a: RecoveryAlertInfo, after: () => void): HTMLElement {
  const err = h("p", { class: "footnote red-text" });
  const cancel = h("button", { class: "bar-text destructive", type: "button", id: "recovery-cancel" }, t("Annuler la récupération", "Cancel recovery"));
  cancel.addEventListener("click", async () => {
    cancel.disabled = true;
    try {
      await call("cancel_recovery", { enrollmentId: a.enrollmentId });
      after();
    } catch (e) {
      err.textContent = sharingMessage(e);
      cancel.disabled = false;
    }
  });
  return h("div", { class: "banner warn", id: "recovery-alert" },
    h("div", { class: "banner-line" }, icon("shield_lock", 22, "orange"),
      h("span", { id: "recovery-alert-message" }, t(`${a.organizerName} a demandé à récupérer ton compte. Ce sera possible le ${longDate(a.releaseAfter)} à ${shortTime(a.releaseAfter)}. Si ce n'est pas toi, annule.`,
        `${a.organizerName} asked to recover your account. It will be possible on ${longDate(a.releaseAfter)} at ${shortTime(a.releaseAfter)}. If this isn't you, cancel.`))),
    cancel, err);
}

function sharingBanners(): HTMLElement | null {
  const rows: Node[] = recoveryAlerts.map((a) => recoveryAlertCard(a, () => void refresh(undefined)));
  const row = (id: string, text: string, ic: IconName, open: () => void) =>
    h("button", { class: "banner", type: "button", id: `banner-${id}`, onclick: open }, icon(ic, 20, "accent"), h("span", { class: "row-text" }, text), icon("chevron_right", 16, "chev"));
  if (sharing.shareInvites.length) rows.push(row("invites", t(`Invitations à un coffre : ${sharing.shareInvites.length}`, `Vault invitations: ${sharing.shareInvites.length}`), "person_add", () => shareInvitesSheet()));
  if (sharing.identityChanges.length) rows.push(row("identity", t(`Clés changées : ${sharing.identityChanges.length}`, `Changed keys: ${sharing.identityChanges.length}`), "key", () => identitySheet()));
  if (sharing.receivedItems.length) rows.push(row("received", t(`Éléments reçus : ${sharing.receivedItems.length}`, `Received items: ${sharing.receivedItems.length}`), "upload", () => receivedSheet()));
  if (sharing.familyInvites.length) rows.push(row("family", t(`Rejoindre la famille de ${sharing.familyInvites[0]!.fromName}`, `Join ${sharing.familyInvites[0]!.fromName}'s family`), "person_add", () => openSettings("family")));
  return rows.length ? h("div", { class: "banners" }, ...rows) : null;
}

/** After a sharing write: the lists, the sidebar and the open page again. */
async function afterSharing(redraw?: () => void): Promise<void> {
  await refresh(ui.selected);
  redraw?.();
}

// ---- Settings > Contacts (ContactsView) ------------------------------------------------------------

async function contactsPage(head: HTMLElement, redraw: () => void): Promise<Node[]> {
  await loadSharing();
  const s = sharing;
  const list = s.contacts.length
    ? s.contacts.map((c) => contactRow(c, () => contactSheet(c, redraw)))
    : [h("div", { class: "row static" }, h("span", { class: "row-text secondary" }, t("Aucun contact. Ajoute quelqu'un en personne ou par lien.", "No contacts. Add someone in person or by link.")))];
  const add = h("button", { class: "row", type: "button", id: "contacts-add-link", onclick: () => inviteSheet(redraw) }, icon("link", 22, "accent"),
    h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Ajouter par lien", "Add by link"))));
  const waiting: Node[] = [];
  const countRow = (id: string, label: string, n: number, open: () => void) =>
    h("button", { class: "row", type: "button", id, onclick: open }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, label)), h("span", { class: "secondary" }, String(n)), icon("chevron_right", 18, "chev"));
  if (s.shareInvites.length) waiting.push(countRow("contacts-invites", t("Invitations", "Invitations"), s.shareInvites.length, () => shareInvitesSheet(redraw)));
  if (s.receivedItems.length) waiting.push(countRow("contacts-received", t("Éléments reçus", "Received items"), s.receivedItems.length, () => receivedSheet(redraw)));
  if (s.identityChanges.length) waiting.push(countRow("contacts-identity", t("Clés changées", "Changed keys"), s.identityChanges.length, () => identitySheet(redraw)));
  return keep(head,
    h("div", { class: "card list-card", id: "contacts-list" }, ...list),
    h("div", { class: "caps" }, t("Ajouter un contact", "Add a contact")),
    h("div", { class: "card list-card" }, add),
    h("p", { class: "footnote" }, s.zonesReady
      ? t("Le lien expire après 24 heures. Un contact ajouté par lien n'a que la lecture tant qu'il n'est pas vérifié.", "The link expires after 24 hours. A contact added by link only gets Read until verified.")
      : t("Le partage passe par la synchronisation : active-la dans Réglages > Sync.", "Sharing goes through sync: turn it on in Settings > Sync.")),
    waiting.length ? h("div", { class: "card list-card spaced" }, ...waiting) : null);
}

/** "Ajouter par lien": make a link to send, or paste the one a contact sent. */
function inviteSheet(after: () => void): void {
  let stopped = false;
  const s = sheet(t("Ajouter par lien", "Add by link"), { cancel: t("Annuler", "Cancel") });
  const body = h("div", {});
  s.body.append(body);
  const err = errorLine();
  const paste = h("input", { id: "invite-link-in", placeholder: "onepass://contact#…", spellcheck: false, autocomplete: "off", class: "mono" });
  const create = h("button", { class: "row", type: "button", id: "invite-create" }, icon("link", 22, "accent"), h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Créer un lien", "Create link"))));
  const open = h("button", { class: "capsule prominent", type: "button", id: "invite-open" }, t("Ouvrir le lien", "Open link"));
  const start = async (cmd: string, args?: Record<string, unknown>) => {
    err.textContent = "";
    try {
      await call(cmd, args);
      void poll();
    } catch (e) {
      err.textContent = sharingMessage(e);
    }
  };
  create.addEventListener("click", () => void start("contact_invite_create"));
  open.addEventListener("click", () => void start("contact_invite_open", { link: paste.value }));
  body.append(
    h("div", { class: "card list-card" }, create),
    h("p", { class: "footnote" }, t("Le lien expire après 24 heures. Un contact ajouté par lien n'a que la lecture tant qu'il n'est pas vérifié.", "The link expires after 24 hours. A contact added by link only gets Read until verified.")),
    h("div", { class: "caps" }, t("Tu as reçu un lien ?", "Received a link?")),
    h("div", { class: "card" }, h("div", { class: "field-box" }, paste)),
    h("div", { class: "buttons-row left" }, open),
    err);
  let shown = "";
  const draw = (v: InviteInfo) => {
    const key = v.step + (v.link ?? "") + (v.error ?? "");
    if (key === shown) return;
    shown = key;
    const waitingLine = h("div", { class: "row static", id: "invite-waiting" }, icon("hourglass", 22, "secondary"), h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("En attente de la réponse…", "Waiting for a reply…"))));
    switch (v.step) {
      case "creating":
      case "replying":
        body.replaceChildren(h("div", { class: "column pair-center" }, h("div", { class: "spinner" })));
        break;
      case "sharing": {
        const copy = h("button", { class: "capsule prominent", type: "button", id: "invite-copy" }, icon("copy", 18), t("Copier le lien", "Copy link"));
        copy.addEventListener("click", async () => {
          await navigator.clipboard.writeText(v.link ?? "").catch(() => {});
          toast(t("Lien copié", "Link copied"));
        });
        body.replaceChildren(
          h("div", { class: "caps" }, t("Envoyer le lien", "Send link")),
          h("div", { class: "card pad" }, h("div", { class: "mono invite-link", id: "invite-link" }, v.link ?? "")),
          h("div", { class: "buttons-row left" }, copy),
          h("p", { class: "footnote" }, t("Envoie ce lien à ton contact par le moyen de ton choix. Il expire après 24 heures.", "Send this link to your contact any way you like. It expires after 24 hours.")),
          h("div", { class: "card list-card" }, waitingLine));
        break;
      }
      case "waitingAnswer":
        body.replaceChildren(h("div", { class: "card list-card" }, waitingLine));
        break;
      case "done":
        if (v.contact) body.replaceChildren(h("div", { class: "card list-card", id: "invite-done" }, contactRow(v.contact)),
          h("p", { class: "footnote" }, t("Ajouté par lien. Compare le numéro de sécurité pour le vérifier.", "Added by link. Compare the safety number to verify.")));
        break;
      case "failed": {
        const text = v.error === "expired" ? t("L'invitation a expiré. Envoie un nouveau lien.", "The invitation expired. Send a new link.")
          : v.error === "offline" ? t("Connecte-toi à Internet pour terminer l'ajout de ce contact.", "Connect to the internet to finish adding this contact.")
          : v.error === "badLink" ? t("Ce n'est pas un lien d'invitation Cleon.", "This isn't a Cleon invitation link.")
          : v.error === "own" ? t("Ce lien vient de ton propre compte.", "This link comes from your own account.")
          : v.error === "noSync" ? sharingMessage({ code: "NoSync" })
          : v.detail ?? t("L'ajout n'a pas abouti.", "Adding didn't go through.");
        body.replaceChildren(h("div", { class: "column pair-center" }, icon("warning", 48, "red"), h("p", { class: "secondary center-text", id: "invite-error" }, text)));
        break;
      }
    }
  };
  const poll = async () => {
    if (stopped || !s.dialog.isConnected) return;
    const v = await call<InviteInfo>("contact_invite_state").catch(() => null);
    if (v && v.step) draw(v);
    if (v?.step === "done" || v?.step === "failed") {
      (s.dialog.querySelector(".sheet-bar .bar-text") as HTMLElement).textContent = "OK";
      after();
      return;
    }
    window.setTimeout(poll, 700);
  };
  s.dialog.addEventListener("close", () => {
    stopped = true;
  });
  // A flow already running (a link opened before): its state again.
  void call<InviteInfo>("contact_invite_state").then((v) => {
    if (v.step && v.step !== "done" && v.step !== "failed") void poll();
  });
  queueMicrotask(() => paste.focus());
}

/** One contact (ContactDetailView): level, safety number, rename, remove. */
function contactSheet(c: ContactInfo, after: () => void): void {
  const s = sheet(c.name, { cancel: t("Fermer", "Close") });
  const err = errorLine();
  const name = h("input", { id: "contact-name", value: c.name });
  const rename = h("button", { class: "bar-text", type: "button" }, t("Renommer", "Rename"));
  rename.addEventListener("click", async () => {
    try {
      await call("rename_contact", { accountId: c.accountId, name: name.value });
      s.close();
      after();
    } catch (e) {
      err.textContent = sharingMessage(e);
    }
  });
  const level = c.level === "link" ? unverifiedBadge() : h("span", { class: "green-text", id: "contact-verified" }, icon("check_circle", 16), " ", t("Vérifié", "Verified"));
  const compare = h("button", { class: "row", type: "button", id: "contact-compare", onclick: () => safetySheet(c, () => (s.close(), after())) },
    h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Comparer le numéro de sécurité", "Compare safety number"))), icon("chevron_right", 18, "chev"));
  const remove = h("button", { class: "row", type: "button", id: "contact-remove", onclick: () =>
    confirmSheet(t(`Retirer ${c.name} de tes contacts ? Ses partages avec toi s'arrêtent.`, `Remove ${c.name} from your contacts? Their shares with you stop.`), t("Retirer", "Remove"), async () => {
      try {
        await call("remove_contact", { accountId: c.accountId });
        s.close();
        after();
      } catch (e) {
        err.textContent = sharingMessage(e);
      }
    }) }, h("span", { class: "row-text" }, h("span", { class: "row-title destructive" }, t("Retirer le contact", "Remove contact"))));
  s.body.append(...keep(
    h("div", { class: "card list-card" }, h("div", { class: "row static" }, monogram(initials(c.name), "var(--accent)", 36, true), h("span", { class: "row-text" }, h("span", { class: "row-title bold" }, c.name)), level)),
    c.level === "link" ? h("p", { class: "footnote" }, t("Ajouté par lien. Compare le numéro de sécurité pour le vérifier.", "Added by link. Compare the safety number to verify.")) : null,
    c.level === "link" ? h("div", { class: "card list-card" }, compare) : null,
    c.state === "keysChanged" ? h("p", { class: "footnote orange-text" }, t("Ses clés ont changé", "Their keys changed")) : null,
    h("div", { class: "caps" }, t("Nom", "Name")),
    h("div", { class: "card" }, h("div", { class: "field-box" }, name)),
    h("div", { class: "buttons-row left" }, rename),
    h("p", { class: "footnote" }, t("Ce nom reste sur tes appareils.", "This name stays on your devices.")),
    h("div", { class: "card list-card spaced" }, remove),
    err));
}

/** "Comparer le numéro de sécurité" (SafetyNumberView). */
function safetySheet(c: ContactInfo, after: () => void): void {
  const err = errorLine();
  const s = sheet(t("Comparer le numéro de sécurité", "Compare safety number"), { cancel: t("Annuler", "Cancel") });
  const groups = c.safetyNumber.split(/\s+/).filter(Boolean);
  const match = h("button", { class: "row", type: "button", id: "safety-match" }, h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Les numéros sont identiques", "The numbers match"))));
  match.addEventListener("click", async () => {
    match.disabled = true;
    try {
      await call("confirm_safety_number", { accountId: c.accountId, shown: c.safetyNumber });
      s.close();
      toast(t(`${c.name} est vérifié`, `${c.name} is verified`));
      after();
    } catch (e) {
      err.textContent = sharingMessage(e);
      match.disabled = false;
    }
  });
  s.body.append(
    h("div", { class: "caps" }, t("Numéro de sécurité", "Safety number")),
    h("div", { class: "card pad" }, h("div", { class: "safety-number mono", id: "safety-number" }, ...groups.map((g) => h("span", {}, g)))),
    h("p", { class: "footnote" }, t(`Compare ce numéro avec celui affiché chez ${c.name}, de vive voix ou par appel.`, `Compare this number with the one ${c.name} sees, in person or on a call.`)),
    h("div", { class: "card list-card" }, match),
    err);
}

// ---- invitations, received items, changed keys --------------------------------------------------------

function shareInvitesSheet(after?: () => void): void {
  const s = sheet(t("Invitations", "Invitations"), { cancel: "OK" });
  const err = errorLine();
  const act = async (cmd: string, id: string) => {
    try {
      await call(cmd, { inviteId: id });
      s.close();
      await afterSharing(after);
    } catch (e) {
      err.textContent = sharingMessage(e);
    }
  };
  s.body.append(...sharing.shareInvites.map((i) => h("div", { class: "card list-card spaced share-invite" },
    h("div", { class: "row static" }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, i.vaultNameHint
      ? t(`${i.fromName} t'invite dans « ${i.vaultNameHint} ».`, `${i.fromName} invites you to "${i.vaultNameHint}".`)
      : t(`${i.fromName} t'invite dans un coffre.`, `${i.fromName} invites you to a vault.`)))),
    h("div", { class: "row static" }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Rôle", "Role"))), h("span", { class: "secondary" }, roleName(i.role))),
    h("button", { class: "row", type: "button", id: "invite-accept", onclick: () => void act("accept_share_invite", i.id) }, h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Rejoindre", "Join")))),
    h("button", { class: "row", type: "button", onclick: () => void act("decline_share_invite", i.id) }, h("span", { class: "row-text" }, h("span", { class: "row-title destructive" }, t("Refuser", "Decline")))))), err);
}

function receivedSheet(after?: () => void): void {
  const s = sheet(t("Éléments reçus", "Received items"), { cancel: "OK" });
  const err = errorLine();
  const writable = ui.vaults.filter((v) => v.sharedRole !== "read");
  const into = h("select", { id: "received-into" }, ...writable.map((v) => h("option", { value: v.id }, v.name)));
  const act = async (run: () => Promise<unknown>) => {
    try {
      await run();
      s.close();
      await afterSharing(after);
    } catch (e) {
      err.textContent = sharingMessage(e);
    }
  };
  s.body.append(
    h("div", { class: "card list-card" }, h("label", { class: "row static" }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Dans le coffre", "Into vault"))), into)),
    ...sharing.receivedItems.map((r) => h("div", { class: "card list-card spaced received-item" },
      h("div", { class: "row static" }, art(r.kind, 30), h("span", { class: "row-text" }, h("span", { class: "row-title" }, r.title), h("span", { class: "row-sub" }, t(`De ${r.fromName}`, `From ${r.fromName}`)))),
      h("button", { class: "row", type: "button", id: "received-keep", onclick: () => void act(() => call("accept_received_item", { sendId: r.sendId, into: into.value })) }, h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Garder", "Keep")))),
      h("button", { class: "row", type: "button", onclick: () => void act(() => call("decline_received_item", { sendId: r.sendId })) }, h("span", { class: "row-text" }, h("span", { class: "row-title destructive" }, t("Refuser", "Decline")))))),
    err);
}

function identityMessage(c: IdentityChangeInfo): string {
  const date = longDate(c.issuedAt);
  if (c.offer === "forked") return t(`Deux appareils de ${c.name} se sont retirés l'un l'autre. Lequel a-t-elle encore en main ?`, `Two of ${c.name}'s devices removed each other. Which one do they still have?`);
  if (c.offer === "inPerson") return t(`Les clés de ${c.name} ont changé le ${date}. Pour lui rendre l'accès, vérifiez-vous en personne avec le QR.`, `${c.name}'s keys changed on ${date}. To give them access again, verify each other in person with the QR code.`);
  if (c.rotatorName && c.revokedNames.length) {
    const removed = new Intl.ListFormat(t("fr", "en"), { type: "conjunction" }).format(c.revokedNames);
    return t(`Les clés de ${c.name} ont changé le ${date} (${c.rotatorName} a retiré ${removed}). Demande-lui le code affiché sur son iPhone.`, `${c.name}'s keys changed on ${date} (${c.rotatorName} removed ${removed}). Ask them for the code shown on their iPhone.`);
  }
  return t(`Les clés de ${c.name} ont changé le ${date}. Demande-lui le code affiché sur son iPhone.`, `${c.name}'s keys changed on ${date}. Ask them for the code shown on their iPhone.`);
}

function identitySheet(after?: () => void): void {
  const s = sheet(t("Clés changées", "Changed keys"), { cancel: "OK" });
  const err = errorLine();
  s.body.append(...sharing.identityChanges.map((c) => {
    const code = h("input", { inputmode: "numeric", maxlength: 6, placeholder: t("Code à 6 chiffres", "6-digit code"), class: "mono" });
    const confirm = h("button", { class: "bar-text", type: "button" }, t("Confirmer", "Confirm"));
    confirm.addEventListener("click", async () => {
      try {
        await call("adopt_member_identity", { accountId: c.accountId, child: c.child, code: code.value });
        s.close();
        await afterSharing(after);
      } catch (e) {
        err.textContent = sharingMessage(e);
      }
    });
    return h("div", { class: "card pad spaced" }, h("p", {}, identityMessage(c)),
      c.offer === "code" ? h("div", { class: "field-box" }, code) : h("p", { class: "footnote" }, t("La vérification en personne n'est pas encore disponible sur Windows : faites-la depuis un iPhone ou un Mac.", "In-person verification isn't available on Windows yet: do it from an iPhone or a Mac.")),
      c.offer === "code" ? h("div", { class: "buttons-row left" }, confirm) : null);
  }), err);
}

// ---- shared vaults (ShareVaultSheet, MembersView, RemoveMemberSheet) --------------------------------------

/** "Partage" in the vault editor: the members, or "Partager ce coffre". */
function vaultShareSection(v: Vault, close: () => void): Node[] {
  const shared = sharing.sharedVaults.find((x) => x.vaultId === v.id);
  const row = shared
    ? h("button", { class: "row", type: "button", id: "vault-members", onclick: () => (close(), membersSheet(v.id)) }, icon("person_add", 22, "accent"),
        h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Membres", "Members")), h("span", { class: "row-sub" }, `${shared.members.length} · ${roleName(shared.role)}`)), icon("chevron_right", 18, "chev"))
    : h("button", { class: "row", type: "button", id: "vault-share", onclick: () => (close(), shareVaultSheet(v.id)) }, icon("share", 22, "accent"),
        h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Partager ce coffre", "Share this vault"))));
  return [h("div", { class: "caps" }, t("Partage", "Sharing")), h("div", { class: "card list-card" }, row)];
}

/** Pick a contact and a role (ShareVaultSheet): a contact added by link gets Read only. */
function shareVaultSheet(vaultId: string, after?: () => void): void {
  const members = new Set(sharing.sharedVaults.find((x) => x.vaultId === vaultId)?.members.map((m) => m.accountId) ?? []);
  const contacts = sharing.contacts.filter((c) => c.state === "active" && !members.has(c.accountId));
  let chosen: ContactInfo | null = null;
  let role: Role = "read";
  const err = errorLine();
  const list = h("div", { class: "card list-card", id: "share-contacts" });
  const roles = h("div", { class: "segmented", id: "share-role" });
  const foot = h("p", { class: "footnote" });
  const draw = () => {
    list.replaceChildren(...(contacts.length ? contacts.map((c) => contactRow(c, undefined, chosen?.accountId === c.accountId ? icon("check", 20, "accent") : null))
      : [h("div", { class: "row static" }, h("span", { class: "row-text secondary" }, t("Aucun contact. Ajoute d'abord un contact dans Réglages > Contacts.", "No contacts. First add one in Settings > Contacts.")))]));
    for (const [i, el] of [...list.querySelectorAll(".contact-row")].entries()) {
      el.addEventListener("click", () => {
        chosen = contacts[i]!;
        if (chosen.level === "link") role = "read";
        draw();
      });
      (el as HTMLElement).style.cursor = "pointer";
    }
    const offered: Role[] = chosen?.level === "link" ? ["read"] : ["read", "write", "manage"];
    roles.replaceChildren(...offered.map((r) => h("button", { type: "button", class: r === role ? "on" : "", "data-role": r, onclick: () => ((role = r), draw()) }, roleName(r))));
    foot.textContent = chosen?.level === "link" ? t("Un contact non vérifié n'a que la lecture.", "A contact that is not verified only gets Read.") : "";
  };
  draw();
  const s = sheet(t("Ajouter un membre", "Add member"), {
    action: t("Partager", "Share"),
    onAction: async (sh) => {
      if (!chosen) return;
      const bar = sh.dialog.querySelector(".bar-text.bold") as HTMLButtonElement;
      bar.disabled = true;
      err.textContent = "";
      try {
        await call("add_vault_member", { vaultId, contact: chosen.accountId, role });
        sh.close();
        await afterSharing(after);
        toast(t("Invitation envoyée", "Invitation sent"));
      } catch (e) {
        err.textContent = sharingMessage(e);
      }
      bar.disabled = false;
    },
  });
  s.body.append(h("div", { class: "caps" }, "Contacts"), list, h("div", { class: "caps" }, t("Rôle", "Role")), roles, foot, err);
}

function membersSheet(vaultId: string): void {
  const s = sheet(t("Membres", "Members"), { cancel: "OK" });
  const draw = async () => {
    await loadSharing();
    const v = sharing.sharedVaults.find((x) => x.vaultId === vaultId);
    if (!v) {
      s.close();
      return;
    }
    const manages = v.role === "manage";
    const err = errorLine();
    const act = async (run: () => Promise<unknown>, close = false) => {
      err.textContent = "";
      try {
        await run();
        await refresh(ui.selected);
        if (close) s.close();
        else void draw();
      } catch (e) {
        err.textContent = sharingMessage(e);
      }
    };
    const rows = v.members.map((m) => {
      const me = !m.name;
      const name = me ? youName() : m.name;
      const sub = [roleName(m.role), m.owner ? t("Propriétaire", "Owner") : ""].filter(Boolean).join(" · ");
      const menuBtn = manages && !m.owner && !me
        ? h("button", { class: "icon-button member-menu", type: "button", title: t("Actions", "Actions"), "data-name": m.name }, icon("more_circle", 20, "accent"))
        : null;
      menuBtn?.addEventListener("click", () => menu(menuBtn, [
        ...(["read", "write", "manage"] as Role[]).filter((r) => r === "read" || m.level !== "link").map((r) => ({
          label: roleName(r) + (r === m.role ? " ✓" : ""), icon: "person_add" as IconName, action: () => void act(() => call("set_member_role", { vaultId, accountId: m.accountId, role: r })) })),
        "separator",
        { label: t("Retirer", "Remove"), icon: "remove_circle", destructive: true, action: () => removeMemberSheet(v, m, () => void draw()) },
      ]));
      return h("div", { class: "row static member-row", "data-name": name }, monogram(initials(name), me ? "#8E8E93" : "var(--accent)", 30, true),
        h("span", { class: "row-text" }, h("span", { class: "row-title" }, name), h("span", { class: "row-sub" }, sub),
          m.keysChanged ? h("span", { class: "row-sub orange-text" }, t("Ses clés ont changé", "Their keys changed")) : null),
        m.level === "link" && !me ? unverifiedBadge() : null, menuBtn);
    });
    const add = manages ? h("button", { class: "row", type: "button", id: "members-add", onclick: () => shareVaultSheet(vaultId, () => void draw()) }, icon("person_add", 22, "accent"),
      h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Ajouter un membre", "Add member")))) : null;
    const actions: Node[] = [];
    if (v.owner && v.members.length === 1) actions.push(h("button", { class: "row", type: "button", id: "vault-stop-sharing", onclick: () => void act(() => call("stop_sharing", { vaultId }), true) },
      h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Arrêter le partage", "Stop sharing")))));
    if (!v.owner) actions.push(h("button", { class: "row", type: "button", id: "vault-leave", onclick: () => confirmSheet(t(`Quitter le coffre « ${v.name} » ?`, `Leave the vault “${v.name}”?`), t("Quitter le coffre", "Leave vault"),
      () => void act(() => call("leave_shared_vault", { vaultId }), true)) }, h("span", { class: "row-text" }, h("span", { class: "row-title destructive" }, t("Quitter le coffre", "Leave vault")))));
    s.body.replaceChildren(...keep(
      h("div", { class: "card list-card", id: "members-list" }, ...rows, add),
      v.notConfirmed ? h("p", { class: "footnote" }, t(`Pas encore confirmé : ${v.notConfirmed}`, `Not confirmed yet: ${v.notConfirmed}`)) : null,
      v.identityPending ? h("p", { class: "footnote" }, icon("hourglass", 14), " ", t("Des clés changées attendent ta confirmation.", "Changed keys wait for your confirmation.")) : null,
      v.refused ? h("p", { class: "footnote red-text" }, t(`Le serveur refuse l'accès à ${v.name}.`, `The server refuses access to ${v.name}.`)) : null,
      v.full ? h("p", { class: "footnote red-text" }, t("Stockage du coffre partagé plein", "Shared vault storage full")) : null,
      actions.length ? h("div", { class: "card list-card spaced" }, ...actions) : null,
      err));
  };
  void draw();
}

function removeMemberSheet(v: SharedVaultInfo, m: MemberInfo, after: () => void): void {
  const err = errorLine();
  const s = sheet(t("Retirer", "Remove"), { cancel: t("Annuler", "Cancel") });
  const removeBtn = h("button", { class: "row", type: "button", id: "member-remove-confirm" }, h("span", { class: "row-text" }, h("span", { class: "row-title destructive" }, t("Retirer", "Remove"))));
  removeBtn.addEventListener("click", async () => {
    removeBtn.disabled = true;
    try {
      const seen = await call<number>("remove_member", { vaultId: v.vaultId, accountId: m.accountId });
      await refresh(ui.selected);
      after();
      const change = h("button", { class: "row", type: "button", id: "removal-change", onclick: () => {
        s.close();
        closeAllSheets();
        go({ kind: "list", filter: { kind: "ids", ids: sharing.seenByFormerMembers }, title: t("Vus par un ancien membre", "Seen by a former member") });
      } }, h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Changer les mots de passe", "Change passwords"))));
      s.body.replaceChildren(
        h("div", { class: "card pad" }, h("p", { id: "removal-prompt" }, t(`${m.name} ne verra plus rien de nouveau dans ${v.name}. Il a pu garder ce qu'il a déjà vu : ${seen} mots de passe. Les changer ?`,
          `${m.name} won't see anything new in ${v.name}. They may have kept what they already saw: ${seen} passwords. Change them?`))),
        h("div", { class: "card list-card" }, change, h("button", { class: "row", type: "button", onclick: () => s.close() }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Plus tard", "Later"))))));
      await loadSharing();
    } catch (e) {
      err.textContent = sharingMessage(e);
      removeBtn.disabled = false;
    }
  });
  s.body.append(h("div", { class: "card pad" }, h("p", {}, t(`Retirer ${m.name} du coffre ?`, `Remove ${m.name} from the vault?`))),
    h("p", { class: "footnote" }, t("Le coffre reçoit une nouvelle clé. Ce que ce membre a déjà vu reste vu.", "The vault gets a new key. What this member already saw stays seen.")),
    h("div", { class: "card list-card" }, removeBtn), err);
}

function closeAllSheets(): void {
  for (const d of [...document.querySelectorAll("dialog[open]")]) {
    (d as HTMLDialogElement).close();
    d.remove();
  }
}

/** "Envoyer à un contact": a copy of the item, kept until the date picked (30 days at most). */
function sendItemSheet(item: Item): void {
  const contacts = sharing.contacts.filter((c) => c.state === "active");
  let chosen: ContactInfo | null = null;
  let days = 7;
  const err = errorLine();
  const list = h("div", { class: "card list-card", id: "send-contacts" });
  const span = h("div", { class: "segmented", id: "send-days" });
  const draw = () => {
    list.replaceChildren(...(contacts.length ? contacts.map((c) => contactRow(c, undefined, chosen?.accountId === c.accountId ? icon("check", 20, "accent") : null))
      : [h("div", { class: "row static" }, h("span", { class: "row-text secondary" }, t("Aucun contact. Ajoute d'abord un contact dans Réglages > Contacts.", "No contacts. First add one in Settings > Contacts.")))]));
    for (const [i, el] of [...list.querySelectorAll(".contact-row")].entries()) {
      el.addEventListener("click", () => ((chosen = contacts[i]!), draw()));
      (el as HTMLElement).style.cursor = "pointer";
    }
    span.replaceChildren(...[1, 7, 30].map((d) => h("button", { type: "button", class: d === days ? "on" : "", onclick: () => ((days = d), draw()) },
      d === 1 ? t("1 jour", "1 day") : t(`${d} jours`, `${d} days`))));
  };
  draw();
  const s = sheet(t("Envoyer une copie", "Send a copy"), {
    action: t("Envoyer", "Send"),
    onAction: async (sh) => {
      if (!chosen) return;
      try {
        await call("send_item", { vaultId: item.vaultId, itemId: item.id, to: chosen.accountId, days });
        sh.close();
        toast(t(`Copie envoyée à ${chosen.name}`, `Copy sent to ${chosen.name}`));
      } catch (e) {
        err.textContent = sharingMessage(e);
      }
    },
  });
  s.body.append(h("p", { class: "secondary" }, t(`Une copie de « ${item.title} » : ton contact la garde dans un de ses coffres ou la refuse.`, `A copy of “${item.title}”: your contact keeps it in one of their vaults or declines it.`)),
    h("div", { class: "caps" }, "Contacts"), list, h("div", { class: "caps" }, t("Disponible pendant", "Available for")), span, err);
}

// ---- Settings > Famille (FamilyView) ---------------------------------------------------------------------

async function familyPage(head: HTMLElement, redraw: () => void): Promise<Node[]> {
  await loadSharing();
  const s = sharing;
  const err = errorLine();
  const act = async (run: () => Promise<unknown>) => {
    err.textContent = "";
    try {
      await run();
      await refresh(ui.selected);
      redraw();
    } catch (e) {
      err.textContent = sharingMessage(e);
    }
  };
  const invites = s.familyInvites.length
    ? h("div", { class: "card list-card spaced" }, ...s.familyInvites.map((i) => h("button", { class: "row", type: "button", id: "family-join", onclick: () => void act(() => call("accept_family_invite", { inviteId: i.id })) },
        icon("person_add", 22, "accent"), h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t(`Rejoindre la famille de ${i.fromName}`, `Join ${i.fromName}'s family`)), h("span", { class: "row-sub" }, familyRoleName(i.role))))))
    : null;
  const f = s.family;
  if (!f) {
    return keep(head,
      h("div", { class: "card pad notyet" }, settingsArt("family", 44), h("p", { class: "secondary" }, t("Aucune famille pour l'instant. Une famille partage un coffre et peut aider à récupérer un compte.", "No family yet. A family shares a vault and can help recover an account."))),
      h("div", { class: "card list-card spaced" }, h("button", { class: "row", type: "button", id: "family-create", disabled: !s.zonesReady, onclick: (ev: Event) => {
        const b = ev.currentTarget as HTMLButtonElement;
        b.disabled = true;
        b.querySelector(".row-title")!.textContent = t("Création de la famille…", "Creating the family…");
        void act(() => call("create_family", { vaultName: t("Famille", "Family") }));
      } },
        icon("add", 22, "accent"), h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Créer une famille", "Create a family"))))),
      s.zonesReady ? null : h("p", { class: "footnote" }, sharingMessage({ code: "NoSync" })),
      invites, err);
  }
  const members: HTMLElement[] = f.members.map((m) => {
    const me = !m.name;
    const name = me ? youName() : m.name;
    const more = f.iAmOrganizer && !me ? h("button", { class: "icon-button family-menu", type: "button", "data-name": m.name, title: t("Actions", "Actions") }, icon("more_circle", 20, "accent")) : null;
    more?.addEventListener("click", () => menu(more, [
      m.role === "organizer"
        ? { label: t("Membre", "Member"), icon: "person_add", action: () => void act(() => call("set_family_role", { accountId: m.accountId, role: "member" })) }
        : { label: t("Organisateur", "Organizer"), icon: "person_add", action: () => void act(() => call("set_family_role", { accountId: m.accountId, role: "organizer" })) },
      "separator",
      { label: t("Retirer", "Remove"), icon: "remove_circle", destructive: true, action: () => confirmSheet(t(`Retirer ${m.name} de la famille ?`, `Remove ${m.name} from the family?`), t("Retirer", "Remove"),
        () => void act(() => call("remove_from_family", { accountId: m.accountId }))) },
    ]));
    return h("div", { class: "row static family-member", "data-name": name }, monogram(initials(name), me ? "#8E8E93" : "var(--accent)", 30, true),
      h("span", { class: "row-text" }, h("span", { class: "row-title" }, name)), h("span", { class: "secondary" }, familyRoleName(m.role)), more);
  });
  if (f.iAmOrganizer) members.push(h("button", { class: "row", type: "button", id: "family-invite", onclick: () => familyInviteSheet(redraw) }, icon("person_add", 22, "accent"),
    h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Inviter dans la famille", "Invite to family")))));
  const familyVaults = ui.vaults.filter((v) => f.vaults.includes(v.id));
  const personal = ui.vaults.filter((v) => !v.sharedRole);
  const vaultRows: Node[] = familyVaults.map((v) => h("div", { class: "row static family-vault" }, monogram(v.name.slice(0, 1).toUpperCase(), vaultColor(v.color), 28), h("span", { class: "row-text" }, h("span", { class: "row-title" }, v.name))));
  if (personal.length) {
    const add = h("button", { class: "row", type: "button", id: "family-add-vault" }, icon("add", 22, "accent"), h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Donner un coffre à la famille", "Give a vault to the family"))));
    add.addEventListener("click", () => menu(add, personal.map((v) => ({ label: v.name, icon: "folder" as IconName, action: () => void act(() => call("add_family_vault", { vaultId: v.id })) }))));
    vaultRows.push(add);
  }
  const recovery: Node[] = [];
  const e = s.recoveryEnrollment;
  if (e) {
    recovery.push(h("div", { class: "row static", id: "recovery-enrolled" }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Organisateur choisi", "Chosen organizer"))), h("span", { class: "secondary" }, e.organizerName)));
    recovery.push(h("button", { class: "row", type: "button", onclick: () => passwordSheet(t("Désactiver la récupération", "Turn off recovery"), t("Désactiver", "Turn off"), (password) => call("disable_recovery", { password }), redraw) },
      h("span", { class: "row-text" }, h("span", { class: "row-title destructive" }, t("Désactiver la récupération", "Turn off recovery")))));
  } else if (!f.iAmOrganizer) {
    recovery.push(h("button", { class: "row", type: "button", id: "recovery-enroll", onclick: () => enrollSheet(f, redraw) }, h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Récupération par un organisateur", "Recovery by an organizer"))), icon("chevron_right", 18, "chev")));
  }
  const helpers = s.helpers.map((hp) => h("button", { class: "row helper-row", type: "button", "data-name": hp.name, onclick: () => helperSheet(hp, redraw) },
    h("span", { class: "row-text" }, h("span", { class: "row-title" }, t(`${hp.name} t'a choisi pour l'aider à récupérer son compte.`, `${hp.name} chose you to help recover their account.`))), icon("chevron_right", 18, "chev")));
  const sole = f.members.filter((m) => m.role === "organizer").length === 1 && f.iAmOrganizer;
  const leave = sole && f.members.length > 1 ? null : h("button", { class: "row", type: "button", id: "family-leave", onclick: () => confirmSheet(t("Quitter la famille ?", "Leave the family?"), t("Quitter", "Leave"), () => void act(() => call("leave_family"))) },
    h("span", { class: "row-text" }, h("span", { class: "row-title destructive" }, t("Quitter la famille", "Leave the family"))));
  return keep(head,
    f.needsSecondOrganizer ? h("div", { class: "banner warn", id: "family-second" }, h("div", { class: "banner-line" }, icon("warning", 20, "orange"), h("span", {}, t("Ajoute un deuxième organisateur pour que la famille ne dépende pas d'une seule personne.", "Add a second organizer so the family does not depend on one person.")))) : null,
    h("div", { class: "caps" }, t("Membres", "Members")),
    h("div", { class: "card list-card", id: "family-members" }, ...members),
    vaultRows.length ? h("div", { class: "caps" }, t("Coffres", "Vaults")) : null,
    vaultRows.length ? h("div", { class: "card list-card" }, ...vaultRows) : null,
    recovery.length ? h("div", { class: "caps" }, t("Récupération du compte", "Account recovery")) : null,
    recovery.length ? h("div", { class: "card list-card" }, ...recovery) : null,
    helpers.length ? h("div", { class: "card list-card spaced" }, ...helpers) : null,
    invites,
    leave ? h("div", { class: "card list-card spaced" }, leave) : null,
    err);
}

function familyInviteSheet(after: () => void): void {
  const s = sheet(t("Inviter dans la famille", "Invite to family"));
  const err = errorLine();
  const members = new Set(sharing.family?.members.map((m) => m.accountId) ?? []);
  const verified = sharing.contacts.filter((c) => c.state === "active" && !members.has(c.accountId));
  const invite = async (c: ContactInfo, role: string) => {
    try {
      await call("invite_to_family", { contact: c.accountId, role });
      s.close();
      toast(t("Invitation envoyée", "Invitation sent"));
      after();
    } catch (e) {
      err.textContent = sharingMessage(e);
    }
  };
  s.body.append(h("div", { class: "card list-card", id: "family-invite-list" }, ...(verified.length ? verified.map((c) => {
    const row = contactRow(c);
    row.append(h("button", { class: "bar-text family-as-member", type: "button", onclick: () => void invite(c, "member") }, t("Membre", "Member")),
      h("button", { class: "bar-text", type: "button", disabled: c.level === "link", onclick: () => void invite(c, "organizer") }, t("Organisateur", "Organizer")));
    return row;
  }) : [h("div", { class: "row static" }, h("span", { class: "row-text secondary" }, t("Aucun contact. Ajoute d'abord un contact dans Réglages > Contacts.", "No contacts. First add one in Settings > Contacts.")))])), err);
}

/** A sheet that asks the master password, then runs `run`. */
function passwordSheet(title: string, action: string, run: (password: string) => Promise<unknown>, after: () => void, intro?: Node): void {
  const pw = secretInput("share-pw", t("Mot de passe principal", "Master password"), "current-password");
  const err = errorLine();
  const s = sheet(title, { action, onAction: async (sh) => {
    try {
      await run(pw.input.value);
      pw.input.value = "";
      sh.close();
      after();
    } catch (e) {
      err.textContent = sharingMessage(e);
    }
  } });
  s.body.append(...keep(intro, pw.box, err));
  queueMicrotask(() => pw.input.focus());
}

/** RecoveryEnrollView: the organizer, the delay, the risk sentence confirmed, then the master password. */
function enrollSheet(f: FamilyInfo, after: () => void): void {
  const organizers = f.members.filter((m) => m.role === "organizer" && m.name);
  let organizer = organizers[0]?.accountId ?? "";
  let days = 3;
  const err = errorLine();
  const pick = h("select", { id: "enroll-organizer" }, ...organizers.map((o) => h("option", { value: o.accountId }, o.name)));
  const daysLabel = h("span", { class: "row-title" });
  const minus = h("button", { class: "icon-button", type: "button", "aria-label": "-" }, "−");
  const plus = h("button", { class: "icon-button", type: "button", "aria-label": "+" }, "+");
  const risk = h("p", { id: "enroll-risk" });
  const understood = h("input", { type: "checkbox", class: "switch", id: "enroll-understood" });
  const pw = secretInput("enroll-pw", t("Mot de passe principal", "Master password"), "current-password");
  const pwBox = h("div", {}, pw.box);
  const draw = () => {
    daysLabel.textContent = t(`Délai : ${days} jours`, `Delay: ${days} days`);
    const name = organizers.find((o) => o.accountId === organizer)?.name ?? "";
    risk.textContent = t(`${name} et quelqu'un qui aurait ton Emergency Kit pourraient ensemble ouvrir ton coffre.`, `${name} and someone with your Emergency Kit could open your vault together.`);
    pwBox.hidden = !understood.checked;
  };
  pick.addEventListener("change", () => ((organizer = pick.value), draw()));
  minus.addEventListener("click", () => ((days = Math.max(1, days - 1)), draw()));
  plus.addEventListener("click", () => ((days = Math.min(7, days + 1)), draw()));
  understood.addEventListener("change", draw);
  const s = sheet(t("Récupération par un organisateur", "Recovery by an organizer"), {
    action: t("Activer", "Turn on"),
    onAction: async (sh) => {
      if (!understood.checked || !pw.input.value || !organizer) return;
      try {
        await call("enroll_recovery", { organizer, days, password: pw.input.value });
        pw.input.value = "";
        sh.close();
        after();
      } catch (e) {
        err.textContent = sharingMessage(e);
      }
    },
  });
  s.body.append(
    h("div", { class: "card list-card" },
      h("label", { class: "row static" }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, t("Organisateur", "Organizer"))), pick),
      h("div", { class: "row static" }, h("span", { class: "row-text" }, daysLabel), minus, plus)),
    h("div", { class: "card pad spaced" }, risk, h("label", { class: "toggle-row", for: "enroll-understood" }, h("span", { class: "row-text" }, t("J'ai compris", "I understand")), understood)),
    pwBox, err);
  draw();
}

/** RecoveryHelperView: the organizer asks, the delay runs, then the handover in person. */
function helperSheet(hp: HelperInfo, after: () => void): void {
  const s = sheet(t("Récupération du compte", "Account recovery"), { cancel: "OK" });
  const draw = async () => {
    const st = await call<RecoveryStatus>("recovery_status", { member: hp.member }).catch(() => ({ kind: "notEnrolled" }) as RecoveryStatus);
    const head = h("div", { class: "card pad" }, h("p", {}, t(`${hp.name} t'a choisi pour l'aider à récupérer son compte.`, `${hp.name} chose you to help recover their account.`)));
    const err = errorLine();
    let part: Node[];
    if (st.kind === "waiting") {
      part = [h("div", { class: "card pad", id: "helper-waiting" }, h("p", {}, t(`Possible à partir du ${longDate(st.releaseAfter)} à ${shortTime(st.releaseAfter)}.`, `Possible from ${longDate(st.releaseAfter)} at ${shortTime(st.releaseAfter)}.`)))];
    } else if (st.kind === "ready") {
      part = [h("p", { class: "footnote" }, t("Le délai est passé. Scanne le code affiché sur le nouvel appareil du membre, en face à face.", "The delay is over. Scan the code on the member's new device, face to face.")),
        h("p", { class: "footnote" }, t("La remise en face à face se fait depuis un iPhone : la version Windows ne lit pas encore les codes des autres appareils.", "The face-to-face handover happens from an iPhone: the Windows version can't read other devices' codes yet."))];
    } else if (st.kind === "cancelled") {
      part = [h("div", { class: "card pad" }, h("p", { class: "secondary", id: "helper-cancelled" }, t("Le membre a annulé la récupération.", "The member cancelled the recovery.")))];
    } else {
      const pw = secretInput("helper-pw", t("Mot de passe principal", "Master password"), "current-password");
      const req = h("button", { class: "row", type: "button", id: "helper-request" }, h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Demander la récupération", "Request recovery"))));
      req.addEventListener("click", async () => {
        try {
          await call("request_recovery", { member: hp.member, password: pw.input.value });
          pw.input.value = "";
          after();
          void draw();
        } catch (e) {
          err.textContent = sharingMessage(e);
        }
      });
      part = [pw.box, h("div", { class: "card list-card spaced" }, req),
        h("p", { class: "footnote" }, t("Le membre est prévenu sur tous ses appareils et peut annuler pendant le délai.", "The member is told on all their devices and can cancel during the delay."))];
    }
    s.body.replaceChildren(head, ...part, err);
  };
  void draw();
}

// ---- keyboard and start ------------------------------------------------------------------------------

// The Mac app's shortcuts, Ctrl for Cmd: N new item, Shift+I import, F search,
// E edit, S save (in the editor), Delete trash, L lock, comma settings,
// Enter import (in the import sheet).
document.addEventListener("keydown", (e) => {
  if (!e.ctrlKey || e.altKey || !document.querySelector(".shell")) return;
  const dialogs = document.querySelectorAll("dialog[open]");
  const top = dialogs[dialogs.length - 1] as HTMLDialogElement | undefined;
  const key = e.key.toLowerCase();
  if (top) {
    const action = top.querySelector(".sheet-bar .bar-text.bold") as HTMLButtonElement | null;
    const saving = key === "s" && top.classList.contains("editor");
    const importing = e.key === "Enter" && top.classList.contains("import-sheet");
    if ((saving || importing) && action && !action.disabled && !action.hidden) {
      e.preventDefault();
      action.click();
    }
    return;
  }
  const selected = ui.page.kind === "list" ? ui.items.find((i) => i.id === ui.selected) : undefined;
  if (key === "n" && !e.shiftKey) {
    e.preventDefault();
    newItem();
  } else if (key === "i" && e.shiftKey) {
    e.preventDefault();
    importSheet();
  } else if (key === "l") {
    e.preventDefault();
    void lockNow();
  } else if (key === "f") {
    e.preventDefault();
    if (ui.page.kind !== "list") go({ kind: "list", filter: { kind: "all" }, title: t("Tous les éléments", "All Items") });
    (document.querySelector(".search-input") as HTMLInputElement | null)?.focus();
  } else if (key === ",") {
    e.preventDefault();
    openSettings();
  } else if (key === "e" && selected && !selected.trashed) {
    e.preventDefault();
    void call<Item>("item", { vaultId: selected.vaultId, itemId: selected.id }).then((it) => editItem(it, false)).catch((x) => toast(message(x)));
  } else if ((e.key === "Delete" || e.key === "Backspace") && selected && !selected.trashed && !(document.activeElement instanceof HTMLInputElement)) {
    e.preventDefault();
    confirmSheet(t(`Mettre « ${selected.title} » dans Supprimés récemment ?`, `Move “${selected.title}” to Recently Deleted?`), t("Supprimer", "Delete"), async () => {
      try {
        await call("trash_item", { vaultId: selected.vaultId, itemId: selected.id });
        await refresh(null);
      } catch (x) {
        toast(message(x));
      }
    });
  }
});

void listen("locked", () => {
  resetSession();
  void route();
});

void route();
