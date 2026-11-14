// OnePass for Windows, laid out like the iPad and Mac app of the same
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
}
interface Vault {
  id: string;
  name: string;
  icon: string;
  color: string;
  itemCount: number;
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
}
interface Account {
  accountId: string;
  name: string;
  devices: { name: string; addedAt: number; thisDevice: boolean }[];
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
      return t("OnePass est verrouillé.", "OnePass is locked.");
    case "Validation":
      return t("Un champ n'est pas valide : ", "A field is not valid: ") + err.detail;
    case "NotFound":
      return t("Élément introuvable.", "Item not found.");
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
type Page = { kind: "home" } | { kind: "watchtower" } | { kind: "list"; filter: Filter; title: string };

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
};

const active = (): Summary[] => ui.items.filter((i) => !i.trashed && !i.archived);

async function reload(): Promise<void> {
  const [vaults, items, account] = await Promise.all([call<Vault[]>("vaults"), call<Summary[]>("items"), call<Account>("account")]);
  ui.vaults = vaults;
  ui.items = items;
  ui.name = account.name;
  ui.report = null;
  void loadReport();
}

let reportLoading = false;
async function loadReport(): Promise<void> {
  if (reportLoading) return;
  reportLoading = true;
  try {
    ui.report = await call<Report>("watchtower");
    if (ui.page.kind !== "list") renderMain();
    renderSidebar();
  } catch {
    /* the page says "Analyse…" */
  } finally {
    reportLoading = false;
  }
}

// ---- routing --------------------------------------------------------------------

async function route(): Promise<void> {
  let status: Status;
  try {
    status = await invoke<Status>("status");
    setFrench(status.language === "fr");
  } catch (e) {
    mount(problem(t("OnePass n'a pas pu lire son coffre.", "OnePass could not read its vault."), message(e)));
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
        t("C'est une anomalie d'intégrité : OnePass ne crée pas de compte par-dessus.", "That is an integrity fault: OnePass does not create an account over it.")));
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
    body: t("OnePass les retient pour toi et les remplit quand tu te connectes.", "OnePass remembers them for you and fills them in when you sign in.") },
  { icon: "lock", title: t("Toi seul as la clé", "Only you hold the key"),
    body: t("Pas de compte chez nous. Ton coffre est chiffré sur ton appareil, et même nous ne pouvons pas l'ouvrir.",
      "No account with us. Your vault is encrypted on your device, and even we can't open it.") },
  { icon: "shield_check", title: t("Sur tous tes appareils", "On all your devices"),
    body: t("Ton coffre reste sur ce PC ; la synchronisation avec tes autres appareils arrive sur Windows.",
      "Your vault stays on this PC; syncing with your other devices is coming to Windows.") },
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
  const notYet = () => toast(t("Pas encore disponible sur Windows : il faut d'abord la synchronisation entre appareils.", "Not available on Windows yet: it needs device sync first."));
  const option = (ic: IconName, color: string, title: string, detail: string, onclick: () => void) =>
    h("button", { class: "row", onclick }, tile(ic, color, 36), h("span", { class: "row-text" }, h("span", { class: "row-title" }, title), h("span", { class: "row-sub" }, detail)), icon("chevron_right", 18, "chev"));
  return h(
    "div",
    { class: "center" },
    h(
      "div",
      { class: "column" },
      appIcon(88),
      h("h1", { class: "big" }, t("Bienvenue dans OnePass", "Welcome to OnePass")),
      h("p", { class: "secondary lead" }, t("Comment veux-tu commencer ?", "How would you like to start?")),
      h(
        "div",
        { class: "card list-card" },
        option("vault_new", "var(--accent)", t("Créer un coffre", "Create a Vault"), t("Première fois sur OnePass", "First time on OnePass"), () => mount(create())),
        option("person_add", "var(--blue)", t("Ajouter cet appareil", "Add This Device"), t("Avec un QR code, depuis ton autre appareil", "With a QR code from your other device"), notYet),
        option("restore", "var(--orange)", t("Restaurer avec mon Emergency Kit", "Restore with My Emergency Kit"), t("Aucun autre appareil sous la main", "No other device at hand"), notYet),
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
          const created = await call<{ secretKey: string }>("create_account", { password: a.input.value });
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

function lockScreen(status: Status): HTMLElement {
  const { box, input } = secretInput("pw", t("Mot de passe maître", "Master Password"), "current-password");
  const err = h("div", { class: "error", role: "alert" });
  const go = h("button", { class: "go", type: "submit", title: t("Déverrouiller", "Unlock"), "aria-label": t("Déverrouiller", "Unlock") }, icon("arrow_forward", 20));
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
    h("h1", {}, t("Déverrouille OnePass", "Unlock OnePass")),
    h("div", { class: "account-capsule" }, monogram("1", "var(--accent)", 26, true), h("span", {}, t("Compte OnePass", "OnePass Account"))),
    box,
    err,
    h("p", { class: "footnote center-text" },
      t(`Verrouillage automatique après ${status.autoLockMinutes} min. Clés de l'appareil protégées par ${status.protection === "dpapi" ? "Windows (DPAPI)" : status.protection}.`,
        `Auto-lock after ${status.autoLockMinutes} min. Device keys protected by ${status.protection === "dpapi" ? "Windows (DPAPI)" : status.protection}.`)),
  );
  queueMicrotask(() => input.focus());
  return h("div", { class: "center" }, form);
}

async function lockNow(): Promise<void> {
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

const sidebarEl = h("nav", { class: "sidebar", "aria-label": "OnePass" });
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
  const account = h(
    "button",
    { class: "account", title: t("Compte", "Account") },
    monogram(initials(ui.name), "var(--accent)", 30),
    h("span", { class: "account-name" }, ui.name || t("Mon compte", "My account")),
    icon("chevron_down", 16, "accent"),
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
  sidebarEl.replaceChildren(
    h("div", { class: "sidebar-top" }, account, h("button", { class: "round", title: t("Nouvel élément", "New Item"), "aria-label": t("Nouvel élément", "New Item"), onclick: () => newItem() }, icon("add", 20))),
    h(
      "div",
      { class: "sidebar-scroll" },
      nav(t("Accueil", "Home"), tile("home_fill", "var(--accent)", 22), null, { kind: "home" }),
      nav(t("Tous les éléments", "All Items"), tile("grid", "var(--accent)", 22), live.length, { kind: "list", filter: { kind: "all" }, title: t("Tous les éléments", "All Items") }),
      nav(t("Favoris", "Favorites"), tile("star_fill", "var(--orange)", 22), live.filter((i) => i.favorite).length, { kind: "list", filter: { kind: "favorites" }, title: t("Favoris", "Favorites") }),
      nav("Watchtower", tile("watchtower", "#E14D3C", 22), score ?? null, { kind: "watchtower" }),
      h("h3", {}, t("Coffres", "Vaults")),
      ...ui.vaults
        .slice()
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((v) => nav(v.name, monogram(v.name.slice(0, 1).toUpperCase(), vaultColor(v.color), 22), live.filter((i) => i.vaultId === v.id).length, { kind: "list", filter: { kind: "vault", id: v.id }, title: v.name })),
      h("button", { class: "nav add", onclick: () => vaultEditor(null) }, icon("add", 18, "accent"), h("span", { class: "nav-label accent" }, t("Nouveau coffre", "New Vault"))),
      cats.length ? h("h3", {}, t("Catégories", "Categories")) : null,
      ...cats.map((c) => nav(c.plural, art(c.key, 22), live.filter((i) => i.itemType === c.key).length, { kind: "list", filter: { kind: "category", key: c.key }, title: c.plural })),
      tags.length ? h("h3", {}, "Tags") : null,
      ...tags.map((tag) => nav(tag, icon("tag", 20, "secondary"), live.filter((i) => i.tags.includes(tag)).length, { kind: "list", filter: { kind: "tag", tag }, title: tag })),
      h("div", { class: "sidebar-gap" }),
      nav(t("Archive", "Archive"), icon("archive", 20, "secondary"), ui.items.filter((i) => i.archived && !i.trashed).length, { kind: "list", filter: { kind: "archive" }, title: t("Archive", "Archive") }),
      nav(t("Supprimés récemment", "Recently Deleted"), icon("trash", 20, "secondary"), ui.items.filter((i) => i.trashed).length, { kind: "list", filter: { kind: "trash" }, title: t("Supprimés récemment", "Recently Deleted") }),
    ),
  );
}

function renderMain(): void {
  stopTimers();
  const p = ui.page;
  if (p.kind === "home") mainEl.replaceChildren(homePage());
  else if (p.kind === "watchtower") mainEl.replaceChildren(watchtowerPage());
  else {
    mainEl.replaceChildren(h("div", { class: "split" }, listPane(p), detailEl));
    void renderDetail();
  }
}

// ---- Accueil ------------------------------------------------------------------------------

function homePage(): HTMLElement {
  const live = active();
  const first = ui.name.split(/\s+/).find(Boolean);
  const title = first ? t(`Bonjour ${first}`, `Hi ${first}`) : t("Accueil", "Home");
  if (!live.length) {
    const fan = h("div", { class: "fan" }, ...["login", "creditCard", "identity", "secureNote"].map((k, i) => {
      const a = art(k, 64);
      a.style.transform = `rotate(${i * 8 - 12}deg)`;
      return a;
    }));
    return h(
      "div",
      { class: "page" },
      h("h1", { class: "large-title" }, title),
      h("div", { class: "empty-state" }, fan, h("h2", {}, t("Ton coffre est vide", "Your Vault Is Empty")),
        h("p", { class: "secondary" }, t("Mots de passe, cartes, identités, notes : tout ce que tu ranges ici est chiffré sur tes appareils.", "Passwords, cards, identities, notes: everything you keep here is encrypted on your devices.")),
        h("button", { class: "capsule prominent", onclick: () => newItem() }, t("Créer ton premier élément", "Create Your First Item"))),
    );
  }
  const homeTile = (label: string, ic: IconName, color: string, value: Node, page: Page) =>
    h("button", { class: "home-tile card", onclick: () => go(page) }, h("span", { class: "tile-top" }, tile(ic, color, 34), value), h("span", { class: "tile-label" }, label));
  const figure = (n: number | string, color?: string) => {
    const f = h("span", { class: "figure" }, String(n));
    if (color) f.style.color = color;
    return f;
  };
  const score = ui.report?.score;
  const fold = (key: string, label: string, ic: IconName, color: string, list: Summary[], empty: string) => {
    const open = !ui.folded.has(key);
    const head = h(
      "button",
      { class: "fold-head", "aria-expanded": String(open), onclick: () => (open ? ui.folded.add(key) : ui.folded.delete(key), renderMain()) },
      tile(ic, color, 32),
      h("span", { class: "row-text" }, h("span", { class: "row-title bold" }, label), list.length ? h("span", { class: "row-sub tertiary" }, countLabel(list.length)) : null),
      icon("chevron_down", 18, "accent" + (open ? "" : " folded")),
    );
    return h("div", { class: "card list-card" }, head, open ? (list.length ? h("div", {}, ...list.slice(0, 8).map((s) => itemRow(s, true))) : h("p", { class: "fold-empty" }, empty)) : null);
  };
  const byId = new Map(live.map((i) => [i.id, i]));
  const profile = live.filter((i) => i.itemType === "identity").sort((a, b) => a.title.localeCompare(b.title))[0];
  return h(
    "div",
    { class: "page" },
    h("h1", { class: "large-title" }, title),
    h(
      "div",
      { class: "tiles" },
      homeTile(t("Tous les éléments", "All Items"), "grid", "var(--accent)", figure(live.length), { kind: "list", filter: { kind: "all" }, title: t("Tous les éléments", "All Items") }),
      homeTile(t("Favoris", "Favorites"), "star_fill", "var(--orange)", figure(live.filter((i) => i.favorite).length), { kind: "list", filter: { kind: "favorites" }, title: t("Favoris", "Favorites") }),
      homeTile("Watchtower", "watchtower", "#E14D3C", score === undefined ? icon("chevron_right", 20, "tertiary") : figure(score, scoreColor(score)), { kind: "watchtower" }),
      homeTile(t("Archive", "Archive"), "archive", "#8E8E93", figure(ui.items.filter((i) => i.archived && !i.trashed).length), { kind: "list", filter: { kind: "archive" }, title: t("Archive", "Archive") }),
    ),
    h(
      "div",
      { class: "home-cards" },
      profile
        ? h("div", { class: "card list-card" }, h("button", { class: "row", onclick: () => openItem(profile) }, art("identity", 40),
            h("span", { class: "row-text" }, h("span", { class: "row-title bold" }, t("Profil", "Profile")), h("span", { class: "row-sub" }, profile.title)), icon("chevron_right", 18, "chev")))
        : null,
      fold("favorites", t("Favoris", "Favorites"), "star_fill", "var(--orange)", live.filter((i) => i.favorite).sort((a, b) => a.title.localeCompare(b.title)),
        t("Touche l'étoile d'un élément pour le retrouver ici.", "Tap an item's star to find it here.")),
      fold("recents", t("Récents", "Recents"), "history", "#8C8C8C", ui.recents.map((id) => byId.get(id)).filter((s): s is Summary => !!s),
        t("Les éléments ouverts apparaissent ici jusqu'au verrouillage.", "Items you open appear here until OnePass locks.")),
    ),
  );
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
    art(s.itemType, 36, s.favorite),
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
    h("div", { class: "pill" }, ...(item.trashed ? [more] : [star, h("button", { class: "bar-text", onclick: () => void editItem(item, false) }, t("Modifier", "Edit")), more])),
  );

  const vault = ui.vaults.find((v) => v.id === item.vaultId);
  const chips = h("div", { class: "chips" });
  if (vault) {
    const c = h("span", { class: "chip" }, vault.name);
    c.style.setProperty("--chip", vaultColor(vault.color));
    chips.append(c);
  }
  if (item.archived) chips.append(h("span", { class: "chip gray" }, t("Archivé", "Archived")));
  if (item.trashed) chips.append(h("span", { class: "chip red" }, t("Dans la corbeille", "In Trash")));

  const sections = item.sections.map((s) => ({ ...s, fields: s.fields.filter((f) => f.hasValue) })).filter((s) => s.fields.length);
  detailEl.replaceChildren(
    toolbar,
    h("div", { class: "detail-scroll" },
      h("header", { class: "item-head" }, art(item.itemType, 64),
        h("div", {}, h("h2", {}, item.title || t("Sans titre", "Untitled")), h("div", { class: "secondary" }, [cat.singular, sel.subtitle].filter(Boolean).join(" · ")))),
      chips,
      ...sections.flatMap((s) => [h("div", { class: "caps" }, sectionLabel(s, cat.singular)), h("div", { class: "card" }, ...s.fields.map((f) => fieldRow(f, args)))]),
      ...(item.urls.length
        ? [h("div", { class: "caps" }, t("Sites web", "Websites")),
           h("div", { class: "card" }, ...item.urls.map((u) => urlRow(u.label || t("site web", "website"), u.url)))]
        : []),
      item.notes ? h("div", { class: "caps" }, t("Notes", "Notes")) : null,
      item.notes ? h("div", { class: "card notes" }, item.notes) : null,
      item.tags.length ? h("div", { class: "caps" }, "Tags") : null,
      item.tags.length ? h("div", { class: "chips" }, ...item.tags.map((x) => h("span", { class: "chip" }, x))) : null,
      item.trashed ? null : attachmentsSection(item),
      h("div", { class: "meta" },
        h("div", {}, t("Modifié le ", "Modified ") + dateTime(item.updatedAt)),
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
  const size = 210;
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", `0 0 ${size} ${size}`);
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("class", "dial");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", t("Score de sécurité", "Security Score") + (score === undefined ? "" : ` ${score}/100, ${scoreLabel(score)}`));
  const c = size / 2;
  const r = c - 7;
  const pt = (deg: number, rad: number) => [c + rad * Math.cos((deg * Math.PI) / 180), c + rad * Math.sin((deg * Math.PI) / 180)] as const;
  const arc = (fraction: number) => {
    const end = 135 + 270 * fraction;
    const [x1, y1] = pt(135, r);
    const [x2, y2] = pt(end, r);
    return `M ${x1} ${y1} A ${r} ${r} 0 ${270 * fraction > 180 ? 1 : 0} 1 ${x2} ${y2}`;
  };
  const path = (d: string, cls: string, color?: string) => {
    const p = document.createElementNS(SVG, "path");
    p.setAttribute("d", d);
    p.setAttribute("class", cls);
    if (color) p.style.stroke = color;
    svg.append(p);
  };
  path(arc(1), "track");
  const color = score === undefined ? "var(--secondary)" : scoreColor(score);
  if (score) path(arc(Math.min(score, 99.9) / 100), "fill", color);
  const lit = score === undefined ? -1 : Math.round((score / 100) * 40);
  for (let i = 0; i <= 40; i++) {
    const deg = 135 + (270 * i) / 40;
    const [x1, y1] = pt(deg, c - 29);
    const [x2, y2] = pt(deg, c - 22);
    path(`M ${x1} ${y1} L ${x2} ${y2}`, i <= lit ? "tick lit" : "tick", i <= lit ? color : undefined);
  }
  const text = (s: string, y: number, cls: string, fill?: string) => {
    const el = document.createElementNS(SVG, "text");
    el.setAttribute("x", String(c));
    el.setAttribute("y", String(y));
    el.setAttribute("class", cls);
    el.setAttribute("text-anchor", "middle");
    if (fill) el.style.fill = fill;
    el.textContent = s;
    svg.append(el);
  };
  text(score === undefined ? "–" : String(score), c + 14, "dial-figure");
  text((score === undefined ? t("Analyse…", "Analyzing…") : scoreLabel(score)).toUpperCase(), c + 40, "dial-word", score === undefined ? undefined : color);
  return svg;
}

function unavailable(card: WatchCard, r: Report): string | null {
  switch (card.source) {
    case "breaches":
      return r.pwned === "checked" || r.pwned === "partial" ? null : t("Vérification des fuites désactivée.", "Breach check turned off.");
    case "sites":
      return r.sitesChecked ? null : t("Active « Vérifier les fuites » pour télécharger le catalogue des sites.", "Turn on “Check for breaches” to download the site catalog.");
    case "breachCatalog":
      return t("Active « Vérifier les fuites » pour télécharger le catalogue des sites piratés.", "Turn on “Check for breaches” to download the list of breached sites.");
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
    h("div", { class: "wt-hero" }, dial(r?.score),
      h("div", {},
        h("p", { class: "secondary lead" }, t("Watchtower repère les mots de passe à changer et les sites où tu peux renforcer la sécurité de tes comptes.",
          "Watchtower finds passwords to change and sites where you can make your accounts more secure.")),
        r ? h("p", { class: "tertiary" }, plural(r.itemsAnalyzed, t("1 élément analysé", "1 item analyzed"), t("%d éléments analysés", "%d items analyzed"))) : null)),
    strength,
    h("div", { class: "wt-grid" }, ...cards),
  );
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

async function settingsPage(key: string, redraw: () => void): Promise<Node[]> {
  const title = settingsPages().flat().find((p) => p.key === key)?.title ?? "";
  const head = h("h2", { class: "settings-title" }, title);
  const row = (label: string, value: string) => h("div", { class: "row static" }, h("span", { class: "row-text" }, h("span", { class: "row-title" }, label)), h("span", { class: "secondary" }, value));
  const note = (text: string) => [head, h("div", { class: "card pad notyet" }, settingsArt(key, 44), h("p", { class: "secondary" }, text))];
  switch (key) {
    case "general": {
      const status = await call<Status>("status");
      return [head, h("div", { class: "card list-card" }, row(t("Verrouillage automatique", "Auto-Lock"), t(`${status.autoLockMinutes} minutes`, `${status.autoLockMinutes} minutes`)),
        row(t("Langue", "Language"), t("Français (système)", "English (system)"))),
        h("p", { class: "footnote" }, t("OnePass se verrouille aussi quand la session Windows se verrouille.", "OnePass also locks when the Windows session locks."))];
    }
    case "security": {
      const status = await call<Status>("status");
      return [head, h("div", { class: "card list-card" },
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
        h("div", { class: "caps" }, t("Compte OnePass", "OnePass Account")),
        h("div", { class: "card list-card" }, row(t("Identifiant", "ID"), acc.accountId)),
        h("p", { class: "footnote" }, t("Cet identifiant est imprimé sur ton Emergency Kit.", "This ID is printed on your Emergency Kit."))];
    }
    case "devices": {
      const acc = await call<Account>("account");
      return [head, h("div", { class: "card list-card" }, ...acc.devices.map((d) => h("div", { class: "row static" }, tile("key", "#008CB3", 28),
        h("span", { class: "row-text" }, h("span", { class: "row-title" }, d.name + (d.thisDevice ? t(" (cet appareil)", " (this device)") : "")),
          h("span", { class: "row-sub" }, t("Ajouté le ", "Added ") + dateTime(d.addedAt)))))),
        h("p", { class: "footnote" }, t("Ajouter un autre appareil demande la synchronisation, qui arrive sur Windows.", "Adding another device needs sync, which is coming to Windows."))];
    }
    case "vaults":
      return [head, h("div", { class: "card list-card" },
        ...ui.vaults.map((v) => h("button", { class: "row", onclick: () => vaultEditor(v, redraw) }, monogram(v.name.slice(0, 1).toUpperCase(), vaultColor(v.color), 30),
          h("span", { class: "row-text" }, h("span", { class: "row-title" }, v.name), h("span", { class: "row-sub" }, countLabel(v.itemCount))), icon("chevron_right", 18, "chev"))),
        h("button", { class: "row", onclick: () => vaultEditor(null, redraw) }, icon("add", 22, "accent"), h("span", { class: "row-text" }, h("span", { class: "row-title accent" }, t("Nouveau coffre", "New Vault")))))];
    case "about":
      return [head, h("div", { class: "about" }, appIcon(80), h("div", { class: "bold big-text" }, "OnePass"), h("div", { class: "secondary" }, "Version 0.1.0")),
        h("div", { class: "card list-card" }, row(t("Licence", "License"), "AGPL-3.0"), row(t("Code source", "Source Code"), "github.com/soma-intelligence/onepass"),
          row(t("Icônes de l'interface", "Interface Icons"), "Material Symbols, Apache-2.0")),
        h("p", { class: "footnote" }, t("Chiffré de bout en bout. Ton coffre ne quitte pas ce PC sans ton mot de passe maître et ta Secret Key.", "End-to-end encrypted. Your vault never leaves this PC without your master password and Secret Key."))];
    case "autofill":
      return note(t("Le remplissage dans les navigateurs (extension et pont natif) arrive sur Windows. En attendant, copie une valeur depuis l'élément : elle est effacée du presse-papiers après 90 secondes.",
        "Filling in browsers (extension and native bridge) is coming to Windows. Meanwhile, copy a value from the item: it is cleared from the clipboard after 90 seconds."));
    case "sync":
      return note(t("Ton coffre reste sur ce PC. La synchronisation chiffrée avec tes autres appareils arrive sur Windows.", "Your vault stays on this PC. Encrypted sync with your other devices is coming to Windows."));
    case "contacts":
    case "family":
      return note(t("Le partage avec tes contacts et ta famille demande la synchronisation, qui arrive sur Windows.", "Sharing with your contacts and family needs sync, which is coming to Windows."));
    case "travel":
      return note(t("Travel Mode retire de l'appareil les coffres non sûrs pour un voyage. Il arrive sur Windows avec la synchronisation.", "Travel Mode removes the vaults not safe for travel from the device. It comes to Windows with sync."));
    case "crypto":
      return note(t("Les portefeuilles crypto se rangent déjà comme éléments. Le suivi des soldes arrive sur Windows.", "Crypto wallets can already be stored as items. Balance tracking is coming to Windows."));
    default:
      return note(t("Les agents (serveur MCP, agent SSH) demandent un canal de contrôle que la version Windows n'ouvre pas encore.", "Agents (MCP server, SSH agent) need a control channel the Windows version does not open yet."));
  }
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

// ---- keyboard and start ------------------------------------------------------------------------------

document.addEventListener("keydown", (e) => {
  if (!e.ctrlKey || !document.querySelector(".shell") || document.querySelector("dialog[open]")) return;
  if (e.key === "n") {
    e.preventDefault();
    newItem();
  } else if (e.key === "l") {
    e.preventDefault();
    void lockNow();
  } else if (e.key === "f") {
    e.preventDefault();
    if (ui.page.kind !== "list") go({ kind: "list", filter: { kind: "all" }, title: t("Tous les éléments", "All Items") });
    (document.querySelector(".search-input") as HTMLInputElement | null)?.focus();
  }
});

void listen("locked", () => {
  resetSession();
  void route();
});

void route();
