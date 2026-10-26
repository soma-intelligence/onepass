// Toolbar popup (spec 8.8, Extension mockup): pairing, locked and missing
// host states, suggestions for the active tab, search, item detail with
// reveal and TOTP, "Remplir", and the generator with its history.
import { ext } from "../shared/browser";
import type { GeneratorEntry, GeneratorKind, PopupStatus, Summary } from "../shared/ui";
import {
  type Send,
  type Timers,
  call,
  errorText,
  h,
  icon,
  mark,
  mount,
  realTimers,
  srOnly,
  tile,
} from "./components";
import {
  parseEmpty,
  parseFilled,
  parseGenerated,
  parseHistory,
  parseItem,
  parseItems,
  parseLocked,
  parseSas,
  parseStatus,
  parseSuggestions,
  parseTotp,
  parseValue,
} from "./parse";

export interface PopupDeps {
  send: Send;
  timers?: Timers;
  /** Clipboard write (navigator.clipboard in the extension). */
  copy?: (text: string) => Promise<void>;
}

export interface PopupHandle {
  ready: Promise<void>;
  /** Resolves when pending renders triggered by the last action are done (tests). */
  settled(): Promise<void>;
}

const MASK = "••••••••••••";
const TOAST_MS = 1600;
const SEARCH_DEBOUNCE_MS = 150;

export const GENERATOR_TYPES: readonly { kind: GeneratorKind; label: string; help: string }[] = [
  { kind: "smart", label: "Intelligent", help: "Un mot de passe fort, lisible et facile à saisir." },
  { kind: "random", label: "Aléatoire", help: "Caractères tirés au hasard par le générateur sécurisé du système." },
  { kind: "memorable", label: "Mémorisable", help: "Des mots faciles à taper, difficiles à deviner." },
  { kind: "pin", label: "Code PIN", help: "Des chiffres seulement, pour les codes et les cadenas." },
];

/** "703083" -> "703 083". */
export function formatCode(code: string): string {
  return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
}

function initials(account: string): string {
  const name = account.split("@")[0] ?? account;
  const parts = name.split(/[._\-\s]+/).filter((p) => p !== "");
  const letters = parts.length >= 2 ? (parts[0]?.charAt(0) ?? "") + (parts[1]?.charAt(0) ?? "") : name.slice(0, 2);
  return letters.toUpperCase() || "OP";
}

export function mountPopup(root: HTMLElement, deps: PopupDeps): PopupHandle {
  const timers = deps.timers ?? realTimers;
  const container = h("div", { class: "pp" });
  mount(root, container);
  let pending: Promise<unknown> = Promise.resolve();
  const track = <T>(p: Promise<T>): Promise<T> => {
    pending = pending.then(() => p).catch(() => undefined);
    return p;
  };

  // ---- toast ----
  let toastEl: HTMLElement | null = null;
  let toastTimer: unknown = null;
  const toast = (text: string) => {
    toastEl?.remove();
    if (toastTimer !== null) timers.clearTimeout(toastTimer);
    const el = h("div", { class: "toast", attrs: { role: "status" } }, text);
    toastEl = el;
    container.append(el);
    toastTimer = timers.setTimeout(() => el.remove(), TOAST_MS);
  };

  const button = (label: string, cls: string, fn: () => void, attrs: Record<string, string> = {}) =>
    h("button", { class: cls, attrs: { type: "button", ...attrs }, on: { click: () => fn() } }, label);

  // ---- full-page states ----
  const center = (...children: (Node | null)[]) => mount(container, h("div", { class: "center" }, ...children));

  function renderUnpaired(err?: string): void {
    center(
      mark("m"),
      h("h1", null, "OnePass n'est pas appairé"),
      h("p", null, "Relie cette extension à l'app OnePass de cet ordinateur pour remplir tes logins."),
      button("Appairer avec OnePass", "btn btn-primary", () => void track(startPairing())),
      err ? h("p", { class: "error-line", attrs: { role: "alert" } }, err) : null,
    );
  }

  async function startPairing(): Promise<void> {
    center(mark("m"), h("h1", null, "Appairage…"), h("p", null, "Ouvre l'app OnePass si elle ne l'est pas."));
    const r = await call(deps.send, { type: "popup_pair_start" }, parseSas);
    if (!r.ok) {
      if (r.code === "host_missing") renderHostMissing();
      else renderUnpaired(errorText(r.code));
      return;
    }
    center(
      h("h1", null, "Compare les codes"),
      h("p", null, "Le même code doit s'afficher dans l'app OnePass."),
      h("div", { class: "sas", attrs: { "aria-label": "Code d'appairage" } }, r.value.sas),
      h(
        "div",
        { class: "actions" },
        button("Annuler", "btn", () => {
          void call(deps.send, { type: "popup_pair_cancel" }, parseEmpty);
          renderUnpaired();
        }),
        button("Les codes sont identiques", "btn btn-primary", () => void track(approve())),
      ),
    );
  }

  async function approve(): Promise<void> {
    const r = await call(deps.send, { type: "popup_pair_approve" }, parseEmpty);
    if (!r.ok) {
      renderUnpaired(errorText(r.code));
      return;
    }
    await load();
  }

  function renderLocked(): void {
    center(
      mark("m"),
      h("h1", null, "OnePass est verrouillé"),
      button("Déverrouiller dans OnePass", "btn btn-primary", () =>
        void track(
          call(deps.send, { type: "popup_unlock" }, parseLocked).then((r) => {
            if (r.ok && !r.value.locked) return load();
            if (!r.ok) toast(errorText(r.code));
            return undefined;
          }),
        ),
      ),
    );
  }

  function renderHostMissing(): void {
    center(
      mark("m"),
      h("h1", null, "App OnePass introuvable"),
      h("p", null, "Installe ou ouvre l'app OnePass sur cet ordinateur, puis réessaie."),
      button("Réessayer", "btn btn-primary", () => void track(load())),
    );
  }

  function renderError(code: string): void {
    center(mark("m"), h("h1", null, errorText(code)), button("Réessayer", "btn btn-primary", () => void track(load())));
  }

  // ---- main view ----
  let status: PopupStatus | null = null;
  let domain: string | null = null;
  let suggestions: Summary[] = [];
  let results: Summary[] | null = null;
  let selected: string | null = null;
  let view: "detail" | "gen" | "none" = "none";
  let totpTimer: unknown = null;
  let searchTimer: unknown = null;
  const side = h("div", { class: "pp-side" });
  const main = h("div", { class: "pp-main" });

  const stopTotp = () => {
    if (totpTimer !== null) timers.clearInterval(totpTimer);
    totpTimer = null;
  };

  function renderMain(): void {
    const input = h("input", {
      attrs: { type: "search", placeholder: "Rechercher dans OnePass", "aria-label": "Rechercher dans OnePass", maxlength: "256" },
    });
    input.addEventListener("input", () => {
      if (searchTimer !== null) timers.clearTimeout(searchTimer);
      const q = input.value;
      searchTimer = timers.setTimeout(() => void track(search(q)), SEARCH_DEBOUNCE_MS);
    });
    const genBtn = h(
      "button",
      {
        class: `btn-icon${view === "gen" ? " on" : ""}`,
        attrs: { type: "button", "aria-label": "Générateur de mot de passe" },
        on: { click: () => void track(openGenerator()) },
      },
      icon("key", 18),
    );
    mount(
      container,
      h(
        "div",
        { class: "pp-head" },
        h("span", { class: "account" }, h("span", { class: "avatar", attrs: { "aria-hidden": "true" } }, initials(status?.account ?? "")), status?.account ?? ""),
        h("label", { class: "search" }, icon("search", 14), input),
        genBtn,
      ),
      h("div", { class: "pp-body" }, side, main),
    );
    renderSide();
    if (view === "none") mount(main, h("div", { class: "center" }, h("p", null, "Choisis un élément ou ouvre le générateur.")));
  }

  function renderSide(): void {
    const list = h("div", { class: "pp-list", attrs: { role: "listbox", "aria-label": results ? "Résultats" : "Suggestions" } });
    const items = results ?? suggestions;
    for (const it of items) {
      list.append(
        h(
          "button",
          {
            class: "row",
            attrs: { type: "button", role: "option", "aria-selected": String(view === "detail" && selected === it.item_id) },
            on: { click: () => void track(openItem(it.item_id)) },
          },
          tile(it.icon_letter, it.icon_color, "m"),
          h("span", { class: "stack" }, h("span", { class: "t1" }, it.title), h("span", { class: "t2" }, it.subtitle)),
        ),
      );
    }
    let title: string;
    let empty: string | null = null;
    if (results) {
      title = "Résultats";
      if (items.length === 0) empty = "Aucun résultat";
    } else if (domain) {
      title = `Suggestions pour ${domain}`;
      if (items.length === 0) empty = `Aucun login pour ${domain}`;
    } else {
      title = "Suggestions";
      empty = "Cette page n'est pas un site HTTPS.";
    }
    mount(
      side,
      h("div", { class: "pp-side-title" }, icon("star", 14), title),
      list,
      empty ? h("p", { class: "pp-empty" }, empty) : null,
      domain && !results
        ? h(
            "div",
            { class: "verified" },
            icon("shield", 16),
            h("span", null, `Domaine vérifié : ${domain}. Le remplissage ne marche que sur ce site exact.`),
          )
        : null,
    );
  }

  async function search(q: string): Promise<void> {
    if (q.trim() === "") {
      results = null;
      renderSide();
      return;
    }
    const r = await call(deps.send, { type: "popup_search", query: q }, parseItems);
    if (!r.ok) return handleError(r.code);
    results = r.value.items;
    renderSide();
  }

  function handleError(code: string): void {
    stopTotp();
    if (code === "locked") renderLocked();
    else if (code === "unpaired") renderUnpaired();
    else if (code === "host_missing") renderHostMissing();
    else toast(errorText(code));
  }

  const fieldRow = (label: string, value: Node | string, ...extra: (Node | null)[]) =>
    h(
      "div",
      { class: "field-row" },
      h("span", { class: "stack" }, h("span", { class: "cell-label" }, label), typeof value === "string" ? h("span", { class: "field-value" }, value) : value),
      ...extra,
    );

  async function openItem(itemId: string): Promise<void> {
    stopTotp();
    const r = await call(deps.send, { type: "popup_item", itemId }, parseItem);
    if (!r.ok) return handleError(r.code);
    selected = itemId;
    view = "detail";
    renderSide();
    const { summary: s, website } = r.value;
    const card = h("div", { class: "card" });
    card.append(fieldRow(s.kind === "login" ? "nom d’utilisateur" : s.kind === "card" ? "carte" : "identité", s.subtitle));
    if (s.kind === "login" && s.has_password) {
      const value = h("span", { class: "field-value mono pwd-value" }, MASK);
      let shown = false;
      const toggle: HTMLButtonElement = button("Afficher", "btn btn-link", () =>
        void track(
          (async () => {
            if (shown) {
              value.textContent = MASK;
              toggle.textContent = "Afficher";
              shown = false;
              return;
            }
            const v = await call(deps.send, { type: "popup_reveal", itemId }, parseValue);
            if (!v.ok) return handleError(v.code);
            value.textContent = v.value.value;
            toggle.textContent = "Masquer";
            shown = true;
          })(),
        ),
      );
      card.append(fieldRow("mot de passe", value, toggle));
    }
    if (s.kind === "login" && s.has_totp) {
      const code = h("span", { class: "field-value mono totp-code" }, "··· ···");
      const left = h("span", { class: "field-note totp-left" }, "");
      card.append(fieldRow("code à usage unique", code, left));
      let remaining = 0;
      const refresh = async () => {
        const t = await call(deps.send, { type: "popup_totp", itemId }, parseTotp);
        if (!t.ok) {
          stopTotp();
          return handleError(t.code);
        }
        code.textContent = formatCode(t.value.code);
        remaining = Math.max(0, Math.floor(t.value.remaining));
        left.textContent = `${remaining} s`;
      };
      await refresh();
      totpTimer = timers.setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) void track(refresh());
        else left.textContent = `${remaining} s`;
      }, 1000);
    }
    const fill = button("Remplir", "btn btn-primary", () =>
      void track(
        call(deps.send, { type: "popup_fill", itemId }, parseFilled).then((f) => {
          if (f.ok) toast(`Rempli sur ${f.value.domain}`);
          else handleError(f.code);
        }),
      ),
    );
    mount(
      main,
      h("div", { class: "pp-bar" }, h("span", { class: "pp-vault" }, s.vault_name), fill),
      h(
        "div",
        { class: "pp-detail" },
        h("div", { class: "pp-title" }, tile(s.icon_letter, s.icon_color, "l"), h("span", null, s.title)),
        card,
        website
          ? h("div", { class: "website" }, h("span", { class: "cell-label" }, "site web"), h("span", { class: "field-value" }, website))
          : null,
      ),
    );
  }

  // ---- generator ----
  let genKind: GeneratorKind = "smart";
  let genLength = 20;
  let genPassword = "";
  let genEntropy = 0;
  let historyOpen = false;

  async function generate(): Promise<void> {
    const msg =
      genKind === "random"
        ? ({ type: "popup_generate", kind: genKind, length: genLength, symbols: true } as const)
        : ({ type: "popup_generate", kind: genKind } as const);
    const r = await call(deps.send, msg, parseGenerated);
    if (!r.ok) return handleError(r.code);
    genPassword = r.value.password;
    genEntropy = r.value.entropy_bits;
    await renderGenerator();
  }

  async function openGenerator(): Promise<void> {
    stopTotp();
    view = "gen";
    selected = null;
    renderSide();
    container.querySelector(".pp-head .btn-icon")?.classList.add("on");
    await generate();
  }

  function colored(pw: string): HTMLElement {
    const out = h("div", { class: "gen-out", attrs: { "aria-label": "Mot de passe généré" } });
    for (const ch of pw) {
      const cls = /[0-9]/.test(ch) ? "ch-digit" : /\p{L}/u.test(ch) ? "" : "ch-symbol";
      out.append(cls ? h("span", { class: cls }, ch) : ch);
    }
    return out;
  }

  async function renderGenerator(): Promise<void> {
    const select = h("select", { class: "select", attrs: { "aria-label": "Type de mot de passe" } });
    for (const t of GENERATOR_TYPES) {
      const o = h("option", { attrs: { value: t.kind } }, t.label);
      if (t.kind === genKind) o.selected = true;
      select.append(o);
    }
    select.addEventListener("change", () => {
      const k = GENERATOR_TYPES.find((t) => t.kind === select.value)?.kind;
      if (k) {
        genKind = k;
        void track(generate());
      }
    });
    let lengthRow: HTMLElement | null = null;
    if (genKind === "random") {
      const range = h("input", { attrs: { type: "range", min: "8", max: "64", value: String(genLength), "aria-label": "Longueur" } });
      const shown = h("span", { class: "field-note" }, String(genLength));
      range.addEventListener("input", () => (shown.textContent = range.value));
      range.addEventListener("change", () => {
        genLength = Number(range.value);
        void track(generate());
      });
      lengthRow = h("label", { class: "gen-line" }, "Longueur", range, shown);
    }
    let historyList: HTMLElement | null = null;
    if (historyOpen) {
      const r = await call(deps.send, { type: "popup_history" }, parseHistory);
      const entries: GeneratorEntry[] = r.ok ? r.value.entries : [];
      historyList = h("ul", { class: "history-list" });
      for (const e of entries) historyList.append(h("li", null, e.password));
      if (entries.length === 0) historyList.append(h("li", null, "Aucun mot de passe généré"));
    }
    const strength = h("div", { class: "strength" }, h("div"));
    (strength.firstChild as HTMLElement).style.width = `${Math.min(100, Math.round((genEntropy / 100) * 100))}%`;
    mount(
      main,
      h(
        "div",
        { class: "gen-head" },
        h("h2", null, "Générateur de mot de passe"),
        h(
          "button",
          {
            class: "btn-icon",
            attrs: { type: "button", "aria-label": "Fermer le générateur" },
            on: {
              click: () => {
                view = "none";
                historyOpen = false;
                renderMain();
              },
            },
          },
          icon("close", 12),
        ),
      ),
      h(
        "div",
        { class: "gen" },
        h(
          "div",
          { class: "actions" },
          button("Copier", "btn", () =>
            void track(
              (deps.copy ?? ((t: string) => navigator.clipboard.writeText(t)))(genPassword).then(
                () => toast("Copié"),
                () => toast("Copie impossible"),
              ),
            ),
          ),
          h("span", { class: "stack" }),
          h(
            "button",
            { class: "btn-icon", attrs: { type: "button", "aria-label": "Générer un autre" }, on: { click: () => void track(generate()) } },
            icon("refresh", 16),
          ),
          button("Remplir", "btn btn-primary", () =>
            void track(
              call(deps.send, { type: "popup_fill_generated", password: genPassword }, parseFilled).then((f) => {
                if (f.ok) toast(`Rempli sur ${f.value.domain}`);
                else handleError(f.code);
              }),
            ),
          ),
        ),
        colored(genPassword),
        strength,
        srOnly(`Entropie : ${Math.round(genEntropy)} bits`),
        h("label", { class: "gen-line" }, "Type", select),
        lengthRow,
        h("p", { class: "gen-help" }, GENERATOR_TYPES.find((t) => t.kind === genKind)?.help ?? ""),
        h(
          "button",
          {
            class: "row history-toggle",
            attrs: { type: "button", "aria-expanded": String(historyOpen) },
            on: {
              click: () => {
                historyOpen = !historyOpen;
                void track(renderGenerator());
              },
            },
          },
          icon("history", 16),
          h("span", { class: "stack" }, "Historique du générateur"),
          icon("chevron", 10),
        ),
        historyList,
      ),
    );
  }

  // ---- load ----
  async function load(): Promise<void> {
    stopTotp();
    const r = await call(deps.send, { type: "popup_status" }, parseStatus);
    if (!r.ok) {
      if (r.code === "unpaired") renderUnpaired();
      else if (r.code === "host_missing") renderHostMissing();
      else if (r.code === "locked") renderLocked();
      else renderError(r.code);
      return;
    }
    status = r.value;
    if (status.locked) {
      renderLocked();
      return;
    }
    const s = await call(deps.send, { type: "popup_suggestions" }, parseSuggestions);
    if (!s.ok) return handleError(s.code);
    domain = s.value.domain;
    suggestions = s.value.items;
    results = null;
    view = "none";
    renderMain();
  }

  mount(container, h("div", { class: "center" }, mark("m")));
  // A pairing in progress dies with the popup.
  addEventListener("pagehide", () => void deps.send({ type: "popup_pair_cancel" }).catch(() => undefined));
  const ready = load();
  pending = ready;
  return {
    ready,
    settled: async () => {
      let p: Promise<unknown>;
      do {
        p = pending;
        await p;
        await new Promise((r) => setTimeout(r, 0));
      } while (p !== pending);
    },
  };
}

if (typeof document !== "undefined" && ext?.runtime?.id) {
  const root = document.getElementById("root");
  if (root) mountPopup(root, { send: (m) => ext.runtime.sendMessage(m) });
}
