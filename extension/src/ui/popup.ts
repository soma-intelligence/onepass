// Toolbar popup (spec 8.8, Extension mockup, Mac app design language):
// pairing, locked and missing host states, suggestions for the active tab,
// search, item detail with copy buttons, reveal and a TOTP countdown ring,
// "Remplir", the generator with its history, and "Oublier cet appairage"
// (spec 6.4) from the main and locked views.
import { ext } from "../shared/browser";
import { tr } from "../shared/i18n";
import type { GeneratorEntry, GeneratorKind, PopupStatus, Summary } from "../shared/ui";
import {
  type Send,
  type Timers,
  call,
  errorText,
  h,
  icon,
  itemArt,
  mark,
  mount,
  realTimers,
  srOnly,
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
/** TOTP period drawn by the ring (the bridge sends the seconds left only). */
const TOTP_PERIOD = 30;
const SVG_NS = "http://www.w3.org/2000/svg";

export const GENERATOR_TYPES: readonly { kind: GeneratorKind; label: string; help: string }[] = [
  {
    kind: "smart",
    label: tr("Intelligent", "Smart"),
    help: tr("Un mot de passe fort, lisible et facile à saisir.", "A strong password that is easy to read and type."),
  },
  {
    kind: "random",
    label: tr("Aléatoire", "Random"),
    help: tr("Caractères tirés au hasard par le générateur sécurisé du système.", "Characters drawn by the system's secure generator."),
  },
  {
    kind: "memorable",
    label: tr("Mémorisable", "Memorable"),
    help: tr("Des mots faciles à taper, difficiles à deviner.", "Words that are easy to type and hard to guess."),
  },
  {
    kind: "pin",
    label: tr("Code PIN", "PIN code"),
    help: tr("Des chiffres seulement, pour les codes et les cadenas.", "Digits only, for codes and locks."),
  },
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

/** Strength in words from the generator's entropy. */
function strengthText(bits: number): string {
  if (bits < 40) return tr("Faible", "Weak");
  if (bits < 60) return tr("Correct", "Fair");
  if (bits < 80) return tr("Fort", "Strong");
  return tr("Très fort", "Very strong");
}

/** Countdown ring of a one-time code (the app's TotpCountdown). */
function ring(): { el: SVGSVGElement; set: (remaining: number) => void } {
  const r = 6.5;
  const c = 2 * Math.PI * r;
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", "16");
  svg.setAttribute("height", "16");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", "ring");
  const mk = (cls: string) => {
    const el = document.createElementNS(SVG_NS, "circle");
    el.setAttribute("cx", "8");
    el.setAttribute("cy", "8");
    el.setAttribute("r", String(r));
    el.setAttribute("fill", "none");
    el.setAttribute("stroke-width", "2");
    el.setAttribute("class", cls);
    svg.appendChild(el);
    return el;
  };
  mk("track");
  const arc = mk("arc");
  arc.setAttribute("stroke-linecap", "round");
  arc.setAttribute("stroke-dasharray", c.toFixed(2));
  const set = (remaining: number) => {
    const f = Math.min(Math.max(remaining / TOTP_PERIOD, 0), 1);
    arc.setAttribute("stroke-dashoffset", (c * (1 - f)).toFixed(2));
  };
  set(0);
  return { el: svg, set };
}

export function mountPopup(root: HTMLElement, deps: PopupDeps): PopupHandle {
  const timers = deps.timers ?? realTimers;
  const copyText = deps.copy ?? ((t: string) => navigator.clipboard.writeText(t));
  const container = h("div", { class: "pp" });
  mount(root, container);
  let pending: Promise<unknown> = Promise.resolve();
  const track = <T>(p: Promise<T>): Promise<T> => {
    pending = pending.then(() => p).catch(() => undefined);
    return p;
  };

  // ---- toast: green check or red triangle ----
  let toastEl: HTMLElement | null = null;
  let toastTimer: unknown = null;
  const toast = (text: string, tone: "ok" | "error" = "ok") => {
    toastEl?.remove();
    if (toastTimer !== null) timers.clearTimeout(toastTimer);
    const el = h(
      "div",
      { class: `toast ${tone}`, attrs: { role: tone === "error" ? "alert" : "status" } },
      h("span", { class: "toast-mark", attrs: { "aria-hidden": "true" } }, icon(tone === "ok" ? "check" : "alert", tone === "ok" ? 11 : 18)),
      h("span", null, text),
    );
    toastEl = el;
    container.append(el);
    toastTimer = timers.setTimeout(() => el.remove(), TOAST_MS);
  };
  const copy = (value: string, done: string) =>
    copyText(value).then(
      () => toast(done),
      () => toast(tr("Copie impossible", "Could not copy"), "error"),
    );

  const button = (label: string, cls: string, fn: () => void, attrs: Record<string, string> = {}) =>
    h("button", { class: cls, attrs: { type: "button", ...attrs }, on: { click: () => fn() } }, label);
  const iconButton = (label: string, glyph: Parameters<typeof icon>[0], fn: () => void, size = 15) =>
    h("button", { class: "btn-icon", attrs: { type: "button", "aria-label": label, title: label }, on: { click: () => fn() } }, icon(glyph, size));

  // ---- full-page states ----
  const center = (...children: (Node | null)[]) => mount(container, h("div", { class: "center" }, ...children));

  function renderUnpaired(err?: string): void {
    center(
      mark("l"),
      h("h1", null, tr("OnePass n'est pas appairé", "OnePass is not paired")),
      h(
        "p",
        null,
        tr(
          "Relie cette extension à l'app OnePass de cet ordinateur pour remplir tes logins.",
          "Link this extension to the OnePass app on this computer to fill your logins.",
        ),
      ),
      h("div", { class: "actions" }, button(tr("Appairer avec OnePass", "Pair with OnePass"), "btn btn-primary", () => void track(startPairing()))),
      err ? h("p", { class: "error-line", attrs: { role: "alert" } }, err) : null,
    );
  }

  async function startPairing(): Promise<void> {
    center(
      mark("l"),
      h("h1", null, tr("Appairage…", "Pairing…")),
      h("p", null, tr("Ouvre l'app OnePass si elle ne l'est pas.", "Open the OnePass app if it is not open.")),
    );
    const r = await call(deps.send, { type: "popup_pair_start" }, parseSas);
    if (!r.ok) {
      if (r.code === "host_missing") renderHostMissing();
      else renderUnpaired(errorText(r.code));
      return;
    }
    center(
      mark("l"),
      h("h1", null, tr("Compare les codes", "Compare the codes")),
      h("p", null, tr("Le même code doit s'afficher dans l'app OnePass.", "The OnePass app must show the same code.")),
      h("div", { class: "sas", attrs: { "aria-label": tr("Code d'appairage", "Pairing code") } }, r.value.sas),
      h(
        "div",
        { class: "actions" },
        button(tr("Annuler", "Cancel"), "btn", () => {
          void call(deps.send, { type: "popup_pair_cancel" }, parseEmpty);
          renderUnpaired();
        }),
        button(tr("Les codes sont identiques", "The codes match"), "btn btn-primary", () => void track(approve())),
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

  const forgetButton = () => button(tr("Oublier cet appairage", "Forget this pairing"), "btn-link", () => confirmForget());

  /** Confirmation step; "Annuler" goes back to the current state. */
  function confirmForget(): void {
    stopTotp();
    center(
      mark("l"),
      h("h1", null, tr("Oublier cet appairage ?", "Forget this pairing?")),
      h("p", null, tr("Il faudra appairer à nouveau.", "You will have to pair again.")),
      h(
        "div",
        { class: "actions" },
        button(tr("Annuler", "Cancel"), "btn", () => void track(load())),
        button(tr("Oublier", "Forget"), "btn btn-primary", () => void track(forget())),
      ),
    );
  }

  async function forget(): Promise<void> {
    const r = await call(deps.send, { type: "popup_forget" }, parseEmpty);
    status = null;
    suggestions = [];
    results = null;
    selected = null;
    view = "none";
    renderUnpaired(r.ok ? undefined : errorText(r.code));
  }

  function renderLocked(): void {
    center(
      mark("l"),
      h("h1", null, tr("OnePass est verrouillé", "OnePass is locked")),
      h("p", null, tr("Déverrouille l'app pour voir et remplir tes logins.", "Unlock the app to see and fill your logins.")),
      h(
        "div",
        { class: "actions" },
        button(tr("Déverrouiller dans OnePass", "Unlock in OnePass"), "btn btn-primary", () =>
          void track(
            call(deps.send, { type: "popup_unlock" }, parseLocked).then((r) => {
              if (r.ok && !r.value.locked) return load();
              if (!r.ok) toast(errorText(r.code), "error");
              return undefined;
            }),
          ),
        ),
      ),
      forgetButton(),
    );
  }

  function renderHostMissing(): void {
    center(
      mark("l"),
      h("h1", null, tr("App OnePass introuvable", "OnePass app not found")),
      h("p", null, tr("Installe ou ouvre l'app OnePass sur cet ordinateur, puis réessaie.", "Install or open the OnePass app on this computer, then try again.")),
      h("div", { class: "actions" }, button(tr("Réessayer", "Try again"), "btn btn-primary", () => void track(load()))),
    );
  }

  function renderError(code: string): void {
    center(
      mark("l"),
      h("h1", null, errorText(code)),
      h("div", { class: "actions" }, button(tr("Réessayer", "Try again"), "btn btn-primary", () => void track(load()))),
    );
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
  const side = h("aside", { class: "pp-side glass" });
  const main = h("section", { class: "pp-main" });

  const stopTotp = () => {
    if (totpTimer !== null) timers.clearInterval(totpTimer);
    totpTimer = null;
  };

  function renderMain(): void {
    const placeholder = tr("Rechercher dans OnePass", "Search OnePass");
    const input = h("input", {
      attrs: { type: "search", placeholder, "aria-label": placeholder, maxlength: "256" },
    });
    input.addEventListener("input", () => {
      if (searchTimer !== null) timers.clearTimeout(searchTimer);
      const q = input.value;
      searchTimer = timers.setTimeout(() => void track(search(q)), SEARCH_DEBOUNCE_MS);
    });
    const genLabel = tr("Générateur de mot de passe", "Password generator");
    const genBtn = h(
      "button",
      {
        class: `btn-icon gen-toggle${view === "gen" ? " on" : ""}`,
        attrs: { type: "button", "aria-label": genLabel, title: genLabel },
        on: { click: () => void track(openGenerator()) },
      },
      icon("key", 18),
    );
    const account = status?.account ?? "";
    mount(
      container,
      h(
        "div",
        { class: "pp-head" },
        h("span", { class: "brand" }, mark("m"), "OnePass"),
        h("label", { class: "search glass" }, icon("search", 14), input),
        genBtn,
        h("span", { class: "account", attrs: { title: account } }, h("span", { class: "avatar", attrs: { "aria-hidden": "true" } }, initials(account)), h("span", null, account)),
      ),
      h("div", { class: "pp-body" }, side, main),
    );
    renderSide();
    if (view === "none") renderIdleMain();
  }

  function renderIdleMain(): void {
    mount(
      main,
      h(
        "div",
        { class: "center" },
        h("h2", null, tr("Choisis un élément", "Pick an item")),
        h("p", null, tr("Ou ouvre le générateur pour créer un mot de passe.", "Or open the generator to make a password.")),
      ),
    );
  }

  function renderSide(): void {
    const items = results ?? suggestions;
    let title: string;
    let empty: string | null = null;
    if (results) {
      title = tr("Résultats", "Results");
      if (items.length === 0) empty = tr("Aucun résultat", "No results");
    } else if (domain) {
      title = tr(`Suggestions pour ${domain}`, `Suggestions for ${domain}`);
      if (items.length === 0) empty = tr(`Aucun login pour ${domain}`, `No login for ${domain}`);
    } else {
      title = tr("Suggestions", "Suggestions");
      empty = tr("Cette page n'est pas un site HTTPS.", "This page is not an HTTPS site.");
    }
    const list = h("div", { class: "pp-list", attrs: { role: "listbox", "aria-label": title } });
    for (const it of items) {
      list.append(
        h(
          "button",
          {
            class: "row",
            attrs: { type: "button", role: "option", "aria-selected": String(view === "detail" && selected === it.item_id) },
            on: { click: () => void track(openItem(it.item_id)) },
          },
          itemArt(it, "m"),
          h("span", { class: "stack" }, h("span", { class: "t1" }, it.title), h("span", { class: "t2" }, it.subtitle)),
        ),
      );
    }
    mount(
      side,
      h("h1", { class: "pp-side-title" }, icon(results ? "search" : "star", 13), title),
      list,
      empty ? h("p", { class: "pp-empty" }, empty) : null,
      domain && !results
        ? h(
            "div",
            { class: "verified" },
            icon("shield", 16),
            h(
              "span",
              null,
              tr(
                `Domaine vérifié : ${domain}. Le remplissage ne marche que sur ce site exact.`,
                `Verified domain: ${domain}. Filling only works on this exact site.`,
              ),
            ),
          )
        : null,
      h("div", { class: "pp-foot" }, forgetButton()),
    );
  }

  /** Only the reply to the latest query is shown (replies may cross). */
  let searchSeq = 0;
  async function search(q: string): Promise<void> {
    const seq = ++searchSeq;
    if (q.trim() === "") {
      results = null;
      renderSide();
      return;
    }
    const r = await call(deps.send, { type: "popup_search", query: q }, parseItems);
    if (seq !== searchSeq) return;
    if (!r.ok) return handleError(r.code);
    results = r.value.items;
    renderSide();
  }

  function handleError(code: string): void {
    stopTotp();
    if (code === "locked") renderLocked();
    else if (code === "unpaired") renderUnpaired();
    else if (code === "host_missing") renderHostMissing();
    else toast(errorText(code), "error");
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
    const firstLabel =
      s.kind === "login" ? tr("nom d’utilisateur", "username") : s.kind === "card" ? tr("carte", "card") : tr("identité", "identity");
    card.append(
      fieldRow(
        firstLabel,
        s.subtitle,
        s.kind === "login" && s.subtitle !== ""
          ? iconButton(tr("Copier le nom d’utilisateur", "Copy username"), "copy", () =>
              void track(copy(s.subtitle, tr("Nom d’utilisateur copié", "Username copied"))),
            )
          : null,
      ),
    );
    if (s.kind === "login" && s.has_password) {
      const value = h("span", { class: "field-value mono pwd-value" }, MASK);
      let shown: string | null = null;
      const label = { show: tr("Afficher", "Show"), hide: tr("Masquer", "Hide") };
      const toggle: HTMLButtonElement = button(label.show, "btn btn-link", () =>
        void track(
          (async () => {
            if (shown !== null) {
              value.textContent = MASK;
              toggle.textContent = label.show;
              shown = null;
              return;
            }
            const v = await call(deps.send, { type: "popup_reveal", itemId }, parseValue);
            if (!v.ok) return handleError(v.code);
            value.textContent = v.value.value;
            toggle.textContent = label.hide;
            shown = v.value.value;
          })(),
        ),
      );
      // Copy asks the app for the value at the click, like "Afficher"; it is
      // never kept once the row is gone.
      const copyPwd = iconButton(tr("Copier le mot de passe", "Copy password"), "copy", () =>
        void track(
          (async () => {
            let secret = shown;
            if (secret === null) {
              const v = await call(deps.send, { type: "popup_reveal", itemId }, parseValue);
              if (!v.ok) return handleError(v.code);
              secret = v.value.value;
            }
            await copy(secret, tr("Mot de passe copié", "Password copied"));
          })(),
        ),
      );
      card.append(fieldRow(tr("mot de passe", "password"), value, toggle, copyPwd));
    }
    if (s.kind === "login" && s.has_totp) {
      const code = h("span", { class: "field-value mono totp-code" }, "··· ···");
      const left = h("span", { class: "field-note totp-left" }, "");
      const countdown = ring();
      const pill = h("span", { class: "totp-pill" }, countdown.el, left);
      let current = "";
      let remaining = 0;
      const show = () => {
        left.textContent = `${remaining} s`;
        countdown.set(remaining);
        pill.classList.toggle("low", remaining <= 5);
        pill.setAttribute("aria-label", tr(`encore ${remaining} secondes`, `${remaining} seconds left`));
      };
      const copyCode = iconButton(tr("Copier le code", "Copy code"), "copy", () => {
        if (current !== "") void track(copy(current, tr("Code copié", "Code copied")));
      });
      card.append(fieldRow(tr("code à usage unique", "one-time code"), code, pill, copyCode));
      // One request at a time: ticks during a slow refresh do not stack.
      let inFlight = false;
      const refresh = async () => {
        if (inFlight) return;
        inFlight = true;
        try {
          const t = await call(deps.send, { type: "popup_totp", itemId }, parseTotp);
          if (selected !== itemId || view !== "detail") return;
          if (!t.ok) {
            stopTotp();
            return handleError(t.code);
          }
          current = t.value.code;
          code.textContent = formatCode(t.value.code);
          remaining = Math.max(0, Math.floor(t.value.remaining));
          show();
        } finally {
          inFlight = false;
        }
      };
      await refresh();
      totpTimer = timers.setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) void track(refresh());
        else show();
      }, 1000);
    }
    if (website) {
      card.append(h("div", { class: "field-row website" }, h("span", { class: "stack" }, h("span", { class: "cell-label" }, tr("site web", "website")), h("span", { class: "field-value" }, website))));
    }
    const fill = button(tr("Remplir", "Fill"), "btn btn-primary", () =>
      void track(
        call(deps.send, { type: "popup_fill", itemId }, parseFilled).then((f) => {
          if (f.ok) toast(tr(`Rempli sur ${f.value.domain}`, `Filled on ${f.value.domain}`));
          else handleError(f.code);
        }),
      ),
    );
    mount(
      main,
      h(
        "div",
        { class: "pp-bar" },
        itemArt(s, 52),
        h("div", { class: "pp-title" }, h("h2", null, s.title), h("span", { class: "vault" }, s.vault_name)),
        fill,
      ),
      h("div", { class: "pp-detail" }, card),
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
    container.querySelector(".pp-head .gen-toggle")?.classList.add("on");
    await generate();
  }

  function colored(pw: string): HTMLElement {
    const out = h("div", { class: "gen-out", attrs: { "aria-label": tr("Mot de passe généré", "Generated password") } });
    for (const ch of pw) {
      const cls = /[0-9]/.test(ch) ? "ch-digit" : /\p{L}/u.test(ch) ? "" : "ch-symbol";
      out.append(cls ? h("span", { class: cls }, ch) : ch);
    }
    return out;
  }

  async function renderGenerator(): Promise<void> {
    const select = h("select", { class: "select", attrs: { "aria-label": tr("Type de mot de passe", "Password type") } });
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
    const settings = h("div", { class: "card" }, h("label", { class: "gen-line" }, tr("Type", "Type"), select));
    if (genKind === "random") {
      const range = h("input", { attrs: { type: "range", min: "8", max: "64", value: String(genLength), "aria-label": tr("Longueur", "Length") } });
      const shown = h("span", { class: "field-note" }, String(genLength));
      range.addEventListener("input", () => (shown.textContent = range.value));
      range.addEventListener("change", () => {
        genLength = Number(range.value);
        void track(generate());
      });
      settings.append(h("label", { class: "gen-line" }, tr("Longueur", "Length"), range, shown));
    }
    let historyList: HTMLElement | null = null;
    if (historyOpen) {
      const r = await call(deps.send, { type: "popup_history" }, parseHistory);
      const entries: GeneratorEntry[] = r.ok ? r.value.entries : [];
      historyList = h("ul", { class: "history-list" });
      for (const e of entries) historyList.append(h("li", null, e.password));
      if (entries.length === 0) historyList.append(h("li", null, tr("Aucun mot de passe généré", "No generated password")));
    }
    const strength = h("div", { class: "strength" }, h("div"));
    (strength.firstChild as HTMLElement).style.width = `${Math.min(100, Math.round((genEntropy / 100) * 100))}%`;
    mount(
      main,
      h(
        "div",
        { class: "gen-head" },
        h("h2", null, tr("Générateur de mot de passe", "Password generator")),
        h(
          "button",
          {
            class: "btn-icon",
            attrs: { type: "button", "aria-label": tr("Fermer le générateur", "Close the generator") },
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
        colored(genPassword),
        h(
          "div",
          { class: "strength-line" },
          strength,
          h("span", { class: "strength-label" }, strengthText(genEntropy)),
          srOnly(tr(`Entropie : ${Math.round(genEntropy)} bits`, `Entropy: ${Math.round(genEntropy)} bits`)),
        ),
        h(
          "div",
          { class: "actions" },
          button(tr("Copier", "Copy"), "btn", () => void track(copy(genPassword, tr("Copié", "Copied")))),
          h(
            "button",
            {
              class: "btn-icon",
              attrs: { type: "button", "aria-label": tr("Générer un autre", "Generate another"), title: tr("Générer un autre", "Generate another") },
              on: { click: () => void track(generate()) },
            },
            icon("refresh", 16),
          ),
          h("span", { class: "stack" }),
          button(tr("Remplir", "Fill"), "btn btn-primary", () =>
            void track(
              call(deps.send, { type: "popup_fill_generated", password: genPassword }, parseFilled).then((f) => {
                if (f.ok) toast(tr(`Rempli sur ${f.value.domain}`, `Filled on ${f.value.domain}`));
                else handleError(f.code);
              }),
            ),
          ),
        ),
        settings,
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
          h("span", { class: "stack" }, tr("Historique du générateur", "Generator history")),
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

  mount(container, h("div", { class: "center" }, mark("l")));
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
