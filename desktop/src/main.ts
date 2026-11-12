// OnePass desktop UI. Plain DOM, no framework. Every text from an item is
// set with textContent, never innerHTML (spec 2026-10-30 section 3.2).
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

// ---- IPC types (mirror src-tauri/src/view.rs and commands.rs) -----------------

interface UiError {
  code: string;
  detail: string;
}
interface Status {
  state: "empty" | "locked" | "unlocked" | "missing" | "noDeviceFile";
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
  updatedAt: number;
}
interface Field {
  id: string;
  label: string;
  kind: string;
  value: string | null;
  secret: boolean;
  hasValue: boolean;
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
  urls: { label: string; url: string }[];
  sections: Section[];
  createdAt: number;
  updatedAt: number;
  trashed: boolean;
}
interface TypeInfo {
  key: string;
  label: string;
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    const err = e as UiError;
    if (err && err.code === "Locked") {
      void route();
    }
    throw err;
  }
}

function message(e: unknown): string {
  const err = e as UiError;
  switch (err?.code) {
    case "WrongPassword":
      return "Mot de passe incorrect.";
    case "WeakPassword":
      return "Choisis un mot de passe d'au moins 10 caractères.";
    case "Locked":
      return "Le coffre est verrouillé.";
    case "Validation":
      return "Un champ n'est pas valide : " + err.detail;
    case "NotFound":
      return "Élément introuvable.";
    default:
      return err?.detail ?? String(e);
  }
}

// ---- DOM helpers ------------------------------------------------------------------

type Child = Node | string | null | undefined | false;

function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<Record<string, unknown>> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") {
      el.addEventListener(k.slice(2).toLowerCase(), v as EventListener);
    } else if (k === "class") {
      el.className = String(v);
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

const app = document.getElementById("app")!;
const toastEl = document.getElementById("toast")!;
let toastTimer: number | undefined;

function toast(text: string): void {
  toastEl.textContent = text;
  toastEl.hidden = false;
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => (toastEl.hidden = true), 2600);
}

function mount(...nodes: Node[]): void {
  stopTimers();
  app.replaceChildren(...nodes);
}

const timers: number[] = [];
function stopTimers(): void {
  while (timers.length) window.clearInterval(timers.pop());
}

// ---- routing --------------------------------------------------------------------

async function route(): Promise<void> {
  let status: Status;
  try {
    status = await invoke<Status>("status");
  } catch (e) {
    mount(problem("OnePass n'a pas pu lire son coffre.", message(e)));
    return;
  }
  switch (status.state) {
    case "empty":
      mount(onboarding());
      break;
    case "locked":
      mount(unlockScreen(status));
      break;
    case "unlocked":
      await mainScreen();
      break;
    case "noDeviceFile":
      mount(
        problem(
          "Les secrets de cet appareil sont introuvables.",
          "Le coffre existe sur ce PC mais pas le fichier qui garde sa Secret Key. La restauration par l'Emergency Kit arrive dans une prochaine version.",
        ),
      );
      break;
    case "missing":
      mount(
        problem(
          "Le compte de cet appareil a disparu du coffre.",
          "C'est une anomalie d'intégrité : OnePass ne crée pas de compte par-dessus.",
        ),
      );
      break;
  }
}

function problem(title: string, detail: string): HTMLElement {
  return h(
    "div",
    { class: "center" },
    h("div", { class: "card" }, h("div", { class: "logo" }, "1"), h("h1", {}, title), h("p", { class: "muted" }, detail)),
  );
}

// ---- onboarding -------------------------------------------------------------------

function onboarding(): HTMLElement {
  const pw = h("input", { type: "password", autocomplete: "new-password", id: "pw" });
  const pw2 = h("input", { type: "password", autocomplete: "new-password", id: "pw2" });
  const err = h("div", { class: "error" });
  const go = h("button", { class: "primary", type: "submit" }, "Créer mon coffre");
  const form = h(
    "form",
    {
      onsubmit: async (ev: Event) => {
        ev.preventDefault();
        err.textContent = "";
        if (pw.value !== pw2.value) {
          err.textContent = "Les deux mots de passe ne sont pas identiques.";
          return;
        }
        go.disabled = true;
        go.textContent = "Création… (quelques secondes)";
        try {
          const created = await call<{ accountId: string; secretKey: string }>("create_account", {
            password: pw.value,
          });
          pw.value = "";
          pw2.value = "";
          mount(secretKeyScreen(created.secretKey));
        } catch (e) {
          err.textContent = message(e);
          go.disabled = false;
          go.textContent = "Créer mon coffre";
        }
      },
    },
    h("label", { for: "pw" }, "Mot de passe maître"),
    pw,
    h("label", { for: "pw2" }, "Encore une fois"),
    pw2,
    err,
    h("div", { class: "actions" }, go),
  );
  queueMicrotask(() => pw.focus());
  return h(
    "div",
    { class: "center" },
    h(
      "div",
      { class: "card" },
      h("div", { class: "logo" }, "1"),
      h("h1", {}, "Bienvenue dans OnePass"),
      h(
        "p",
        { class: "muted" },
        "Ton coffre est chiffré sur ce PC avec ton mot de passe maître et une Secret Key créée ici. Personne d'autre, pas même Soma, ne peut l'ouvrir.",
      ),
      form,
    ),
  );
}

function secretKeyScreen(secretKey: string): HTMLElement {
  const ok = h("input", { type: "checkbox", id: "ok" });
  const next = h("button", { class: "primary", disabled: true, onclick: () => void route() }, "Continuer");
  ok.addEventListener("change", () => (next.disabled = !ok.checked));
  return h(
    "div",
    { class: "center" },
    h(
      "div",
      { class: "card" },
      h("div", { class: "logo" }, "1"),
      h("h1", {}, "Ta Secret Key"),
      h(
        "p",
        { class: "muted" },
        "Note-la et garde-la en lieu sûr, avec ton mot de passe : il faut les deux pour ouvrir ton coffre sur un autre appareil. Ce PC la garde scellée par Windows.",
      ),
      h("div", { class: "secret-key" }, secretKey),
      h("label", { class: "check", for: "ok" }, ok, "J'ai noté ma Secret Key."),
      h("div", { class: "actions" }, next),
    ),
  );
}

// ---- unlock -------------------------------------------------------------------------

function unlockScreen(status: Status): HTMLElement {
  const pw = h("input", { type: "password", autocomplete: "current-password", id: "pw" });
  const err = h("div", { class: "error" });
  const go = h("button", { class: "primary", type: "submit" }, "Déverrouiller");
  const form = h(
    "form",
    {
      onsubmit: async (ev: Event) => {
        ev.preventDefault();
        err.textContent = "";
        go.disabled = true;
        go.textContent = "Déverrouillage…";
        try {
          await call("unlock", { password: pw.value });
          pw.value = "";
          await route();
        } catch (e) {
          err.textContent = message(e);
          pw.select();
          go.disabled = false;
          go.textContent = "Déverrouiller";
        }
      },
    },
    h("label", { for: "pw" }, "Mot de passe maître"),
    pw,
    err,
    h("div", { class: "actions" }, go),
  );
  queueMicrotask(() => pw.focus());
  return h(
    "div",
    { class: "center" },
    h(
      "div",
      { class: "card" },
      h("div", { class: "logo" }, "1"),
      h("h1", {}, "OnePass est verrouillé"),
      h(
        "p",
        { class: "muted" },
        `Verrouillage automatique après ${status.autoLockMinutes} min. Secrets de l'appareil protégés par ${status.protection === "dpapi" ? "Windows (DPAPI)" : status.protection}.`,
      ),
      form,
    ),
  );
}

// ---- main screen ----------------------------------------------------------------------

type Filter = { kind: "all" } | { kind: "favorites" } | { kind: "trash" } | { kind: "vault"; id: string };

const ui = {
  vaults: [] as Vault[],
  items: [] as Summary[],
  types: [] as TypeInfo[],
  filter: { kind: "all" } as Filter,
  query: "",
  selected: null as Summary | null,
};

const sidebarEl = h("nav", { class: "sidebar", "aria-label": "Coffres" });
const listEl = h("div", { class: "list", role: "listbox", "aria-label": "Éléments" });
const detailEl = h("main", { class: "detail" });

async function reload(): Promise<void> {
  [ui.vaults, ui.items] = await Promise.all([call<Vault[]>("vaults"), call<Summary[]>("items")]);
  if (ui.selected) {
    ui.selected = ui.items.find((i) => i.id === ui.selected!.id) ?? null;
  }
}

async function mainScreen(): Promise<void> {
  try {
    await reload();
    if (!ui.types.length) ui.types = await call<TypeInfo[]>("item_types");
  } catch (e) {
    mount(problem("Impossible d'ouvrir le coffre.", message(e)));
    return;
  }
  const search = h("input", {
    class: "search",
    type: "search",
    placeholder: "Rechercher",
    value: ui.query,
    oninput: () => {
      ui.query = search.value;
      renderList();
    },
  });
  const top = h(
    "header",
    { class: "topbar" },
    h("div", { class: "brand" }, "OnePass"),
    search,
    h("div", { class: "spacer" }),
    h("button", { onclick: () => openNewItem() }, "+ Nouvel élément"),
    h("button", { onclick: () => openGenerator() }, "Générateur"),
    h(
      "button",
      {
        onclick: async () => {
          await call("lock");
          ui.selected = null;
          await route();
        },
      },
      "Verrouiller",
    ),
  );
  mount(h("div", { class: "shell" }, top, sidebarEl, listEl, detailEl));
  renderSidebar();
  renderList();
  await renderDetail();
}

function renderSidebar(): void {
  const live = ui.items.filter((i) => !i.trashed && !i.archived);
  const nav = (label: string, count: number, f: Filter) => {
    const active = JSON.stringify(f) === JSON.stringify(ui.filter);
    return h(
      "button",
      {
        class: "nav" + (active ? " active" : ""),
        onclick: () => {
          ui.filter = f;
          renderSidebar();
          renderList();
        },
      },
      h("span", {}, label),
      h("span", { class: "count" }, String(count)),
    );
  };
  sidebarEl.replaceChildren(
    nav("Tous les éléments", live.length, { kind: "all" }),
    nav("Favoris", live.filter((i) => i.favorite).length, { kind: "favorites" }),
    h("h3", {}, "Coffres"),
    ...ui.vaults.map((v) => nav(v.name, v.itemCount, { kind: "vault", id: v.id })),
    h("h3", {}, "Autres"),
    nav("Corbeille", ui.items.filter((i) => i.trashed).length, { kind: "trash" }),
  );
}

function visibleItems(): Summary[] {
  const q = ui.query.trim().toLowerCase();
  return ui.items
    .filter((i) => {
      switch (ui.filter.kind) {
        case "trash":
          return i.trashed;
        case "favorites":
          return !i.trashed && !i.archived && i.favorite;
        case "vault":
          return !i.trashed && !i.archived && i.vaultId === (ui.filter as { id: string }).id;
        default:
          return !i.trashed && !i.archived;
      }
    })
    .filter((i) => !q || i.title.toLowerCase().includes(q) || i.subtitle.toLowerCase().includes(q) || (i.primaryUrl ?? "").toLowerCase().includes(q))
    .sort((a, b) => a.title.localeCompare(b.title, "fr", { sensitivity: "base" }));
}

function initial(title: string): string {
  return (title.trim()[0] ?? "?").toUpperCase();
}

function typeLabel(key: string): string {
  return ui.types.find((t) => t.key === key)?.label ?? key;
}

function renderList(): void {
  const items = visibleItems();
  if (!items.length) {
    listEl.replaceChildren(h("div", { class: "empty" }, ui.query ? "Aucun résultat." : "Aucun élément ici."));
    return;
  }
  listEl.replaceChildren(
    ...items.map((i) =>
      h(
        "button",
        {
          class: "row" + (ui.selected?.id === i.id ? " active" : ""),
          role: "option",
          "aria-selected": ui.selected?.id === i.id ? "true" : "false",
          onclick: () => {
            ui.selected = i;
            renderList();
            void renderDetail();
          },
        },
        h("span", { class: "icon", "aria-hidden": "true" }, initial(i.title)),
        h(
          "span",
          { class: "text" },
          h("div", { class: "title" }, (i.favorite ? "★ " : "") + (i.title || "Sans titre")),
          h("div", { class: "subtitle" }, i.subtitle || typeLabel(i.itemType)),
        ),
      ),
    ),
  );
}

// ---- detail ---------------------------------------------------------------------------

async function renderDetail(): Promise<void> {
  stopTimers();
  const sel = ui.selected;
  if (!sel) {
    detailEl.replaceChildren(h("div", { class: "empty" }, "Choisis un élément."));
    return;
  }
  let item: Item;
  try {
    item = await call<Item>("item", { vaultId: sel.vaultId, itemId: sel.id });
  } catch (e) {
    detailEl.replaceChildren(h("div", { class: "empty" }, message(e)));
    return;
  }
  const args = { vaultId: item.vaultId, itemId: item.id };
  const sections = item.sections
    .map((s) => ({ ...s, fields: s.fields.filter((f) => f.hasValue) }))
    .filter((s) => s.fields.length);

  const fieldRow = (f: Field): HTMLElement => {
    const valueEl = h("div", { class: "value" + (f.secret ? " mono" : "") });
    const buttons = h("div", { class: "buttons" });
    if (f.kind === "otp") {
      valueEl.className = "value otp";
      const tick = async () => {
        try {
          const t = await call<{ code: string; remaining: number }>("totp", { ...args, fieldId: f.id });
          valueEl.textContent = `${t.code.slice(0, 3)} ${t.code.slice(3)}  ·  ${t.remaining}s`;
        } catch {
          valueEl.textContent = "Code indisponible";
        }
      };
      void tick();
      timers.push(window.setInterval(tick, 1000));
    } else if (f.secret) {
      valueEl.textContent = "••••••••••";
      let shown = false;
      const reveal = h(
        "button",
        {
          class: "link",
          onclick: async () => {
            if (shown) {
              valueEl.textContent = "••••••••••";
              reveal.textContent = "Afficher";
              shown = false;
              return;
            }
            try {
              valueEl.textContent = await call<string>("reveal_field", { ...args, fieldId: f.id });
              reveal.textContent = "Masquer";
              shown = true;
            } catch (e) {
              toast(message(e));
            }
          },
        },
        "Afficher",
      );
      buttons.append(reveal);
    } else {
      valueEl.textContent = f.value ?? "";
    }
    buttons.append(
      h(
        "button",
        {
          class: "link",
          onclick: async () => {
            try {
              const secs = await call<number>("copy_field", { ...args, fieldId: f.id });
              toast(f.secret ? `Copié. Effacé du presse-papiers dans ${secs} s.` : "Copié.");
            } catch (e) {
              toast(message(e));
            }
          },
        },
        "Copier",
      ),
    );
    return h("div", { class: "field" }, h("div", {}, h("div", { class: "label" }, f.label), valueEl), buttons);
  };

  const fav = h(
    "button",
    {
      class: "link",
      title: item.favorite ? "Retirer des favoris" : "Ajouter aux favoris",
      onclick: async () => {
        await call("set_favorite", { ...args, favorite: !item.favorite });
        await reload();
        renderSidebar();
        renderList();
        await renderDetail();
      },
    },
    item.favorite ? "★" : "☆",
  );

  detailEl.replaceChildren(
    h(
      "header",
      {},
      h("span", { class: "icon", "aria-hidden": "true" }, initial(item.title)),
      h("div", { class: "grow" }, h("h2", {}, item.title || "Sans titre"), h("div", { class: "muted" }, typeLabel(item.itemType))),
      fav,
      !item.trashed && h("button", { onclick: () => editItem(item) }, "Modifier"),
      !item.trashed &&
        h(
          "button",
          {
            class: "danger",
            onclick: async () => {
              if (!window.confirm(`Mettre « ${item.title} » à la corbeille ?`)) return;
              await call("trash_item", args);
              ui.selected = null;
              await reload();
              renderSidebar();
              renderList();
              await renderDetail();
            },
          },
          "Corbeille",
        ),
    ),
    ...(item.urls.length
      ? [
          h(
            "div",
            { class: "section" },
            ...item.urls.map((u) =>
              h("div", { class: "field" }, h("div", {}, h("div", { class: "label" }, u.label || "Site web"), h("div", { class: "value" }, u.url))),
            ),
          ),
        ]
      : []),
    ...sections.map((s) => h("div", { class: "section" }, s.label && h("h4", {}, s.label), ...s.fields.map(fieldRow))),
    item.notes &&
      h(
        "div",
        { class: "section" },
        h("div", { class: "field" }, h("div", {}, h("div", { class: "label" }, "Notes"), h("div", { class: "value" }, item.notes))),
      ),
    h(
      "div",
      { class: "meta" },
      `Modifié le ${new Date(item.updatedAt * 1000).toLocaleString("fr-FR")} · créé le ${new Date(item.createdAt * 1000).toLocaleDateString("fr-FR")}`,
    ),
  );
}

// ---- editor -----------------------------------------------------------------------------

const TEXT_KINDS = new Set(["text", "concealed", "password", "url", "email", "phone", "menu", "otp", "mnemonic"]);

function editItem(item: Item): void {
  const title = h("input", { value: item.title, id: "f-title" });
  const url = h("input", { value: item.urls[0]?.url ?? "", id: "f-url", placeholder: "https://" });
  const notes = h("textarea", { id: "f-notes" });
  notes.value = item.notes;
  const changed = new Map<string, HTMLInputElement>();
  const inputs: Node[] = [];
  for (const s of item.sections) {
    for (const f of s.fields) {
      if (!TEXT_KINDS.has(f.kind)) continue;
      const input = h("input", {
        id: "f-" + f.id,
        type: f.secret ? "password" : "text",
        value: f.secret ? "" : (f.value ?? ""),
        placeholder: f.secret && f.hasValue ? "Inchangé" : "",
        autocomplete: "off",
        spellcheck: false,
      });
      input.addEventListener("input", () => changed.set(f.id, input));
      const row: Child[] = [h("label", { for: "f-" + f.id }, f.label), input];
      if (f.kind === "password") {
        row.push(
          h(
            "button",
            {
              type: "button",
              class: "link",
              onclick: async () => {
                const g = await call<{ password: string }>("generate_password", {
                  recipe: { kind: "characters", length: 20, digits: true, symbols: true },
                });
                input.type = "text";
                input.value = g.password;
                changed.set(f.id, input);
              },
            },
            "Générer",
          ),
        );
      }
      inputs.push(h("div", {}, ...row));
    }
  }
  const err = h("div", { class: "error" });
  const dialog = h(
    "dialog",
    {},
    h(
      "form",
      {
        method: "dialog",
        onsubmit: async (ev: Event) => {
          ev.preventDefault();
          const fields: Record<string, string> = {};
          for (const [id, el] of changed) fields[id] = el.value;
          try {
            await call("save_item", {
              edit: {
                vaultId: item.vaultId,
                itemId: item.id,
                title: title.value,
                notes: notes.value,
                url: url.value,
                fields,
              },
            });
            dialog.close();
            dialog.remove();
            await reload();
            renderSidebar();
            renderList();
            await renderDetail();
            toast("Enregistré.");
          } catch (e) {
            err.textContent = message(e);
          }
        },
      },
      h("h2", {}, "Modifier"),
      h("label", { for: "f-title" }, "Titre"),
      title,
      h("label", { for: "f-url" }, "Site web"),
      url,
      ...inputs,
      h("label", { for: "f-notes" }, "Notes"),
      notes,
      err,
      h(
        "div",
        { class: "actions" },
        h(
          "button",
          {
            type: "button",
            onclick: () => {
              dialog.close();
              dialog.remove();
            },
          },
          "Annuler",
        ),
        h("button", { class: "primary", type: "submit" }, "Enregistrer"),
      ),
    ),
  );
  document.body.append(dialog);
  dialog.showModal();
  title.focus();
}

function openNewItem(): void {
  const type = h("select", { id: "n-type" }, ...ui.types.map((t) => h("option", { value: t.key }, t.label)));
  const vault = h("select", { id: "n-vault" }, ...ui.vaults.map((v) => h("option", { value: v.id }, v.name)));
  if (ui.filter.kind === "vault") vault.value = ui.filter.id;
  const title = h("input", { id: "n-title", placeholder: "Ex. : Banque" });
  const err = h("div", { class: "error" });
  const dialog = h(
    "dialog",
    {},
    h(
      "form",
      {
        onsubmit: async (ev: Event) => {
          ev.preventDefault();
          try {
            const item = await call<Item>("new_item", {
              vaultId: vault.value,
              itemType: type.value,
              title: title.value.trim() || typeLabel(type.value),
            });
            dialog.close();
            dialog.remove();
            await reload();
            ui.selected = ui.items.find((i) => i.id === item.id) ?? null;
            renderSidebar();
            renderList();
            await renderDetail();
            editItem(item);
          } catch (e) {
            err.textContent = message(e);
          }
        },
      },
      h("h2", {}, "Nouvel élément"),
      h("label", { for: "n-type" }, "Type"),
      type,
      h("label", { for: "n-vault" }, "Coffre"),
      vault,
      h("label", { for: "n-title" }, "Titre"),
      title,
      err,
      h(
        "div",
        { class: "actions" },
        h(
          "button",
          {
            type: "button",
            onclick: () => {
              dialog.close();
              dialog.remove();
            },
          },
          "Annuler",
        ),
        h("button", { class: "primary", type: "submit" }, "Créer"),
      ),
    ),
  );
  document.body.append(dialog);
  dialog.showModal();
  title.focus();
}

// ---- generator ------------------------------------------------------------------------

function openGenerator(): void {
  const words = h("input", { type: "checkbox", id: "g-words" });
  const length = h("input", { type: "range", min: "8", max: "64", value: "20", id: "g-len" });
  const lengthOut = h("span", {}, "20");
  const symbols = h("input", { type: "checkbox", id: "g-sym", checked: true });
  const out = h("div", { class: "generated", "aria-live": "polite" });
  const bits = h("div", { class: "muted" });
  const regen = async () => {
    lengthOut.textContent = length.value;
    const recipe = words.checked
      ? { kind: "words", count: Math.max(4, Math.round(Number(length.value) / 5)), french: true }
      : { kind: "characters", length: Number(length.value), digits: true, symbols: symbols.checked };
    try {
      const g = await call<{ password: string; bits: number }>("generate_password", { recipe });
      out.textContent = g.password;
      bits.textContent = `${Math.round(g.bits)} bits d'entropie`;
    } catch (e) {
      out.textContent = message(e);
    }
  };
  for (const el of [words, length, symbols]) el.addEventListener("input", () => void regen());
  const dialog = h(
    "dialog",
    {},
    h("h2", {}, "Générateur"),
    h("label", { class: "check", for: "g-words" }, words, "Phrase de passe (mots français)"),
    h("label", { for: "g-len" }, "Longueur"),
    h("div", { class: "inline" }, length, lengthOut),
    h("label", { class: "check", for: "g-sym" }, symbols, "Symboles"),
    out,
    bits,
    h(
      "div",
      { class: "actions" },
      h("button", { type: "button", onclick: () => void regen() }, "Nouveau"),
      h(
        "button",
        {
          type: "button",
          class: "primary",
          onclick: () => {
            dialog.close();
            dialog.remove();
          },
        },
        "Fermer",
      ),
    ),
  );
  document.body.append(dialog);
  dialog.showModal();
  void regen();
}

// ---- start --------------------------------------------------------------------------------

void listen("locked", () => {
  ui.selected = null;
  for (const d of document.querySelectorAll("dialog")) d.remove();
  void route();
});

void route();
