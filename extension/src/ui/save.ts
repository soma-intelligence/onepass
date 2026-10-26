// Save prompt (spec 8.5, Save mockup): views `prompt` (new or update),
// `edit` and `saved`, plus the provider-link variant (spec 8.7). The
// password is not part of `save_init`: it is fetched only when the user
// clicks "Afficher", and the page never sends it back (the worker keeps the
// typed or generated one). Exception: "Enregistrer un nouveau login" from the
// menu (`view: "edit"`) opens the edit view with nothing typed on the page;
// the password the user types here is sent with the save.
import { ext } from "../shared/browser";
import type { SaveDecision, SaveEdits } from "../shared/messages";
import type { SaveInit } from "../shared/ui";
import {
  ClickGuard,
  type FrameDeps,
  call,
  errorText,
  h,
  icon,
  mark,
  messageBlock,
  mount,
  observeVisibility,
  providerLabel,
  realTimers,
  tile,
  tokenFromHash,
} from "./components";
import { parseEmpty, parsePassword, parseSaveInit } from "./parse";

/** The saved confirmation closes itself after this delay. */
export const SAVED_CLOSE_MS = 4000;

const MASK = "••••••••••••";
const ACCENT_TILE = "#14532D";

export const RULES: readonly { value: SaveEdits["rule"]; label: string }[] = [
  { value: "domain", label: "Tout le domaine" },
  { value: "exact_host", label: "Sous-domaine exact" },
  { value: "exact_url", label: "URL exacte" },
  { value: "never", label: "Jamais remplir" },
];

export interface SaveHandle {
  ready: Promise<void>;
}

interface Draft {
  title: string;
  username: string;
  vaultId: string;
  rule: SaveEdits["rule"];
  tags: string[];
  /** Shown in clear (revealed or generated), else null. */
  password: string | null;
  revealed: boolean;
  /** New login from the menu: the password typed here ("" when generated). */
  typed: string;
}

export function mountSave(root: HTMLElement, deps: FrameDeps): SaveHandle {
  const now = deps.now ?? (() => performance.now());
  const timers = deps.timers ?? realTimers;
  const guard = new ClickGuard({ now, ...(deps.trusted ? { trusted: deps.trusted } : {}) });
  const token = tokenFromHash(deps.hash);
  const container = h("div", { class: "save" });
  mount(root, container);
  (deps.observe ?? observeVisibility)(container, (v) => guard.setVisibility(v));

  let init: SaveInit | null = null;
  let draft: Draft | null = null;
  let mode: "new" | "update" = "new";
  let more = false;

  const btn = (label: string, cls: string, fn: () => void, attrs: Record<string, string> = {}) =>
    h("button", { class: cls, attrs: { type: "button", ...attrs }, on: { click: guard.wrap(fn) } }, label);

  const iconBtn = (label: string, glyph: Parameters<typeof icon>[0], fn: () => void) =>
    h("button", { class: "btn-icon", attrs: { type: "button", "aria-label": label }, on: { click: guard.wrap(fn) } }, icon(glyph, 12));

  const show = (...children: (HTMLElement | null)[]) => {
    mount(container, ...children);
    guard.reset();
  };

  const errLine = () => h("p", { class: "error-line", attrs: { role: "alert" } });

  const closeSoon = () => {
    timers.setTimeout(() => {
      if (token) void call(deps.send, { type: "save_close", token }, parseEmpty);
    }, SAVED_CLOSE_MS);
  };

  const decide = async (decision: SaveDecision, err: HTMLElement, saved: () => void) => {
    if (!token || !init || !draft) return;
    const msg: { type: "save_decide"; token: string; decision: SaveDecision; edits?: SaveEdits } = {
      type: "save_decide",
      token,
      decision,
    };
    if (decision === "save" && init.kind === "login") {
      msg.edits = {
        title: draft.title,
        username: draft.username,
        // Never sent back: the worker holds the typed or generated password,
        // except one typed in this very page (new login from the menu).
        password: init.view === "edit" ? draft.typed : "",
        vaultId: draft.vaultId,
        rule: draft.rule,
        tags: draft.tags,
      };
    }
    const r = await call(deps.send, msg, parseEmpty);
    if (!r.ok) {
      err.textContent = errorText(r.code);
      return;
    }
    if (decision !== "dismiss") saved();
  };

  const vaultName = () => init?.vaults.find((v) => v.id === draft?.vaultId)?.name ?? "";

  const vaultSelect = () => {
    const sel = h("select", { class: "select", attrs: { "aria-label": "Coffre" } });
    for (const v of init?.vaults ?? []) {
      const o = h("option", { attrs: { value: v.id } }, v.name);
      if (v.id === draft?.vaultId) o.selected = true;
      sel.append(o);
    }
    sel.addEventListener("change", () => {
      if (draft) draft.vaultId = sel.value;
    });
    return sel;
  };

  /** Vault choice and "Enregistrer"; with no vault, nothing can be saved. */
  const saveActions = (cls: string, err: HTMLElement, d: Draft) => {
    const save = btn("Enregistrer", "btn btn-primary", () =>
      void decide("save", err, () => renderSaved(`${d.title} enregistré`, `Dans ${vaultName()}`)),
    );
    if ((init?.vaults.length ?? 0) > 0) return h("div", { class: cls }, vaultSelect(), save);
    save.disabled = true;
    return h("div", { class: cls }, h("span", { class: "stack note no-vault" }, "Aucun coffre disponible"), save);
  };

  const header = (title: string, withMore: boolean) =>
    h(
      "div",
      { class: "save-head" },
      mark("m"),
      h("h1", null, title),
      withMore
        ? iconBtn("Options", "more", () => {
            more = !more;
            renderPrompt();
          })
        : null,
      iconBtn("Fermer", "close", () => void decide("dismiss", errLine(), () => undefined)),
    );

  function renderSaved(title: string, sub: string): void {
    show(
      h(
        "div",
        { class: "saved", attrs: { role: "status" } },
        tile(init?.title.charAt(0) ?? "O", ACCENT_TILE, "m"),
        h("span", { class: "stack" }, h("span", { class: "t1" }, title), h("span", { class: "t2" }, sub)),
        btn("Fermer", "btn-link", () => {
          if (token) void call(deps.send, { type: "save_close", token }, parseEmpty);
        }),
      ),
    );
    closeSoon();
  }

  const never = () => {
    if (!init) return;
    const err = errLine();
    void decide("never", err, () => renderSaved("OnePass ne proposera plus rien ici", "Réglable dans Réglages › Remplissage auto"));
  };

  function renderProviderLink(i: SaveInit): void {
    const p = i.provider;
    const err = errLine();
    const line = p ? `Enregistrer le lien ${i.site} ↔ ${providerLabel(p.id)} (${p.email})` : "Enregistrer le lien";
    show(
      h(
        "div",
        { class: "save-body", attrs: { role: "dialog", "aria-label": "Enregistrer le lien" } },
        header("Enregistrer le lien ?", true),
        more ? moreMenu(i) : null,
        h("p", { class: "message-title link-line" }, line),
        h(
          "div",
          { class: "actions" },
          h("span", { class: "stack" }),
          btn("Pas maintenant", "btn", () => void decide("dismiss", err, () => undefined)),
          btn("Enregistrer", "btn btn-primary", () =>
            void decide("save", err, () =>
              renderSaved("Lien enregistré", p ? `${i.site} ↔ ${providerLabel(p.id)}` : i.site),
            ),
          ),
        ),
        err,
      ),
    );
  }

  const moreMenu = (i: SaveInit) =>
    h(
      "div",
      { class: "more", attrs: { role: "menu" } },
      btn(`Ne jamais proposer pour ${i.site}`, "", never, { role: "menuitem" }),
      btn("Pas maintenant", "", () => void decide("dismiss", errLine(), () => undefined), { role: "menuitem" }),
    );

  function renderPrompt(): void {
    if (!init || !draft) return;
    const i = init;
    if (i.kind === "provider_link") {
      renderProviderLink(i);
      return;
    }
    const d = draft;
    const err = errLine();
    const seg = i.update
      ? h(
          "div",
          { class: "seg", attrs: { role: "tablist" } },
          btn("Nouvel élément", "", () => {
            mode = "new";
            renderPrompt();
          }, { role: "tab", "aria-selected": String(mode === "new") }),
          btn("Mettre à jour (1)", "", () => {
            mode = "update";
            renderPrompt();
          }, { role: "tab", "aria-selected": String(mode === "update") }),
        )
      : null;
    let card: HTMLElement;
    let note: string | null = null;
    if (mode === "update" && i.update) {
      card = h(
        "div",
        { class: "candidate selected" },
        tile(i.update.title.charAt(0), ACCENT_TILE, "m"),
        h("span", { class: "stack" }, h("span", { class: "t1" }, i.update.title), h("span", { class: "t2" }, d.username)),
      );
      note = "L'ancien mot de passe reste dans l'historique de l'élément.";
    } else {
      card = h(
        "div",
        { class: "candidate" },
        tile(d.title.charAt(0), ACCENT_TILE, "m"),
        h("span", { class: "stack" }, h("span", { class: "t1" }, d.title), h("span", { class: "t2" }, d.username)),
        h(
          "button",
          { class: "btn", attrs: { type: "button" }, on: { click: guard.wrap(() => renderEdit()) } },
          icon("edit", 13),
          "Modifier",
        ),
      );
    }
    const actions =
      mode === "update"
        ? h(
            "div",
            { class: "actions" },
            h("span", { class: "stack" }),
            btn("Mettre à jour", "btn btn-primary", () =>
              void decide("update", err, () => renderSaved(`${i.update?.title ?? d.title} mis à jour`, d.username)),
            ),
          )
        : saveActions("actions", err, d);
    show(
      h(
        "div",
        { class: "save-body", attrs: { role: "dialog", "aria-label": "Enregistrer le login" } },
        header("Enregistrer le login ?", true),
        more ? moreMenu(i) : null,
        seg,
        card,
        note ? h("p", { class: "note" }, note) : null,
        actions,
        err,
      ),
    );
  }

  function renderEdit(): void {
    if (!init || !draft || !token) return;
    const i = init;
    const d = draft;
    const t = token;
    const err = errLine();
    const title = h("input", { class: "title-input", attrs: { type: "text", "aria-label": "Titre", maxlength: "256" } });
    title.value = d.title;
    title.addEventListener("input", () => (d.title = title.value));
    const user = h("input", { attrs: { type: "text", "aria-label": "nom d'utilisateur", maxlength: "1024" } });
    user.value = d.username;
    user.addEventListener("input", () => (d.username = user.value));
    const fresh = i.view === "edit";
    let pwd: HTMLElement;
    if (fresh) {
      const input = h("input", {
        class: "field-value mono pwd-value",
        attrs: { type: d.password !== null ? "text" : "password", "aria-label": "mot de passe", maxlength: "4096", autocomplete: "off" },
      });
      input.value = d.password ?? d.typed;
      input.addEventListener("input", () => {
        d.typed = input.value;
      });
      pwd = input;
    } else {
      pwd = h("span", { class: "field-value mono pwd-value" }, d.revealed && d.password !== null ? d.password : MASK);
    }
    const reveal = btn(d.revealed ? "Masquer" : "Afficher", "btn-link", async () => {
      if (d.revealed) {
        d.revealed = false;
        renderEdit();
        return;
      }
      if (d.password === null) {
        const r = await call(deps.send, { type: "save_reveal", token: t }, parsePassword);
        if (!r.ok) {
          err.textContent = errorText(r.code);
          return;
        }
        d.password = r.value.password;
      }
      d.revealed = true;
      renderEdit();
    });
    const generate = btn("Générer", "btn-link", async () => {
      const r = await call(deps.send, { type: "save_generate", token: t }, parsePassword);
      if (!r.ok) {
        err.textContent = errorText(r.code);
        return;
      }
      d.password = r.value.password;
      // The worker now holds this one; a later edit of the field replaces it.
      d.typed = "";
      d.revealed = true;
      renderEdit();
    });
    const rule = h("select", { class: "select", attrs: { "aria-label": "Correspondance" } });
    for (const x of RULES) {
      const o = h("option", { attrs: { value: x.value } }, x.label);
      if (x.value === d.rule) o.selected = true;
      rule.append(o);
    }
    rule.addEventListener("change", () => (d.rule = rule.value as SaveEdits["rule"]));
    const tags = h("div", { class: "tags" });
    for (const tag of d.tags) {
      tags.append(
        btn(tag, "tag", () => {
          d.tags = d.tags.filter((x) => x !== tag);
          renderEdit();
        }, { "aria-label": `Retirer le tag ${tag}` }),
      );
    }
    const tagInput = h("input", { class: "tag-input", attrs: { type: "text", "aria-label": "Ajouter un tag", placeholder: "Ajouter un tag", maxlength: "64" } });
    tagInput.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      e.preventDefault();
      const v = tagInput.value.trim();
      if (v !== "" && !d.tags.includes(v) && d.tags.length < 32) d.tags.push(v);
      renderEdit();
      container.querySelector<HTMLInputElement>(".tag-input")?.focus();
    });
    tags.append(tagInput);
    show(
      h(
        "div",
        { class: "save-body edit-head", attrs: { role: "dialog", "aria-label": "Enregistrer l'élément" } },
        h(
          "div",
          { class: "save-head" },
          mark("m"),
          h("h1", null, "Enregistrer l'élément"),
          iconBtn("Fermer", "close", () => (fresh ? void decide("dismiss", errLine(), () => undefined) : renderPrompt())),
        ),
      ),
      h(
        "div",
        { class: "edit-sheet" },
        title,
        h(
          "div",
          { class: "group" },
          h("label", { class: "cell" }, h("span", { class: "stack" }, h("span", { class: "cell-label" }, "nom d'utilisateur"), user)),
          h(
            "div",
            { class: "cell" },
            h("span", { class: "stack" }, h("span", { class: "cell-label" }, "mot de passe"), pwd),
            fresh ? null : reveal,
            generate,
          ),
        ),
        h(
          "div",
          { class: "group" },
          h(
            "div",
            { class: "cell" },
            h("span", { class: "stack" }, h("span", { class: "cell-label" }, "site web"), h("span", { class: "field-value" }, i.origin)),
            rule,
          ),
        ),
        h("div", { class: "stack" }, h("span", { class: "cell-label" }, "tags"), tags),
        err,
      ),
      saveActions("actions save-foot", err, d),
    );
  }

  async function load(): Promise<void> {
    if (!token) {
      show(messageBlock(errorText("invalid")));
      return;
    }
    const r = await call(deps.send, { type: "save_init", token }, parseSaveInit);
    if (!r.ok) {
      show(messageBlock(r.code === "unpaired" ? "Appairer OnePass depuis la barre d'outils" : errorText(r.code)));
      return;
    }
    init = r.value;
    mode = init.status === "update" && init.update ? "update" : "new";
    draft = {
      title: init.title,
      username: init.username,
      vaultId: init.vaults[0]?.id ?? "",
      rule: "domain",
      tags: [],
      password: null,
      revealed: false,
      typed: "",
    };
    if (init.view === "edit") renderEdit();
    else renderPrompt();
  }

  return { ready: load() };
}

if (typeof document !== "undefined" && ext?.runtime?.id) {
  const root = document.getElementById("root");
  if (root) mountSave(root, { send: (m) => ext.runtime.sendMessage(m), hash: location.hash });
}
