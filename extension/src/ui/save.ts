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
  autosize,
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
  wayArt,
} from "./components";
import { tr } from "../shared/i18n";
import { parseEmpty, parsePassword, parseSaveInit } from "./parse";

/** Asked for by the edit view: the content script clamps it to the frame's largest height. */
const FULL_HEIGHT = 2000;

/** The saved confirmation closes itself after this delay. */
export const SAVED_CLOSE_MS = 4000;

const MASK = "••••••••••••";
const ACCENT_TILE = "#14532D";

export const RULES: readonly { value: SaveEdits["rule"]; label: string }[] = [
  { value: "domain", label: tr("Tout le domaine", "Whole domain") },
  { value: "exact_host", label: tr("Sous-domaine exact", "Exact subdomain") },
  { value: "exact_url", label: tr("URL exacte", "Exact URL") },
  { value: "never", label: tr("Jamais remplir", "Never fill") },
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
  const container = h("div", { class: "save fit" });
  mount(root, container);
  (deps.observe ?? observeVisibility)(container, (v) => guard.setVisibility(v));
  // The prompt is as tall as its content; the edit view takes the whole frame.
  let fit = true;
  const remeasure = autosize(
    container,
    (height) => {
      if (token) void call(deps.send, { type: "save_resize", token, height: fit ? height : FULL_HEIGHT }, parseEmpty);
    },
    deps.observeSize,
  );

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
    remeasure();
  };
  const setFit = (on: boolean) => {
    fit = on;
    container.classList.toggle("fit", on);
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
    const sel = h("select", { class: "select", attrs: { "aria-label": tr("Coffre", "Vault") } });
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

  /** "Enregistrer" of the current view; disabled while nothing can be saved. */
  let saveBtn: HTMLButtonElement | null = null;
  /** New login from the menu: no password typed or generated yet. */
  const noPassword = (d: Draft) => init?.view === "edit" && d.typed === "" && d.password === null;
  const updateSave = (d: Draft) => {
    if (saveBtn) saveBtn.disabled = (init?.vaults.length ?? 0) === 0 || noPassword(d);
  };

  /** Vault choice and "Enregistrer"; with no vault, nothing can be saved. */
  const saveActions = (cls: string, err: HTMLElement, d: Draft) => {
    const save = btn(tr("Enregistrer", "Save"), "btn btn-primary", () =>
      void decide("save", err, () => renderSaved(tr(`${d.title} enregistré`, `${d.title} saved`), tr(`Dans ${vaultName()}`, `In ${vaultName()}`))),
    );
    saveBtn = save;
    updateSave(d);
    if ((init?.vaults.length ?? 0) > 0) return h("div", { class: cls }, vaultSelect(), save);
    save.disabled = true;
    return h("div", { class: cls }, h("span", { class: "stack note no-vault" }, tr("Aucun coffre disponible", "No vault available")), save);
  };

  const header = (title: string, withMore: boolean) =>
    h(
      "div",
      { class: "save-head" },
      mark("m"),
      h("h1", null, title),
      withMore
        ? iconBtn(tr("Options", "Options"), "more", () => {
            more = !more;
            renderPrompt();
          })
        : null,
      iconBtn(tr("Fermer", "Close"), "close", () => void decide("dismiss", errLine(), () => undefined)),
    );

  function renderSaved(title: string, sub: string): void {
    setFit(true);
    show(
      h(
        "div",
        { class: "saved", attrs: { role: "status" } },
        h("span", { class: "saved-art" }, tile(init?.title.charAt(0) ?? "O", ACCENT_TILE, 52), h("span", { class: "ok-badge", attrs: { "aria-hidden": "true" } }, icon("check", 11))),
        h("span", { class: "stack" }, h("span", { class: "t1" }, title), h("span", { class: "t2" }, sub)),
        btn(tr("Fermer", "Close"), "btn-link", () => {
          if (token) void call(deps.send, { type: "save_close", token }, parseEmpty);
        }),
      ),
    );
    closeSoon();
  }

  const never = () => {
    if (!init) return;
    const err = errLine();
    void decide("never", err, () => renderSaved(tr("OnePass ne proposera plus rien ici", "OnePass won't offer anything here again"), tr("Réglable dans Réglages › Remplissage auto", "Change it in Settings › AutoFill")));
  };

  /**
   * Spec 8.7, after a sign-in through a provider by hand: one compact
   * prompt (not a sheet) that names the site, the provider and the very
   * provider account (its item) the link will point to.
   */
  function renderProviderLink(i: SaveInit): void {
    setFit(true);
    const p = i.provider;
    const err = errLine();
    const name = p ? providerLabel(p.id) : "";
    const art = wayArt({ kind: "login", has_password: false, methods: [], icon_letter: i.title.charAt(0).toUpperCase() || "O" }, p?.id, "m");
    show(
      h(
        "div",
        { class: "save-body link", attrs: { role: "dialog", "aria-label": tr("Enregistrer le lien", "Save the link") } },
        header(tr("Retenir ce lien ?", "Remember this link?"), true),
        more ? moreMenu(i) : null,
        h(
          "div",
          { class: "link-card" },
          art,
          h(
            "span",
            { class: "stack" },
            h("span", { class: "t1 link-line" }, p ? `${i.site} ↔ ${name}` : i.site),
            p ? h("span", { class: "line2" }, h("span", { class: "t2" }, p.email), p.title ? h("span", { class: "meta" }, ` · ${p.title}`) : null) : null,
          ),
        ),
        h(
          "p",
          { class: "note" },
          p
            ? tr(`La prochaine fois, OnePass se connectera avec ce compte ${name} en un clic.`, `Next time, OnePass signs in with this ${name} account in one click.`)
            : tr("La prochaine fois, OnePass se connectera en un clic.", "Next time, OnePass signs in in one click."),
        ),
        h(
          "div",
          { class: "actions" },
          h("span", { class: "stack" }),
          btn(tr("Pas maintenant", "Not now"), "btn", () => void decide("dismiss", err, () => undefined)),
          btn(tr("Enregistrer", "Save"), "btn btn-primary", () =>
            void decide("save", err, () =>
              renderSaved(tr("Lien enregistré", "Link saved"), p ? `${i.site} ↔ ${name} (${p.email})` : i.site),
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
      btn(tr(`Ne jamais proposer pour ${i.site}`, `Never offer for ${i.site}`), "", never, { role: "menuitem" }),
      btn(tr("Pas maintenant", "Not now"), "", () => void decide("dismiss", errLine(), () => undefined), { role: "menuitem" }),
    );

  function renderPrompt(): void {
    if (!init || !draft) return;
    const i = init;
    if (i.kind === "provider_link") {
      renderProviderLink(i);
      return;
    }
    setFit(true);
    const d = draft;
    const err = errLine();
    const seg = i.update
      ? h(
          "div",
          { class: "seg", attrs: { role: "tablist" } },
          btn(tr("Nouvel élément", "New item"), "", () => {
            mode = "new";
            renderPrompt();
          }, { role: "tab", "aria-selected": String(mode === "new") }),
          btn(tr("Mettre à jour (1)", "Update (1)"), "", () => {
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
      note = tr("L'ancien mot de passe reste dans l'historique de l'élément.", "The old password stays in the item's history.");
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
          tr("Modifier", "Edit"),
        ),
      );
    }
    const actions =
      mode === "update"
        ? h(
            "div",
            { class: "actions" },
            h("span", { class: "stack" }),
            btn(tr("Mettre à jour", "Update"), "btn btn-primary", () =>
              void decide("update", err, () => renderSaved(tr(`${i.update?.title ?? d.title} mis à jour`, `${i.update?.title ?? d.title} updated`), d.username)),
            ),
          )
        : saveActions("actions", err, d);
    show(
      h(
        "div",
        { class: "save-body", attrs: { role: "dialog", "aria-label": "Enregistrer le login" } },
        header(tr("Enregistrer le login ?", "Save the login?"), true),
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
    setFit(false);
    const i = init;
    const d = draft;
    const t = token;
    const err = errLine();
    const title = h("input", { class: "title-input", attrs: { type: "text", "aria-label": tr("Titre", "Title"), maxlength: "256" } });
    title.value = d.title;
    title.addEventListener("input", () => (d.title = title.value));
    const user = h("input", { attrs: { type: "text", "aria-label": tr("nom d'utilisateur", "username"), maxlength: "1024" } });
    user.value = d.username;
    user.addEventListener("input", () => (d.username = user.value));
    const fresh = i.view === "edit";
    let pwd: HTMLElement;
    if (fresh) {
      const input = h("input", {
        class: "field-value mono pwd-value",
        attrs: { type: d.password !== null ? "text" : "password", "aria-label": tr("mot de passe", "password"), maxlength: "4096", autocomplete: "off" },
      });
      input.value = d.password ?? d.typed;
      input.addEventListener("input", () => {
        d.typed = input.value;
        // Cleared after a generation: the generated one is no longer shown, nor saved.
        if (input.value === "") d.password = null;
        updateSave(d);
      });
      pwd = input;
    } else {
      pwd = h("span", { class: "field-value mono pwd-value" }, d.revealed && d.password !== null ? d.password : MASK);
    }
    const reveal = btn(d.revealed ? tr("Masquer", "Hide") : tr("Afficher", "Show"), "btn-link", async () => {
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
    const generate = btn(tr("Générer", "Generate"), "btn-link", async () => {
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
    const rule = h("select", { class: "select", attrs: { "aria-label": tr("Correspondance", "Match") } });
    for (const x of RULES) {
      const o = h("option", { attrs: { value: x.value } }, x.label);
      if (x.value === d.rule) o.selected = true;
      rule.append(o);
    }
    rule.addEventListener("change", () => (d.rule = rule.value as SaveEdits["rule"]));
    const tags = h("div", { class: tr("tags", "tags") });
    for (const tag of d.tags) {
      tags.append(
        btn(tag, "tag", () => {
          d.tags = d.tags.filter((x) => x !== tag);
          renderEdit();
        }, { "aria-label": tr(`Retirer le tag ${tag}`, `Remove tag ${tag}`) }),
      );
    }
    const tagInput = h("input", { class: "tag-input", attrs: { type: "text", "aria-label": tr("Ajouter un tag", "Add a tag"), placeholder: tr("Ajouter un tag", "Add a tag"), maxlength: "64" } });
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
        { class: "save-body edit-head", attrs: { role: "dialog", "aria-label": tr("Enregistrer l'élément", "Save the item") } },
        h(
          "div",
          { class: "save-head" },
          mark("m"),
          h("h1", null, tr("Enregistrer l'élément", "Save the item")),
          iconBtn(tr("Fermer", "Close"), "close", () => (fresh ? void decide("dismiss", errLine(), () => undefined) : renderPrompt())),
        ),
      ),
      h(
        "div",
        { class: "edit-sheet" },
        title,
        h(
          "div",
          { class: "group" },
          h("label", { class: "cell" }, h("span", { class: "stack" }, h("span", { class: "cell-label" }, tr("nom d'utilisateur", "username")), user)),
          h(
            "div",
            { class: "cell" },
            h("span", { class: "stack" }, h("span", { class: "cell-label" }, tr("mot de passe", "password")), pwd),
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
            h("span", { class: "stack" }, h("span", { class: "cell-label" }, tr("site web", "website")), h("span", { class: "field-value" }, i.origin)),
            rule,
          ),
        ),
        h("div", { class: "stack" }, h("span", { class: "cell-label" }, tr("tags", "tags")), tags),
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
      show(messageBlock(r.code === "unpaired" ? tr("Appairer OnePass depuis la barre d'outils", "Pair OnePass from the toolbar") : errorText(r.code)));
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
