// Inline menu (spec 8.3, Inline mockup): `menu.html#<token>` under a field.
// The menu asks the service worker for its summaries with its token and
// asks it to fill; it never sees a secret.
import { ext } from "../shared/browser";
import type { ProviderId, UiToBg } from "../shared/messages";
import { tr } from "../shared/i18n";
import type { MenuInit, Summary } from "../shared/ui";
import {
  ClickGuard,
  type FrameDeps,
  call,
  errorText,
  h,
  hostOf,
  icon,
  itemArt,
  mark,
  messageBlock,
  mount,
  observeVisibility,
  providerLabel,
  tokenFromHash,
} from "./components";
import { parseEmpty, parseLocked, parseMenuInit } from "./parse";

export interface MenuHandle {
  /** Resolves once the first render is done. */
  ready: Promise<void>;
}

const LOGIN_FORMS = new Set(["login", "signup", "change_password", "otp"]);
const NEW_PASSWORD_FORMS = new Set(["signup", "change_password"]);

function emptyText(init: MenuInit): string {
  if (init.formKind === "card") return tr("Aucune carte dans OnePass", "No card in OnePass");
  if (init.formKind === "identity" || init.formKind === "address") return tr("Aucune identité dans OnePass", "No identity in OnePass");
  return tr(`Aucun login pour ${hostOf(init.origin)}`, `No login for ${hostOf(init.origin)}`);
}

function hintFor(it: Summary): string {
  if (it.kind !== "login") return "";
  if (it.has_totp) return tr("mot de passe + code", "password + code");
  if (it.match === "exact_host") return tr("ce site exact", "this exact site");
  return "";
}

export function mountMenu(root: HTMLElement, deps: FrameDeps): MenuHandle {
  const now = deps.now ?? (() => performance.now());
  const guard = new ClickGuard({ now, ...(deps.trusted ? { trusted: deps.trusted } : {}) });
  const token = tokenFromHash(deps.hash);
  const container = h("div", { class: "menu" });
  mount(root, container);

  const send = (m: UiToBg) => deps.send(m);
  const close = () => {
    if (token) void send({ type: "menu_close", token });
  };

  let wasIntersecting = false;
  (deps.observe ?? observeVisibility)(container, (v) => {
    guard.setVisibility(v);
    // Spec 8.3: the menu closes when its frame leaves the viewport.
    if (wasIntersecting && !v.intersecting) close();
    wasIntersecting = v.intersecting;
  });

  const options = (): HTMLButtonElement[] => [...container.querySelectorAll<HTMLButtonElement>("[data-opt]")];

  const keydown = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      close();
      return;
    }
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const opts = options();
    if (opts.length === 0) return;
    const i = opts.indexOf(document.activeElement as HTMLButtonElement);
    const next = e.key === "ArrowDown" ? (i + 1) % opts.length : i <= 0 ? opts.length - 1 : i - 1;
    opts[next]?.focus();
  };
  document.addEventListener("keydown", keydown);

  const header = (origin: string | null) =>
    h("h1", { class: "menu-head" }, mark("s"), origin ? `OnePass · ${hostOf(origin)}` : "OnePass");
  const glyphTile = (name: "key" | "plus", size: number) => h("span", { class: "glyph-wrap", attrs: { "aria-hidden": "true" } }, icon(name, size));

  const showError = (line: HTMLElement | null, code: string) => {
    if (code === "locked" || code === "unpaired" || code === "host_missing") {
      renderState(code, null);
      return;
    }
    if (line) line.textContent = errorText(code);
  };

  const option = (
    label: string,
    sub: string | null,
    lead: Element,
    hint: string,
    act: () => Promise<void>,
  ): HTMLButtonElement =>
    h(
      "button",
      {
        class: "row",
        attrs: { type: "button", role: "option", "data-opt": "" },
        on: { click: guard.wrap(() => void act()) },
      },
      lead,
      h("span", { class: "stack" }, h("span", { class: "t1" }, label), sub ? h("span", { class: "t2" }, sub) : null),
      hint ? h("span", { class: "hint" }, hint) : null,
    );

  function renderState(code: string, origin: string | null): void {
    let body: HTMLElement;
    if (code === "locked") {
      const btn = h(
        "button",
        {
          class: "btn btn-primary",
          attrs: { type: "button", "data-opt": "" },
          on: {
            click: guard.wrap(() => {
              if (!token) return;
              void call(deps.send, { type: "menu_unlock", token }, parseLocked).then((r) => {
                if (r.ok && !r.value.locked) void load();
                else if (!r.ok) renderState(r.code, origin);
              });
            }),
          },
        },
        tr("Déverrouiller dans OnePass", "Unlock in OnePass"),
      );
      body = messageBlock(tr("OnePass est verrouillé", "OnePass is locked"), undefined, btn);
    } else if (code === "unpaired") {
      body = messageBlock(tr("Appairer OnePass depuis la barre d'outils", "Pair OnePass from the toolbar"));
    } else if (code === "host_missing") {
      body = messageBlock(
        tr("App OnePass introuvable", "OnePass app not found"),
        tr("Ouvre l'app OnePass sur cet ordinateur, puis réessaie.", "Open the OnePass app on this computer, then try again."),
      );
    } else {
      body = messageBlock(errorText(code));
    }
    mount(container, header(origin), body);
    guard.reset();
  }

  function render(init: MenuInit): void {
    const errLine = h("p", { class: "error-line", attrs: { role: "alert" } });
    const list = h("div", { class: "menu-list" });
    const pick = (itemId: string) => async () => {
      if (!token) return;
      const r = await call(deps.send, { type: "menu_pick", token, itemId }, parseEmpty);
      if (!r.ok) showError(errLine, r.code);
    };
    const signin = (itemId: string, provider: ProviderId) => async () => {
      if (!token) return;
      const r = await call(deps.send, { type: "menu_signin", token, itemId, provider }, parseEmpty);
      if (!r.ok) showError(errLine, r.code);
    };
    // On a provider's chooser: the account linked to the site comes first.
    const linked = init.linked;
    const items = linked ? [...init.items].sort((a, b) => Number(b.item_id === linked.itemId) - Number(a.item_id === linked.itemId)) : init.items;
    for (const it of items) {
      const providerOnly = it.kind === "login" && !it.has_password && it.methods.length > 0;
      if (!providerOnly) {
        const hint = linked?.itemId === it.item_id ? tr(`Utilisé pour ${linked.site}`, `Used for ${linked.site}`) : hintFor(it);
        list.append(option(it.title, it.subtitle, itemArt(it, "s"), hint, pick(it.item_id)));
      }
      if (it.kind === "login" && LOGIN_FORMS.has(init.formKind)) {
        for (const m of it.methods) {
          list.append(
            option(
              tr(`Se connecter avec ${providerLabel(m.provider)} (${m.account_email})`, `Sign in with ${providerLabel(m.provider)} (${m.account_email})`),
              it.title,
              itemArt(it, "s"),
              tr("compte lié", "linked account"),
              signin(it.item_id, m.provider),
            ),
          );
        }
      }
    }
    const empty = init.items.length === 0 ? h("p", { class: "message-detail empty" }, emptyText(init)) : null;
    const extras: HTMLElement[] = [];
    if (NEW_PASSWORD_FORMS.has(init.formKind)) {
      extras.push(h("div", { class: "sep", attrs: { "aria-hidden": "true" } }));
      extras.push(
        option(tr("Générer un mot de passe", "Generate a password"), null, glyphTile("key", 16), "", async () => {
          if (!token) return;
          const r = await call(deps.send, { type: "menu_generate", token }, parseEmpty);
          if (!r.ok) showError(errLine, r.code);
        }),
      );
    }
    if (LOGIN_FORMS.has(init.formKind)) {
      // Spec 8.3; the save prompt opens in its edit view (nothing typed is read from the page).
      if (extras.length === 0) extras.push(h("div", { class: "sep", attrs: { "aria-hidden": "true" } }));
      extras.push(
        option(tr("Enregistrer un nouveau login", "Save a new login"), null, glyphTile("plus", 12), "", async () => {
          if (!token) return;
          const r = await call(deps.send, { type: "menu_new_login", token }, parseEmpty);
          if (!r.ok) showError(errLine, r.code);
        }),
      );
    }
    // Only options (and decorative separators) inside the listbox.
    const listbox =
      list.childElementCount + extras.length > 0
        ? h("div", { class: "menu-options", attrs: { role: "listbox", "aria-label": tr("Suggestions OnePass", "OnePass suggestions") } }, list, ...extras)
        : null;
    mount(container, header(init.origin), empty, listbox, errLine);
    guard.reset();
  }

  async function load(): Promise<void> {
    if (!token) {
      renderState("invalid", null);
      return;
    }
    const r = await call(deps.send, { type: "menu_init", token }, parseMenuInit);
    if (r.ok) render(r.value);
    else renderState(r.code, null);
  }

  mount(container, header(null));
  return { ready: load() };
}

// Entry point in the extension (not under test, where `ext` is absent).
if (typeof document !== "undefined" && ext?.runtime?.id) {
  const root = document.getElementById("root");
  if (root) mountMenu(root, { send: (m) => ext.runtime.sendMessage(m), hash: location.hash });
}
