// Inline menu (spec 8.3, Inline mockup): `menu.html#<token>` under a field.
// The menu asks the service worker for its summaries with its token and
// asks it to fill; it never sees a secret.
import { ext } from "../shared/browser";
import type { ProviderId, UiToBg } from "../shared/messages";
import type { MenuInit, Summary } from "../shared/ui";
import {
  ClickGuard,
  type FrameDeps,
  call,
  errorText,
  h,
  hostOf,
  icon,
  mark,
  messageBlock,
  mount,
  observeVisibility,
  providerLabel,
  tile,
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
  if (init.formKind === "card") return "Aucune carte dans OnePass";
  if (init.formKind === "identity" || init.formKind === "address") return "Aucune identité dans OnePass";
  return `Aucun login pour ${hostOf(init.origin)}`;
}

function hintFor(it: Summary): string {
  if (it.kind !== "login") return "";
  if (it.has_totp) return "mot de passe + code";
  if (it.match === "exact_host") return "ce site exact";
  return "";
}

export function mountMenu(root: HTMLElement, deps: FrameDeps): MenuHandle {
  const now = deps.now ?? (() => performance.now());
  const guard = new ClickGuard({ now, ...(deps.trusted ? { trusted: deps.trusted } : {}) });
  const token = tokenFromHash(deps.hash);
  const container = h("div", { class: "menu", attrs: { role: "listbox", "aria-label": "Suggestions OnePass" } });
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
    h("div", { class: "menu-head" }, mark("s"), origin ? `OnePass · ${hostOf(origin)}` : "OnePass");

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
        "Déverrouiller dans OnePass",
      );
      body = messageBlock("OnePass est verrouillé", undefined, btn);
    } else if (code === "unpaired") {
      body = messageBlock("Appairer OnePass depuis la barre d'outils");
    } else if (code === "host_missing") {
      body = messageBlock("App OnePass introuvable", "Ouvre l'app OnePass sur cet ordinateur, puis réessaie.");
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
    for (const it of init.items) {
      const providerOnly = it.kind === "login" && !it.has_password && it.methods.length > 0;
      if (!providerOnly) {
        list.append(option(it.title, it.subtitle, tile(it.icon_letter, it.icon_color, "s"), hintFor(it), pick(it.item_id)));
      }
      if (it.kind === "login" && LOGIN_FORMS.has(init.formKind)) {
        for (const m of it.methods) {
          list.append(
            option(
              `Se connecter avec ${providerLabel(m.provider)} (${m.account_email})`,
              it.title,
              tile(it.icon_letter, it.icon_color, "s"),
              "compte lié",
              signin(it.item_id, m.provider),
            ),
          );
        }
      }
    }
    if (init.items.length === 0) list.append(h("p", { class: "message-detail empty" }, emptyText(init)));
    const extras: HTMLElement[] = [];
    if (NEW_PASSWORD_FORMS.has(init.formKind)) {
      extras.push(h("div", { class: "sep" }));
      extras.push(
        option("Générer un mot de passe", null, icon("key", 16), "", async () => {
          if (!token) return;
          const r = await call(deps.send, { type: "menu_generate", token }, parseEmpty);
          if (!r.ok) showError(errLine, r.code);
        }),
      );
    }
    mount(container, header(init.origin), list, ...extras, errLine);
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
