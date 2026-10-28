// Inline menu (spec 8.3, Inline mockup): `menu.html#<token>` under a field.
// The menu asks the service worker for its summaries with its token and
// asks it to fill; it never sees a secret.
//
// One row per way to sign in, each with one action: a password login fills
// the form ("Remplir"); a login through a provider runs the one-click chain
// ("Continuer"), and says which provider account it uses. When the vault has
// several accounts of that provider, "Autre compte <fournisseur>" unfolds
// them inline. The frame is sized to the content (the page reports its
// height), and the keyboard works from the page's field: the content script
// relays the arrows and Return to the worker, the menu asks for them
// (`menu_keys`), and the focus stays in the page.
import { ext } from "../shared/browser";
import type { MenuKey, ProviderId, UiToBg } from "../shared/messages";
import { tr } from "../shared/i18n";
import type { MenuInit, ProviderChoice, SignInChoice, Summary } from "../shared/ui";
import {
  ClickGuard,
  type FrameDeps,
  autosize,
  call,
  errorText,
  h,
  hostOf,
  icon,
  mark,
  messageBlock,
  mount,
  observeVisibility,
  otherAccounts,
  providerGlyph,
  providerLabel,
  realTimers,
  tokenFromHash,
  wayArt,
} from "./components";
import { parseEmpty, parseKeys, parseLocked, parseMenuInit } from "./parse";

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

/** How a password login signs in, after its username. */
function methodOf(it: Summary): string {
  if (it.kind !== "login") return "";
  return it.has_totp ? tr("mot de passe et code", "password and code") : tr("mot de passe", "password");
}

/** An empty `menu_keys` answer sooner than this: ask again only after it. */
const KEYS_BACKOFF_MS = 1000;

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
  // The frame takes the content's height.
  const remeasure = autosize(
    container,
    (height) => {
      if (token) void send({ type: "menu_resize", token, height });
    },
    deps.observeSize,
  );

  let wasIntersecting = false;
  (deps.observe ?? observeVisibility)(container, (v) => {
    guard.setVisibility(v);
    // Spec 8.3: the menu closes when its frame leaves the viewport.
    if (wasIntersecting && !v.intersecting) close();
    wasIntersecting = v.intersecting;
  });

  const options = (): HTMLButtonElement[] => [...container.querySelectorAll<HTMLButtonElement>("[data-opt]")];
  /** Row highlighted by the relayed arrows (the focus stays in the page). */
  let active = -1;
  const highlight = (i: number) => {
    const opts = options();
    active = opts.length === 0 ? -1 : (i + opts.length) % opts.length;
    opts.forEach((o, j) => {
      o.classList.toggle("active", j === active);
      o.setAttribute("aria-selected", String(j === active));
    });
    opts[active]?.scrollIntoView?.({ block: "nearest" });
  };

  const relayed = (key: MenuKey) => {
    const opts = options();
    if (opts.length === 0) return;
    if (key === "down") highlight(active < 0 ? 0 : active + 1);
    else if (key === "up") highlight(active < 0 ? opts.length - 1 : active - 1);
    // Return: the same rules as a click, but the key was trusted in the page.
    else if (active >= 0 && guard.ready()) opts[active]?.dispatchEvent(new CustomEvent("op-activate"));
  };
  const timers = deps.timers ?? realTimers;
  /** Asks the worker for relayed keys until the menu goes (its token is then refused). */
  const listenKeys = async (): Promise<void> => {
    if (!token) return;
    const asked = now();
    const r = await call(deps.send, { type: "menu_keys", token }, parseKeys);
    if (!r.ok) return;
    for (const k of r.value.keys) relayed(k);
    if (r.value.keys.length > 0 || now() - asked >= KEYS_BACKOFF_MS) void listenKeys();
    else timers.setTimeout(() => void listenKeys(), KEYS_BACKOFF_MS);
  };

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

  interface OptionSpec {
    label: string;
    /** Second line: `sub` (the account) after an optional muted `pre` ("Google · "), then `post` (" · mot de passe"). */
    sub?: string;
    pre?: string;
    post?: string;
    lead: Element;
    /** What the row does ("Remplir", "Continuer"), or a hint ("Utilisé pour …"). */
    act?: string;
    accent?: boolean;
    cls?: string;
    attrs?: Record<string, string>;
    run: () => Promise<void> | void;
  }

  const option = (o: OptionSpec): HTMLButtonElement => {
    const fire = () => void o.run();
    const b = h(
      "button",
      {
        class: `row${o.cls ? ` ${o.cls}` : ""}`,
        attrs: { type: "button", role: "option", "data-opt": "", "aria-selected": "false", ...o.attrs },
        on: { click: guard.wrap(fire) },
      },
      o.lead,
      h(
        "span",
        { class: "stack" },
        h("span", { class: "t1" }, o.label),
        o.sub !== undefined || o.pre
          ? h(
              "span",
              { class: "line2" },
              o.pre ? h("span", { class: "meta" }, o.pre) : null,
              o.sub !== undefined ? h("span", { class: "t2" }, o.sub) : null,
              o.post ? h("span", { class: "meta" }, o.post) : null,
            )
          : null,
      ),
      o.act ? h("span", { class: o.accent ? "act hint" : "act" }, o.act) : null,
    );
    b.addEventListener("op-activate", fire);
    return b;
  };

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
    active = -1;
    guard.reset();
    remeasure();
  }

  /** Provider methods unfolded to show their other accounts (by item and provider). */
  const unfolded = new Set<string>();

  function render(init: MenuInit): void {
    const errLine = h("p", { class: "error-line", attrs: { role: "alert" } });
    const list = h("div", { class: "menu-list" });
    const pick = (itemId: string) => async () => {
      if (!token) return;
      const r = await call(deps.send, { type: "menu_pick", token, itemId }, parseEmpty);
      if (!r.ok) showError(errLine, r.code);
    };
    const signin = (itemId: string, provider: ProviderId, accountId?: string) => async () => {
      if (!token) return;
      const msg: UiToBg = { type: "menu_signin", token, itemId, provider };
      if (accountId !== undefined) msg.accountId = accountId;
      const r = await call(deps.send, msg, parseEmpty);
      if (!r.ok) showError(errLine, r.code);
    };
    const choiceOf = (itemId: string, p: ProviderId): SignInChoice | undefined =>
      init.choices?.find((c) => c.itemId === itemId && c.provider === p);
    // On a provider's chooser: the account linked to the site comes first.
    const linked = init.linked;
    const items = linked ? [...init.items].sort((a, b) => Number(b.item_id === linked.itemId) - Number(a.item_id === linked.itemId)) : init.items;
    const fill = tr("Remplir", "Fill");
    for (const it of items) {
      const providerOnly = it.kind === "login" && !it.has_password && it.methods.length > 0;
      if (!providerOnly) {
        const isLinked = linked?.itemId === it.item_id;
        const post = methodOf(it);
        list.append(
          option({
            label: it.title,
            sub: it.subtitle,
            ...(post ? { post: ` · ${post}` } : {}),
            lead: wayArt(it, undefined),
            act: isLinked ? tr(`Utilisé pour ${linked.site}`, `Used for ${linked.site}`) : fill,
            accent: isLinked,
            run: pick(it.item_id),
          }),
        );
      }
      if (it.kind !== "login" || !LOGIN_FORMS.has(init.formKind)) continue;
      for (const m of it.methods) {
        const name = providerLabel(m.provider);
        const c = choiceOf(it.item_id, m.provider);
        const def = c?.accounts.find((a) => a.itemId === c.accountId);
        list.append(
          option({
            label: it.title,
            pre: tr(`Avec ${name} · `, `With ${name} · `),
            sub: def?.email ?? m.account_email,
            lead: wayArt(it, m.provider),
            act: tr("Continuer", "Continue"),
            attrs: { "data-provider": m.provider },
            run: signin(it.item_id, m.provider, def?.itemId),
          }),
        );
        const others = (c?.accounts ?? []).filter((a) => a.itemId !== c?.accountId);
        if (others.length === 0) continue;
        const key = `${it.item_id}|${m.provider}`;
        const open = unfolded.has(key);
        const toggle = option({
          label: otherAccounts(name, others.length),
          lead: h("span", { class: "way-fold", attrs: { "aria-hidden": "true" } }, icon("chevron", 10)),
          cls: `row-fold${open ? " open" : ""}`,
          attrs: { "aria-expanded": String(open) },
          run: () => {
            if (open) unfolded.delete(key);
            else unfolded.add(key);
            const at = active;
            render(init);
            if (at >= 0) highlight(at);
          },
        });
        list.append(toggle);
        if (!open) continue;
        for (const a of others) list.append(accountOption(a, m.provider, name, signin(it.item_id, m.provider, a.itemId)));
      }
    }
    const empty = init.items.length === 0 ? h("p", { class: "message-detail empty" }, emptyText(init)) : null;
    const extras: HTMLElement[] = [];
    if (NEW_PASSWORD_FORMS.has(init.formKind)) {
      extras.push(h("div", { class: "sep", attrs: { "aria-hidden": "true" } }));
      extras.push(
        option({
          label: tr("Générer un mot de passe", "Generate a password"),
          lead: glyphTile("key", 16),
          run: async () => {
            if (!token) return;
            const r = await call(deps.send, { type: "menu_generate", token }, parseEmpty);
            if (!r.ok) showError(errLine, r.code);
          },
        }),
      );
    }
    if (LOGIN_FORMS.has(init.formKind)) {
      // Spec 8.3; the save prompt opens in its edit view (nothing typed is read from the page).
      if (extras.length === 0) extras.push(h("div", { class: "sep", attrs: { "aria-hidden": "true" } }));
      extras.push(
        option({
          label: tr("Enregistrer un nouveau login", "Save a new login"),
          lead: glyphTile("plus", 12),
          cls: "row-quiet",
          run: async () => {
            if (!token) return;
            const r = await call(deps.send, { type: "menu_new_login", token }, parseEmpty);
            if (!r.ok) showError(errLine, r.code);
          },
        }),
      );
    }
    // Only options (and decorative separators) inside the listbox.
    const listbox =
      list.childElementCount + extras.length > 0
        ? h("div", { class: "menu-options", attrs: { role: "listbox", "aria-label": tr("Suggestions OnePass", "OnePass suggestions") } }, list, ...extras)
        : null;
    mount(container, header(init.origin), empty, listbox, errLine);
    active = -1;
    guard.reset();
    remeasure();
  }

  /** One more account of the provider, unfolded under its method. */
  const accountOption = (a: ProviderChoice, p: ProviderId, name: string, run: () => Promise<void>) =>
    option({
      label: a.email,
      pre: `${name} · `,
      sub: a.title,
      lead: h("span", { class: "way-glyph", attrs: { "aria-hidden": "true" } }, providerGlyph(p, 14)),
      act: tr("Continuer", "Continue"),
      cls: "row-sub",
      attrs: { "data-provider": p, "data-account": a.itemId },
      run,
    });

  async function load(): Promise<void> {
    if (!token) {
      renderState("invalid", null);
      return;
    }
    const r = await call(deps.send, { type: "menu_init", token }, parseMenuInit);
    if (r.ok) {
      render(r.value);
      void listenKeys();
    } else renderState(r.code, null);
  }

  mount(container, header(null));
  return { ready: load() };
}

// Entry point in the extension (not under test, where `ext` is absent).
if (typeof document !== "undefined" && ext?.runtime?.id) {
  const root = document.getElementById("root");
  if (root) mountMenu(root, { send: (m) => ext.runtime.sendMessage(m), hash: location.hash });
}
