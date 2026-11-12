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
import type { MenuKey, ProviderId, SignupMode, SuggestionPreview, UiToBg } from "../shared/messages";
import { NEW_PASSWORD_FORMS } from "../shared/messages";
import { t, tn } from "../shared/i18n";
import { CUSTOM_MAX_LENGTH, CUSTOM_MIN_LENGTH, type MenuInit, type ProviderChoice, type SignInChoice, type Summary } from "../shared/ui";
import {
  ClickGuard,
  type FrameDeps,
  accountNotes,
  autosize,
  call,
  errorText,
  h,
  hostOf,
  icon,
  type IconName,
  mark,
  markTouch,
  passwordRuns,
  messageBlock,
  mount,
  observeVisibility,
  otherAccounts,
  providerGlyph,
  providerLabel,
  realTimers,
  UNLOCK_POLL_MS,
  UNLOCK_WAIT_TRIES,
  siteTile,
  tokenFromHash,
  wayArt,
  wayTile,
} from "./components";
import { parseEmpty, parseKeys, parseLocked, parseMenuInit, parseNativeVaultState, parseSuggestionPreview, type NativeVaultState } from "./parse";

export interface MenuHandle {
  /** Resolves once the first render is done. */
  ready: Promise<void>;
}

const LOGIN_FORMS = new Set(["login", "signup", "change_password", "otp"]);

function emptyText(init: MenuInit): string {
  if (init.formKind === "card") return t("menu.noCardInOnepass");
  if (init.formKind === "identity" || init.formKind === "address") return t("menu.noIdentityInOnepass");
  return t("menu.noLoginForHost", { host: hostOf(init.origin) });
}

/** How a password login signs in, after its username. */
function methodOf(it: Summary): string {
  if (it.kind !== "login") return "";
  return it.has_totp ? t("menu.passwordAndCode") : t("menu.password");
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

  // One selection: the row under the pointer is the highlighted row (the
  // relayed arrows go on from it), never a hover tint beside a key highlight.
  container.addEventListener("mousemove", (e) => {
    const row = (e.target as Element | null)?.closest?.("[data-opt]");
    const i = row ? options().indexOf(row as HTMLButtonElement) : -1;
    if (i >= 0 && i !== active) highlight(i);
  });
  container.addEventListener("mouseleave", () => {
    active = -1;
    for (const o of options()) {
      o.classList.remove("active");
      o.setAttribute("aria-selected", "false");
    }
  });

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

  /** The OnePass mark and the site on the left, how many logins it has on the right. */
  const header = (origin: string | null, logins?: number) =>
    h(
      "h1",
      { class: "menu-head" },
      mark("s"),
      h("span", { class: "menu-host" }, origin ? hostOf(origin) : "OnePass"),
      logins ? h("span", { class: "menu-count" }, tn("menu.loginCount", logins, { n: logins })) : null,
    );
  const glyphTile = (name: IconName, size: number) => h("span", { class: "glyph-wrap", attrs: { "aria-hidden": "true" } }, icon(name, size));

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
    /** After `post`: the account label, the associated-site hint (`accountNotes`). */
    notes?: Node[];
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
              ...(o.notes ?? []),
            )
          : null,
      ),
      o.act ? h("span", { class: o.accent ? "act hint" : "act" }, o.act) : null,
    );
    b.addEventListener("op-activate", fire);
    return b;
  };

  /** What the worker says while an unlock asked for this menu is still pending. */
  const WAITING: ReadonlySet<string> = new Set(["locked", "host_missing", "timeout"]);
  /** Bumped by each wait and each render over it: a check of an older wait does nothing. */
  let waitSeq = 0;

  /**
   * The app was asked to unlock for this menu (by the gesture that opened it, or by its button):
   * it came forward on its lock screen, or is still starting. Say which, ask the worker every
   * second, and let it resume the fill the moment the vault opens (it closes this menu). After
   * the shared deadline (90 s), the button again.
   */
  function waitForUnlock(origin: string | null, code: string): void {
    const seq = ++waitSeq;
    let shown = "";
    const say = (c: string): void => {
      const now = c === "locked" ? "locked" : "host_missing";
      if (now === shown) return;
      shown = now;
      mount(container, header(origin), messageBlock(t(now === "locked" ? "ui.unlockToContinue" : "ui.openingOnepass")));
      active = -1;
      remeasure();
    };
    say(code);
    let left = UNLOCK_WAIT_TRIES;
    const check = (): void => {
      if (!token || seq !== waitSeq) return;
      void call(deps.send, { type: "menu_resume", token }, parseEmpty).then((r) => {
        // Resumed: the worker closed this menu and runs its field's plan.
        if (seq !== waitSeq || r.ok) return;
        if (!WAITING.has(r.code)) {
          // Refused (too late, the page changed): the menu as it now is.
          void load();
          return;
        }
        if (--left > 0) {
          // Launched, then locked: the app's unlock shows now.
          say(r.code);
          timers.setTimeout(check, UNLOCK_POLL_MS);
        } else renderState(r.code === "locked" ? "locked_plain" : "host_missing_plain", origin);
      });
    };
    timers.setTimeout(check, UNLOCK_POLL_MS);
  }

  /**
   * A menu that finds the vault locked or the app missing asks the worker whether an unlock is
   * already under way for it: the trusted gesture that opened it (the icon, the command) asked
   * the app at once. Then it waits and resumes with no second click; if the vault opened
   * meanwhile, the worker resumes right here. No such request: `plain`, the state with its button.
   */
  async function resumeOrAsk(code: "locked" | "host_missing", origin: string | null): Promise<void> {
    if (!token) return renderState(`${code}_plain`, origin);
    const seq = ++waitSeq;
    const r = await call(deps.send, { type: "menu_resume", token }, parseEmpty);
    if (seq !== waitSeq || r.ok) return;
    if (WAITING.has(r.code)) waitForUnlock(origin, r.code);
    else renderState(`${code}_plain`, origin);
  }

  /**
   * The button of a locked or missing app, a click of its own: the worker brings the app forward
   * (launching it if needed) and asks it to unlock. Open already: the fill resumes, or the menu
   * loads. Else the menu waits. Not opened: the button stays, with what to do.
   */
  const askButton = (label: string, code: "locked" | "host_missing", origin: string | null): HTMLButtonElement =>
    h(
      "button",
      {
        class: "btn btn-primary",
        attrs: { type: "button", "data-opt": "" },
        on: {
          click: guard.wrap(() => {
            if (!token) return;
            void call(deps.send, { type: "menu_unlock", token }, parseLocked).then(async (r) => {
              if (r.ok && r.value.locked) waitForUnlock(origin, code);
              else if (r.ok) {
                const done = await call(deps.send, { type: "menu_resume", token }, parseEmpty);
                if (!done.ok) void load();
              } else renderState(r.code === "locked" || r.code === "host_missing" ? `${r.code}_plain` : r.code, origin);
            });
          }),
        },
      },
      label,
    );

  /** Face ID ran once by itself in this menu: never again without a tap (no loop). */
  let autoBiometricDone = false;
  /** A biometric or password unlock is running: the buttons wait. */
  let unlocking = false;

  /**
   * iOS (spec 2026-11-03-ios-safari-autofill 5): the menu turns into the unlock sheet. Face ID
   * (or Touch ID) runs once by itself when the policy allows it, the explicit button after;
   * the master password always works. Unlocked, the menu loads and the fill goes on.
   */
  function renderUnlock(v: NativeVaultState, origin: string | null): void {
    const errLine = h("p", { class: "error-line", attrs: { role: "alert" } });
    const reason = v.error ? unlockErrorText(v) : "";
    if (reason) errLine.textContent = reason;
    const after = (r: Awaited<ReturnType<typeof callVault>>): void => {
      unlocking = false;
      if (!r.ok) {
        renderState(r.code === "locked" ? "locked_plain" : r.code, origin);
        return;
      }
      if (!r.value.locked) {
        // A tap, the password, or the automatic Face ID of a menu a trusted gesture opened (the
        // icon, the command): the worker already closed the menu and resumed the fill (the menu's
        // token died, this load finds nothing). The automatic Face ID of any other menu is no
        // gesture: the menu loads and the user picks.
        void load();
        return;
      }
      renderUnlock(r.value, origin);
    };
    const biometric = (auto = false): void => {
      if (unlocking || !token) return;
      unlocking = true;
      void callVault(auto ? { type: "menu_unlock_biometric", token } : { type: "menu_unlock_biometric", token, gesture: true }).then(after);
    };
    const input = h("input", {
      class: "input unlock-input",
      attrs: {
        type: "password",
        autocomplete: "off",
        autocapitalize: "off",
        spellcheck: "false",
        enterkeyhint: "go",
        "aria-label": t("unlock.masterPassword"),
        placeholder: t("unlock.masterPassword"),
      },
    });
    const submit = (e?: Event): void => {
      e?.preventDefault();
      if (unlocking || !token || input.value.length === 0) return;
      unlocking = true;
      const password = input.value;
      input.value = "";
      void callVault({ type: "menu_unlock_password", token, password }).then(after);
    };
    const kind = v.biometry === "none" ? null : v.biometry;
    const bioButton = kind
      ? h(
          "button",
          { class: "btn btn-primary unlock-bio", attrs: { type: "button" }, on: { click: guard.wrap(() => biometric()) } },
          icon(kind === "touchID" ? "touchid" : "faceid", 18),
          t(kind === "touchID" ? "unlock.withTouchId" : kind === "opticID" ? "unlock.withOpticId" : "unlock.withFaceId"),
        )
      : null;
    const form = h(
      "form",
      { class: "unlock-form", on: { submit } },
      input,
      h("button", { class: kind ? "btn" : "btn btn-primary", attrs: { type: "submit" } }, t("unlock.unlock")),
    );
    const body = h(
      "div",
      { class: "unlock-sheet" },
      h("span", { class: "unlock-mark" }, mark("l")),
      h("p", { class: "message-title" }, t("ui.onepassLocked")),
      v.account ? h("p", { class: "message-detail unlock-account" }, v.account) : null,
      bioButton,
      form,
      v.message && v.error === "password_required" ? h("p", { class: "message-detail" }, v.message) : null,
      errLine,
    );
    mount(container, header(origin), body);
    active = -1;
    guard.reset();
    remeasure();
    // One automatic try per menu, and never after the policy asked for the password.
    if (kind && !autoBiometricDone && !v.error) {
      autoBiometricDone = true;
      biometric(true);
    } else if (!kind) input.focus();
  }

  const callVault = (m: UiToBg) => call(deps.send, m, parseNativeVaultState);

  function unlockErrorText(v: NativeVaultState): string {
    switch (v.error) {
      case "wrong_password":
        return t("unlock.wrongPassword");
      case "locked_out":
        return v.message ?? t("unlock.lockedOut");
      case "password_required":
        return t("unlock.passwordRequired");
      case "no_account":
        return t("unlock.noAccount");
      case "failed":
        return v.message ?? errorText("internal");
      default:
        return "";
    }
  }

  function renderState(code: string, origin: string | null): void {
    let body: HTMLElement;
    if (code === "locked" && token) {
      // iOS has a native vault: the sheet. Elsewhere the app unlocks: asked already, or its button.
      const asked = token;
      const seq = ++waitSeq;
      void callVault({ type: "menu_vault", token: asked }).then((r) => {
        if (seq !== waitSeq) return;
        if (r.ok && r.value.locked) renderUnlock(r.value, origin);
        else if (r.ok) void load();
        else void resumeOrAsk("locked", origin);
      });
      return;
    }
    if (code === "host_missing" && token) {
      // The app is not running: launched already by the gesture that opened this menu, or its button.
      void resumeOrAsk("host_missing", origin);
      return;
    }
    waitSeq++;
    if (code === "locked" || code === "locked_plain") {
      body = messageBlock(t("ui.onepassLocked"), undefined, askButton(t("menu.unlockInOnepass"), "locked", origin));
    } else if (code === "unpaired") {
      // Pairing happens in the popup: the button opens it (its own window where the browser cannot).
      const btn = h(
        "button",
        {
          class: "btn btn-primary",
          attrs: { type: "button", "data-opt": "" },
          on: {
            click: guard.wrap(() => {
              if (!token) return;
              void call(deps.send, { type: "menu_pair", token }, parseEmpty).then((r) => {
                if (!r.ok) renderState(r.code, origin);
              });
            }),
          },
        },
        t("popup.pairWithOnepass"),
      );
      body = messageBlock(t("popup.onepassNotPaired"), undefined, btn);
    } else if (code === "host_missing" || code === "host_missing_plain") {
      body = messageBlock(t("ui.onepassAppNotFound"), t("menu.openOnepassAppOn"), askButton(t("menu.openOnepass"), "host_missing", origin));
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
    waitSeq++;
    const errLine = h("p", { class: "error-line", attrs: { role: "alert" } });
    // A plan opened this menu because the page refused every generated password.
    if (init.notice) errLine.textContent = errorText(init.notice);
    const list = h("div", { class: "menu-group menu-list" });
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
    const fill = t("common.fill");
    // One-click signup on a form that can make a passkey: the two ways, asked first (spec 2.3).
    if (init.signup?.passkey) {
      const signup = (mode: SignupMode) => async () => {
        if (!token) return;
        const r = await call(deps.send, { type: "menu_signup", token, mode }, parseEmpty);
        if (!r.ok) showError(errLine, r.code);
      };
      list.append(
        option({
          label: t("menu.signupWithPassword"),
          sub: t("menu.signupWithPasswordDetail"),
          lead: glyphTile("key", 16),
          act: fill,
          accent: true,
          attrs: { "data-signup": "password" },
          run: signup("password"),
        }),
        option({
          label: t("menu.signupWithPasskey"),
          sub: t("menu.signupWithPasskeyDetail"),
          lead: glyphTile("shield", 14),
          act: t("common.continue"),
          attrs: { "data-signup": "passkey" },
          run: signup("passkey"),
        }),
      );
    }
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
            notes: accountNotes(it),
            // Logins show the site's icon (the pill's source); cards and identities their art.
            lead: it.kind === "login" ? siteTile(init.origin, it.icon_letter, 32) : wayArt(it, undefined),
            act: isLinked ? t("menu.usedForSite", { site: linked.site }) : fill,
            // The best item of a plan that could not choose (listed first by the worker).
            accent: isLinked || init.best === it.item_id,
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
            pre: t("menu.withName", { name }),
            sub: def?.email ?? m.account_email,
            notes: accountNotes(it),
            lead: wayTile(init.origin, it.icon_letter, m.provider, 32),
            act: t("common.continue"),
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
    // On a sign-up form the strong password comes first, above the logins the site already has
    // (they stay reachable below); the passkey choice, when offered, already leads the list.
    const lead: HTMLElement[] = [];
    let panel: HTMLElement | null = null;
    if (NEW_PASSWORD_FORMS.has(init.formKind)) {
      const first = init.formKind === "signup" && !init.signup?.passkey;
      const generate = async () => {
        if (!token) return;
        const r = await call(deps.send, { type: "menu_generate", token }, parseEmpty);
        if (!r.ok) showError(errLine, r.code);
      };
      if (suggestion) {
        // The preview of the held password (mockup B): Use fills that very one.
        const row = suggestRow(generate, first);
        const other = option({
          label: t("menu.otherSuggestion"),
          lead: glyphTile("refresh", 14),
          cls: "row-quiet",
          attrs: { "data-action": "other" },
          run: () => redraw({ type: "menu_regenerate", token: token ?? "" }),
        });
        const more = option({
          label: t("menu.lengthAndCharacters"),
          lead: glyphTile("more", 14),
          cls: "row-quiet",
          attrs: { "data-action": "length", "aria-expanded": String(lengthOpen) },
          run: () => {
            lengthOpen = !lengthOpen;
            const at = active;
            render(init);
            if (at >= 0) highlight(at);
          },
        });
        (first ? lead : extras).push(row, other, more);
        if (lengthOpen) panel = lengthPanel();
      } else {
        (first ? lead : extras).push(
          option({
            label: t("menu.generatePassword"),
            lead: glyphTile("key", 16),
            ...(first ? { act: fill, accent: true } : {}),
            run: generate,
          }),
        );
      }
    }
    if (LOGIN_FORMS.has(init.formKind)) {
      // Spec 8.3; the save prompt opens in its edit view (nothing typed is read from the page).
      extras.push(
        option({
          label: t("menu.saveNewLogin"),
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
    // Only options inside the listbox: the logins in one inset group, the other actions in a second.
    const groups = [
      lead.length > 0 ? h("div", { class: "menu-group menu-lead" }, ...lead) : null,
      list.childElementCount > 0 ? list : null,
      extras.length > 0 ? h("div", { class: "menu-group menu-foot" }, ...extras) : null,
    ];
    const listbox =
      lead.length + list.childElementCount + extras.length > 0
        ? h("div", { class: "menu-options", attrs: { role: "listbox", "aria-label": t("menu.onepassSuggestions") } }, ...groups)
        : null;
    const logins = init.items.filter((x) => x.kind === "login").length;
    mount(container, header(init.origin, logins), empty, listbox, panel, errLine);
    active = -1;
    guard.reset();
    remeasure();
  }

  /** The held suggestion of this menu's field (`menu_preview`); null: the plain Generate row. */
  let suggestion: SuggestionPreview | null = null;
  let lengthOpen = false;
  /** The panel's own values: the length asked, and whether symbols are on. */
  let profile = { length: 16, symbols: true };
  /** Newest redraw only: an older answer never overwrites a newer one. */
  let drawSeq = 0;
  let pwEl: HTMLElement | null = null;
  let barEl: HTMLElement | null = null;
  let lineEl: HTMLElement | null = null;
  let lenEl: HTMLElement | null = null;
  /** The error line of the list on screen. */
  let lastErr: HTMLElement | null = null;

  const strengthLine = (p: SuggestionPreview) =>
    p.strength >= 3 ? t("menu.suggestStrong", { n: p.length }) : `${t(p.strength === 0 ? "popup.weak" : "popup.fair")}, ${p.length}`;

  /** Writes the current suggestion into the row's parts (the row itself stays, so does the focus). */
  const paint = () => {
    const p = suggestion;
    if (!p) return;
    if (pwEl) pwEl.replaceChildren(...passwordRuns(p.password));
    if (barEl) [...barEl.children].forEach((seg, i) => seg.classList.toggle("on", i < p.strength));
    if (lineEl) lineEl.textContent = strengthLine(p);
    if (lenEl) lenEl.textContent = String(profile.length);
  };

  /** The worker redrew (other suggestion, or a new profile): show the answer, if still the newest. */
  async function redraw(m: UiToBg): Promise<void> {
    const seq = ++drawSeq;
    const r = await call(deps.send, m, parseSuggestionPreview);
    if (seq !== drawSeq) return;
    if (!r.ok) {
      showError(lastErr, r.code);
      return;
    }
    suggestion = r.value;
    // A plain redraw (other suggestion) follows the profile the worker holds; a profile draw is ours.
    if (m.type === "menu_regenerate") profile = { ...profile, length: clampLength(r.value.length) };
    paint();
  }

  const clampLength = (n: number) => Math.min(CUSTOM_MAX_LENGTH, Math.max(CUSTOM_MIN_LENGTH, n));
  const writeProfile = (length: number, symbols: boolean) => {
    profile = { length: clampLength(length), symbols };
    if (lenEl) lenEl.textContent = String(profile.length);
    if (token) void redraw({ type: "menu_profile", token, length: profile.length, symbols: profile.symbols });
  };

  /** The suggestion row: the password in mono, four strength segments, the strength line, Use. */
  function suggestRow(run: () => Promise<void>, first: boolean): HTMLButtonElement {
    pwEl = h("span", { class: "suggest-pw mono" });
    barEl = h("span", { class: "strength-bar", attrs: { "aria-hidden": "true" } }, ...[0, 1, 2, 3].map(() => h("span", { class: "strength-seg" })));
    lineEl = h("span", { class: "suggest-line" });
    const row = h(
      "button",
      {
        class: `row row-suggest${first ? "" : " row-suggest-later"}`,
        attrs: { type: "button", role: "option", "data-opt": "", "aria-selected": "false", "aria-label": t("menu.generatePassword") },
        on: { click: guard.wrap(() => void run()) },
      },
      h("span", { class: "stack" }, pwEl, barEl, lineEl),
      h("span", { class: first ? "act hint" : "act" }, t("menu.use")),
    );
    row.addEventListener("op-activate", () => void run());
    paint();
    return row;
  }

  /** "Length and characters": a stepper and the Symbols switch; each change writes the profile. */
  function lengthPanel(): HTMLElement {
    const step = (d: number, cls: string, sign: string) =>
      h(
        "button",
        {
          class: `len-step ${cls}`,
          attrs: { type: "button", "aria-label": `${t("menu.length")} ${sign}` },
          on: {
            click: guard.wrap(() => {
              const next = clampLength(profile.length + d);
              if (next !== profile.length) writeProfile(next, profile.symbols);
            }),
          },
        },
        sign,
      );
    lenEl = h("span", { class: "len-value" }, String(profile.length));
    const sw = h("button", {
      class: "len-symbols",
      attrs: { type: "button", role: "switch", "aria-checked": String(profile.symbols), "aria-label": t("menu.symbols") },
    });
    sw.addEventListener(
      "click",
      guard.wrap(() => {
        const on = !profile.symbols;
        sw.setAttribute("aria-checked", String(on));
        writeProfile(profile.length, on);
      }),
    );
    return h(
      "div",
      { class: "length-panel" },
      h("div", { class: "len-row" }, h("span", { class: "len-label" }, t("menu.length")), h("span", { class: "len-stepper" }, step(-1, "len-minus", "\u2212"), lenEl, step(1, "len-plus", "+"))),
      h("div", { class: "len-row" }, h("span", { class: "len-label" }, t("menu.symbols")), sw),
    );
  }

  /** One more account of the provider, unfolded under its method. */
  const accountOption = (a: ProviderChoice, p: ProviderId, name: string, run: () => Promise<void>) =>
    option({
      label: a.email,
      pre: `${name} · `,
      sub: a.title,
      lead: h("span", { class: "way-glyph", attrs: { "aria-hidden": "true" } }, providerGlyph(p, 14)),
      act: t("common.continue"),
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
      suggestion = null;
      if (NEW_PASSWORD_FORMS.has(r.value.formKind)) {
        const p = await call(deps.send, { type: "menu_preview", token }, parseSuggestionPreview);
        if (p.ok) {
          suggestion = p.value;
          profile = { length: clampLength(p.value.length), symbols: /[^\p{L}\p{N}\p{M}]/u.test(p.value.password) };
        }
      }
      render(r.value);
      void listenKeys();
    } else renderState(r.code, null);
  }

  mount(container, header(null));
  return { ready: load() };
}

// Entry point in the extension (not under test, where `ext` is absent).
if (typeof document !== "undefined" && ext?.runtime?.id) {
  markTouch(document);
  const root = document.getElementById("root");
  if (root) mountMenu(root, { send: (m) => ext.runtime.sendMessage(m), hash: location.hash });
}
