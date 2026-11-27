// "Connexion en un clic" overlay (spec 8.6, Inline mockup). Three faces of
// one compact card, sized to its content:
//
// - the offer: a pill with the first login (the site's icon, with the
//   provider's official mark for a "Sign in with" login, its title and the
//   account in full, never cut), a text "Se connecter" and x. The worker
//   lists first the account the page's plan would pick (the one used last
//   on this site). With exactly one other login, that login hangs under the
//   pill as a row of its own: one click signs in with it. With more,
//   "Autres identifiants" hangs there and opens a searchable list of every
//   login (arrows, Enter, pointer). When the logins live in several vaults,
//   each names its vault on a coloured chip;
// - the progress, in place of the card the user clicked (or under the field
//   when started from the menu): the account at the top, one line that says
//   what happens now ("Ouverture de Google…"), "Annuler" at any time;
// - the result: "Connecté" (the card then leaves by itself), or a precise
//   stop with what to do next, and "Réessayer" when trying again can help.
//
// A click that finds the vault locked (or the app not running) asks the app
// at once: the card then waits ("Déverrouille Cleon pour continuer",
// "Annuler"), polled like a running chain, and the worker starts or continues
// the sign-in the moment the vault opens. No second click; past the shared
// deadline the offer (or the stop with "Réessayer") comes back.
//
// A sign-in page reached with the vault locked gets a generic card: the
// vault cannot say who matches, so the card names no account and holds
// nothing of it. Its one button is the gesture: the worker unlocks, then runs
// the page's own plan (the chain for the best login, or the menu when the
// plan cannot choose). The card waits like any other and then shows what the
// worker started; with nothing to show it loads again, or leaves.
//
// The progress and result cards keep the close button detached at their
// right; everything follows the system appearance. The service
// worker reports the chain (polled every 500 ms while it runs); the overlay
// computes no progress of its own, it only lists the steps a password login
// still has ahead. While it runs the card shows one line (what happens now);
// "Détails" unfolds the steps, and the choice is kept for this browser.
//
// A card that appeared by itself on a recognised page (`auto`, no gesture) is the same pill, the
// generic card, or "Créer avec Cleon" on a signup page; it adds "Jamais sur ce site" and folds
// away AUTO_PILL_MS after it showed unless the user acted on it (its button, its list).
import { AUTO_PILL_MS } from "../shared/auto-pill";
import { ext } from "../shared/browser";
import { t, tn } from "../shared/i18n";
import type { ProviderId, UiToBg } from "../shared/messages";
import type { ChainPhase, ChainView, OverlayAccount, OverlayInit, StopReason } from "../shared/ui";
import {
  accountNotes,
  markTouch,
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
  brandTile,
  providerLabel,
  realTimers,
  siteTile,
  srOnly,
  tokenFromHash,
  vaultChip,
} from "./components";
import { type OverlayWaiting, parseEmpty, parseOverlayInit, parseOverlayStart, parseOverlayState } from "./parse";

export const POLL_MS = 500;
/** "Connecté" stays this long, then the card leaves by itself. */
export const DONE_CLOSE_MS = 1_200;
/** The notch opens in place up to this many other logins; more, and it opens the search. */
export const NOTCH_MAX = 5;
/** The closed notch shows this many of the other logins' initials. */
export const LIP_AVATARS = 3;

export const HELP_TEXT = t("overlay.oneClickRunsEvery");
/** Spec 8.6 stop reasons, word for word. */
export function stopText(reason: StopReason, host?: string, email?: string, provider?: ProviderId): string {
  switch (reason) {
    case "domain":
      return t("overlay.domainChangedValue", { value: host ?? "" }).trimEnd();
    case "captcha":
      return t("overlay.captchaDetectedTurn");
    case "push":
      return t("overlay.approveSignInOn");
    case "otp":
      return t("overlay.codeSentBySms");
    case "unknown":
      return t("overlay.unknownStepFinishBy");
    case "timeout":
      return t("overlay.n60SLimitReached");
    case "user":
      return t("chain.stopped");
    case "locked":
      return t("ui.onepassLocked");
    case "repeat":
      return t("overlay.passwordRefusedBySite");
    case "account": {
      if (!provider) return email ? t("overlay.providerDoesNotOffer", { email }) : t("overlay.accountNotFoundOnProvider");
      const p = providerLabel(provider);
      return email ? t("overlay.pDoesNotOffer", { email, p }) : t("overlay.accountNotFoundOn", { p });
    }
  }
}

/** The progress line of a running chain. */
export function phaseText(p: ChainPhase | undefined, c: Pick<ChainView, "provider" | "email" | "title">): string {
  const name = c.provider ? providerLabel(c.provider) : "";
  switch (p) {
    case "opening":
      return t("overlay.openingName", { name });
    case "choosing":
      return t("overlay.choosingValue", { value: c.email ?? "" });
    case "provider":
      return t("overlay.signingInToName", { name });
    case "back":
      return t("overlay.backToValue", { value: c.title ?? "" });
    case "code":
      return t("overlay.checkingCode");
    default:
      return t("overlay.signingIn");
  }
}

/** Stops where trying again from the site can help. */
const RETRY: ReadonlySet<StopReason> = new Set<StopReason>(["timeout", "locked"]);

/** Stops that hand the sign-in to the user (a phone, a code, a CAPTCHA, a page OnePass does not know): not a failure. */
const HANDOFF: ReadonlySet<StopReason> = new Set<StopReason>(["push", "otp", "captcha", "unknown"]);

/** How a stop reads: grey when it is the user's turn, red when the page left the site, orange otherwise. */
export type StopTone = "handoff" | "warn" | "danger";

export function stopTone(c: Pick<ChainView, "reason">): StopTone {
  const reason = c.reason ?? "user";
  if (HANDOFF.has(reason)) return "handoff";
  return reason === "domain" ? "danger" : "warn";
}

/** No answer from the app after this long: the card says it is still reaching the app. */
export const CONNECT_SLOW_MS = 1_500;

/** The app could not be reached, or refused: these can work on a second try. */
const RETRY_CODES: ReadonlySet<string> = new Set(["host_missing", "timeout", "locked", "bad_mac", "bad_frame", "internal"]);


/** What the card waits on: the app asked to unlock, the app starting, or no answer from it yet. */
type WaitKind = OverlayWaiting | "connecting";

/** After the unlock a generic card asked: polls given to the page's plan to start its chain before the card loads again. */
const PAGE_LOOKS = 6;

/** One login the card can start: a way to sign in, and the provider account it uses. */
interface Entry {
  way: OverlayAccount;
  accountId?: string;
  email?: string;
}

export interface OverlayHandle {
  ready: Promise<void>;
  /** One poll of the chain state (tests drive it). */
  poll(): Promise<void>;
}

export function mountOverlay(root: HTMLElement, deps: FrameDeps): OverlayHandle {
  const now = deps.now ?? (() => performance.now());
  const timers = deps.timers ?? realTimers;
  const guard = new ClickGuard({ now, ...(deps.trusted ? { trusted: deps.trusted } : {}) });
  const token = tokenFromHash(deps.hash);
  const container = h("div", { class: "overlay", attrs: { role: "dialog", "aria-label": t("overlay.oneClickSignIn") } });
  mount(root, container);
  (deps.observe ?? observeVisibility)(container, (v) => guard.setVisibility(v));
  const remeasure = autosize(
    container,
    (height) => {
      if (token) void call(deps.send, { type: "overlay_resize", token, height }, parseEmpty);
    },
    deps.observeSize,
  );

  let init: OverlayInit | null = null;
  let timer: unknown = null;
  let closer: unknown = null;
  /** A card that appeared by itself: the timer that folds it, and whether the user acted on it (no fold then). */
  let folder: unknown = null;
  let acted = false;
  let chainUi: { mode: "running" | "ended"; status: HTMLElement; last: string } | null = null;
  /** The way the user clicked: the progress names its account until the worker reports it. */
  let picked: OverlayAccount | null = null;
  /** The card waits for an unlock asked in the app: what it shows now (polls rebuild nothing). */
  let waitUi: { kind: WaitKind; status: HTMLElement; sub: HTMLElement } | null = null;
  /** This card came up generic (locked vault): once the vault answers with no login for the site, it leaves. */
  let wasGeneric = false;
  /** The card waited for an unlock asked for its page (generic card): once over with no chain, it loads again. */
  let pageWait = false;
  /** Looks left for the chain the page's plan may start after that unlock (the plan runs in the page, a moment later). */
  let pageLooks = 0;
  /** The picker of every login for this site ("Other logins"), open or not, and its search. */
  let pickerOpen = false;
  let query = "";

  const stopPolling = () => {
    if (timer !== null) timers.clearInterval(timer);
    timer = null;
  };
  const startPolling = () => {
    if (timer === null) timer = timers.setInterval(() => void poll(), POLL_MS);
  };
  const cancelClose = () => {
    if (closer !== null) timers.clearTimeout(closer);
    closer = null;
  };
  const stopFold = () => {
    acted = true;
    if (folder !== null) timers.clearTimeout(folder);
    folder = null;
  };
  /** Once, on the first face shown of a card that appeared by itself and that nobody touched. */
  const armFold = () => {
    if (init?.auto && !acted && folder === null) folder = timers.setTimeout(closeOverlay, AUTO_PILL_MS);
  };
  /** Closed: nothing shows again in this frame (a poll or an answer that comes late builds nothing). */
  let closed = false;
  const closeOverlay = () => {
    stopPolling();
    cancelClose();
    stopFold();
    closed = true;
    // Gone at once: the card empties before the worker answers, and stays empty whatever it says
    // (the worker removes the frame, by its token or, a token it no longer knows, by the tab).
    mount(container);
    if (token) void call(deps.send, { type: "overlay_close", token }, parseEmpty);
  };

  const show = (...children: (Node | null)[]) => {
    if (closed) return;
    mount(container, ...children);
    guard.reset();
    remeasure();
  };

  const closeButton = (run: () => void = closeOverlay) =>
    h(
      "button",
      { class: "btn-icon ov-close", attrs: { type: "button", "aria-label": t("common.close") }, on: { click: guard.wrap(run) } },
      icon("close", 10),
    );

  /** The card, with the close button detached at its right. */
  const shell = (card: HTMLElement, close: HTMLElement = closeButton()) => h("div", { class: "ov-shell" }, card, close);

  const head = (origin: string | null) =>
    shell(
      h(
        "div",
        { class: "ov-card ov-head" },
        mark("s"),
        h("h1", { class: "ov-title" }, origin ? t("overlay.signInToHost", { host: hostOf(origin) }) : t("overlay.oneClickSignIn")),
      ),
    );

  /**
   * A failure before any sign-in ran (the app missing, slow, locked, not paired): the cause in one
   * line, what to do in one sentence, and "Réessayer" when the click came from this card and a
   * second try can help.
   */
  const renderMessage = (code: string, retry?: () => void) => {
    stopPolling();
    chainUi = null;
    waitUi = null;
    const title =
      code === "unpaired"
        ? t("menu.pairOnepassFromToolbar")
        : code === "locked"
          ? t("ui.onepassLocked")
          : errorText(code);
    const again = retry && RETRY_CODES.has(code) ? retry : undefined;
    show(
      h(
        "div",
        { class: "ov-pill-wrap" },
        line(
          { tone: "warn", art: icon("alert", 16), text: title, live: true, cls: "ov-stop ov-fail", attrs: { "data-code": code } },
          again ? h("button", { class: "ov-signin", attrs: { type: "button" }, on: { click: guard.wrap(again) } }, t("popup.tryAgain")) : null,
          closeButton(),
        ),
      ),
    );
  };

  /**
   * The card's one line (the minimal card, 2026-11-21): a round tile, one sentence, then its
   * action and x. Every state but the offer is this line.
   */
  function line(
    o: { tone: StopTone | "run" | "done"; art: Node; text: string; sub?: string; live?: boolean; cls?: string; attrs?: Record<string, string> },
    ...actions: (Node | null)[]
  ): HTMLElement {
    const text = h("span", { class: "t1", attrs: o.live ? { role: "status", "aria-live": "polite" } : {} }, o.text);
    return h(
      "div",
      { class: `ov-pill ov-line ov-tone-${o.tone}${o.cls ? ` ${o.cls}` : ""}`, attrs: { "data-tone": o.tone, ...(o.attrs ?? {}) } },
      h("span", { class: "ov-alert", attrs: { "aria-hidden": "true" } }, o.art),
      h("span", { class: "stack" }, text, o.sub ? h("span", { class: "t2" }, o.sub) : null),
      ...actions,
    );
  }

  /** Runs `ask`; when the app has not answered after CONNECT_SLOW_MS, the card says it is reaching it. */
  async function reaching<T>(ask: () => Promise<T>): Promise<T> {
    const slow = timers.setTimeout(() => renderWaiting("connecting", null), CONNECT_SLOW_MS);
    try {
      return await ask();
    } finally {
      timers.clearTimeout(slow);
    }
  }

  const start = (a: OverlayAccount, accountId?: string, email?: string) => async () => {
    if (!token) return;
    stopFold();
    // The notch or the search closes with the choice: back to the plain line afterwards.
    pickerOpen = false;
    query = "";
    const msg: UiToBg = { type: "overlay_start", token, itemId: a.itemId };
    if (a.provider) msg.provider = a.provider;
    if (a.provider && accountId !== undefined) msg.accountId = accountId;
    picked = email !== undefined ? { ...a, email, subtitle: email } : a;
    const r = await reaching(() => call(deps.send, msg, parseOverlayStart));
    if (!r.ok) {
      renderMessage(r.code, () => void start(a, accountId, email)());
      return;
    }
    if (r.value.waiting) {
      // Locked, or the app not running: the click asked the app, the sign-in starts after its unlock.
      renderWaiting(r.value.waiting, null);
      startPolling();
      return;
    }
    const first: ChainView = { itemId: a.itemId, status: "running", steps: [], title: a.title, email: picked.subtitle, phase: "signin" };
    if (a.provider) {
      first.provider = a.provider;
      first.phase = "opening";
    }
    renderChain(first);
    startPolling();
  };

  /**
   * Every login the card can start: each way to sign in with its default
   * account, then the provider's other accounts for that way.
   */
  const entries = (): Entry[] => {
    const out: Entry[] = [];
    for (const a of init?.accounts ?? []) {
      out.push({ way: a, ...(a.accountId !== undefined ? { accountId: a.accountId } : {}), ...(a.email !== undefined ? { email: a.email } : {}) });
      if (!a.provider) continue;
      for (const x of a.accounts ?? []) if (x.itemId !== a.accountId) out.push({ way: a, accountId: x.itemId, email: x.email });
    }
    return out;
  };

  /** The vaults are named only when the logins of this site live in more than one. */
  const showVaults = (list: Entry[]) => new Set(list.map((e) => e.way.vault?.id ?? "")).size > 1;

  /**
   * Line 2: the account, in full. A "Sign in with" login says its provider
   * first ("Google · <email>") when the whole line fits; otherwise the email
   * alone, the mark on the icon saying the rest.
   */
  const accountLine = (e: Entry, vaults: boolean) => {
    const name = e.way.provider ? providerLabel(e.way.provider) : null;
    const who = (e.way.provider ? e.email : null) ?? e.way.subtitle;
    return h(
      "span",
      { class: "ov-line2" },
      name ? h("span", { class: "ov-via" }, `${name} · `) : null,
      h("span", { class: "ov-email" }, who),
      ...accountNotes(e.way),
      vaults && e.way.vault ? vaultChip(e.way.vault) : null,
    );
  };
  /** Drops the "Google · " prefix of the lines it would push past their width; wraps what still does not fit. */
  const fitLines = (el: HTMLElement) => {
    for (const line of el.querySelectorAll<HTMLElement>(".ov-line2")) {
      const via = line.querySelector(".ov-via");
      if (via && line.scrollWidth > line.clientWidth) via.remove();
      // Still too long: the line wraps rather than cut the account.
      if (line.scrollWidth > line.clientWidth) line.classList.add("ov-wrap");
    }
  };

  const startEntry = (e: Entry) => void start(e.way, e.accountId, e.email)();

  /** Who a login signs in: the account in full (its provider is the mark on its tile). */
  const whoOf = (e: Entry) => (e.way.provider ? (e.email ?? e.way.subtitle) : e.way.subtitle) || e.way.title;

  /**
   * The offer: one line (the site's tile, the account, "Se connecter", x). Other logins wait behind
   * the notch hanging under it: one other login is the notch itself (one click signs in with it);
   * several open in place, one row each, and a click on one signs in with it.
   */
  const renderPill = (list: Entry[], notchOpen = false) => {
    const e = list[0];
    const heading = h("h1", { class: "sr-only" }, t("overlay.signInToHost", { host: hostOf(init!.origin) }));
    if (!e) {
      show(h("div", { class: "ov-pill-wrap" }, h("div", { class: "ov-pill" }, heading, messageBlock(t("menu.noLoginForHost", { host: hostOf(init!.origin) })), closeButton())));
      return;
    }
    const pill = h(
      "div",
      { class: "ov-pill", attrs: e.way.provider ? { "data-provider": e.way.provider } : {} },
      heading,
      brandTile(init!.origin, e.way.iconLetter, e.way.provider, 32, true),
      h("span", { class: "stack" }, h("span", { class: "t1", attrs: { title: e.way.title } }, whoOf(e))),
      h(
        "button",
        {
          class: "ov-signin",
          attrs: { type: "button", "aria-label": t("overlay.signInAsOther", { account: whoOf(e) }) },
          on: { click: guard.wrap(() => startEntry(e)) },
        },
        t("popup.signIn"),
      ),
      closeButton(),
    );
    const rest = list.slice(1);
    const row = (x: Entry, cls: string) =>
      h(
        "button",
        {
          class: cls,
          attrs: {
            type: "button",
            "aria-label": t("overlay.signInAsOther", { account: whoOf(x) }),
            ...(x.way.provider ? { "data-provider": x.way.provider } : {}),
            ...(x.accountId ? { "data-account": x.accountId } : {}),
          },
          on: { click: guard.wrap(() => startEntry(x)) },
        },
        brandTile(init!.origin, x.way.iconLetter, x.way.provider, 20),
        h("span", { class: "t1", attrs: { title: x.way.title } }, whoOf(x)),
      );
    let notch: HTMLElement | null = null;
    if (rest.length === 1) notch = row(rest[0]!, "ov-others ov-other");
    else if (rest.length > 1 && notchOpen)
      notch = h(
        "div",
        { class: "ov-others ov-notch-open", attrs: { role: "group", "aria-label": t("overlay.otherLogins") } },
        ...rest.map((x) => row(x, "ov-notch-row")),
        h(
          "button",
          {
            class: "ov-notch-fold",
            attrs: { type: "button", "aria-label": t("overlay.stepsHide"), "aria-expanded": "true" },
            on: {
              click: guard.wrap(() => {
                pickerOpen = false;
                renderIdle();
              }),
            },
          },
          icon("chevron", 10),
        ),
      );
    else if (rest.length > 1)
      notch = h(
        "button",
        {
          class: "ov-others ov-lip",
          // Notch B (2026-11-21): "+N" and a chevron, nothing more; the full count for screen readers.
          attrs: { type: "button", "aria-expanded": "false", "aria-label": tn("overlay.moreOtherAccounts", rest.length, { more: rest.length }) },
          on: {
            click: guard.wrap(() => {
              stopFold();
              pickerOpen = true;
              query = "";
              renderIdle();
            }),
          },
        },
        h(
          "span",
          { class: "ov-lip-in", attrs: { "aria-hidden": "true" } },
          // Notch A+B (2026-11-21): the others' initials, up to three, then "+N" past them.
          h("span", { class: "ov-lip-avs" }, ...rest.slice(0, LIP_AVATARS).map((x) => h("span", { class: "ov-lip-av" }, (whoOf(x).charAt(0) || "?").toUpperCase()))),
          rest.length > LIP_AVATARS ? h("span", { class: "ov-lip-more" }, `+${rest.length - LIP_AVATARS}`) : null,
          icon("chevron", 10),
        ),
      );
    show(h("div", { class: "ov-pill-wrap" }, pill, notch, notchOpen ? null : neverRow()));
  };

  /** "Jamais sur ce site", under a card that appeared by itself: the worker keeps the site away and the card goes. */
  function neverRow(): HTMLElement | null {
    if (!init?.auto) return null;
    return h(
      "button",
      {
        class: "ov-others ov-never",
        attrs: { type: "button" },
        on: {
          click: guard.wrap(() => {
            stopFold();
            if (!token) return;
            void call(deps.send, { type: "overlay_never", token }, parseEmpty).then((r) => {
              if (!r.ok) renderMessage(r.code);
            });
          }),
        },
      },
      t("overlay.neverOnSite"),
    );
  }

  /**
   * "Créer avec Cleon" (a card that appeared by itself on a signup page): its click asks the
   * worker to fill the page's signup form with a strong password made with the site's rules.
   * Nothing is sent: the site's own button stays the user's. The worker then removes the card.
   */
  const renderCreate = (): void => {
    const host = hostOf(init!.origin);
    let asked = false;
    const create = async (): Promise<void> => {
      if (!token || asked) return;
      asked = true;
      stopFold();
      const r = await call(deps.send, { type: "overlay_create", token }, parseEmpty);
      if (!r.ok) renderMessage(r.code);
    };
    const pill = h(
      "div",
      { class: "ov-pill", attrs: { "data-create": "" } },
      h("h1", { class: "sr-only" }, t("overlay.createWithOnepass")),
      siteTile(init!.origin, host.charAt(0).toUpperCase(), 32, true),
      h("span", { class: "stack" }, h("span", { class: "t1", attrs: { title: t("overlay.strongPasswordForSite") } }, t("overlay.createWithOnepass"))),
      h("button", { class: "ov-signin", attrs: { type: "button" }, on: { click: guard.wrap(() => void create()) } }, t("overlay.create")),
      closeButton(),
    );
    show(h("div", { class: "ov-pill-wrap" }, pill, neverRow()));
  };

  /** "Other logins": a search field and every login, the selection moved by the keyboard or the pointer. */
  const renderPicker = (all: Entry[]) => {
    const vaults = showVaults(all);
    const input = h("input", {
      class: "ov-search",
      attrs: { type: "search", placeholder: t("overlay.findLogin"), "aria-label": t("overlay.findLogin"), "aria-controls": "ov-list", autocomplete: "off", spellcheck: "false" },
    }) as HTMLInputElement;
    input.value = query;
    const listEl = h("ul", { class: "ov-list", attrs: { id: "ov-list", role: "listbox", "aria-label": t("overlay.otherLogins") } });
    let shown: Entry[] = [];
    let sel = 0;
    const select = (i: number) => {
      sel = i;
      [...listEl.children].forEach((li, j) => {
        li.classList.toggle("selected", j === i);
        li.setAttribute("aria-selected", String(j === i));
      });
      const cur = listEl.children[i] as HTMLElement | undefined;
      if (cur) input.setAttribute("aria-activedescendant", cur.id);
      cur?.scrollIntoView?.({ block: "nearest" });
    };
    const fillList = () => {
      const q = query.trim().toLowerCase();
      shown = q ? all.filter((e) => [e.way.title, e.email ?? "", e.way.subtitle, e.way.vault?.name ?? ""].some((x) => x.toLowerCase().includes(q))) : all;
      listEl.replaceChildren(
        ...shown.map((e, i) =>
          h(
            "li",
            {
              class: "ov-opt",
              attrs: { id: `ov-opt-${i}`, role: "option", "aria-selected": "false", ...(e.way.provider ? { "data-provider": e.way.provider } : {}), ...(e.accountId ? { "data-account": e.accountId } : {}) },
              on: { click: guard.wrap(() => startEntry(e)), mouseenter: () => select(i) },
            },
            brandTile(init!.origin, e.way.iconLetter, e.way.provider, 32),
            h("span", { class: "stack" }, h("span", { class: "t1" }, e.way.title), accountLine(e, vaults)),
            h("span", { class: "ov-key", attrs: { "aria-hidden": "true" } }, icon("key", 16)),
          ),
        ),
      );
      if (shown.length === 0) listEl.append(h("li", { class: "ov-none", attrs: { role: "presentation" } }, t("overlay.noLoginMatches")));
      select(0);
      fitLines(listEl);
      remeasure();
    };
    input.addEventListener("input", () => {
      query = input.value;
      fillList();
    });
    input.addEventListener("keydown", (ev) => {
      if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
        ev.preventDefault();
        if (shown.length > 0) select((sel + (ev.key === "ArrowDown" ? 1 : shown.length - 1)) % shown.length);
      } else if (ev.key === "Enter") {
        ev.preventDefault();
        const e = shown[sel];
        if (e && guard.accepts(ev)) startEntry(e);
      } else if (ev.key === "Escape") {
        ev.preventDefault();
        pickerOpen = false;
        renderIdle();
      }
    });
    show(h("div", { class: "ov-picker" }, h("div", { class: "ov-find" }, mark("m"), input, closeButton()), h("div", { class: "ov-rule" }), listEl));
    fillList();
    input.focus();
  };

  /**
   * The generic card: the site, "Sign in with Cleon", that it is locked, one button. Its click
   * asks the worker to unlock and to run the page's plan; nothing here comes from the vault.
   */
  const renderGeneric = (): void => {
    stopPolling();
    cancelClose();
    chainUi = null;
    waitUi = null;
    picked = null;
    const host = hostOf(init!.origin);
    let asked = false;
    const unlock = async (): Promise<void> => {
      // One request per card: a second click while it is answered asks nothing more.
      if (!token || asked) return;
      asked = true;
      stopFold();
      const r = await reaching(() => call(deps.send, { type: "overlay_unlock", token }, parseOverlayStart));
      if (!r.ok) {
        renderMessage(r.code, () => {
          asked = false;
          void unlock();
        });
        return;
      }
      pageWait = true;
      pageLooks = PAGE_LOOKS;
      // Waiting for the app, or open already (the page's plan is on its way): polled either way.
      if (r.value.waiting) renderWaiting(r.value.waiting, null);
      startPolling();
    };
    const pill = h(
      "div",
      { class: "ov-pill", attrs: { "data-generic": "" } },
      h("h1", { class: "sr-only" }, t("overlay.signInToHost", { host })),
      // A letter, never the site's icon: a request to the site made only while locked would tell it so.
      siteTile(null, host.charAt(0).toUpperCase(), 32, true),
      // Nothing about the lock: the click asks Touch ID and goes on by itself.
      h("span", { class: "stack" }, h("span", { class: "t1" }, host)),
      h("button", { class: "ov-signin", attrs: { type: "button", "aria-label": t("overlay.unlockAndSignIn") }, on: { click: guard.wrap(() => void unlock()) } }, t("popup.signIn")),
      closeButton(),
    );
    show(h("div", { class: "ov-pill-wrap" }, pill, neverRow()));
  };

  function renderIdle(): void {
    stopPolling();
    cancelClose();
    chainUi = null;
    waitUi = null;
    picked = null;
    if (!init) return;
    if (pageWait) {
      // The unlock asked for the page is over and no chain runs: what the vault now says (the
      // site's logins; the menu the plan opened has already taken this card's place).
      pageWait = false;
      void load();
      return;
    }
    if (init.generic) {
      renderGeneric();
      armFold();
      return;
    }
    if (init.auto === "signup") {
      renderCreate();
      armFold();
      return;
    }
    const list = entries();
    // A card that came up locked and now finds nothing for this site has nothing to offer.
    if (wasGeneric && list.length === 0) {
      closeOverlay();
      return;
    }
    if (pickerOpen && list.length - 1 > NOTCH_MAX) renderPicker(list);
    else renderPill(list, pickerOpen && list.length > 2);
    armFold();
  }

  /** x on a running line: the card is gone at once; the worker stops the chain, then drops the card. */
  const cancel = () => {
    stopPolling();
    if (!token) {
      closeOverlay();
      return;
    }
    closed = true;
    mount(container);
    void call(deps.send, { type: "overlay_stop", token }, parseEmpty).then(() => closeOverlay());
  };

  const retryFor = (c: ChainView): OverlayAccount | undefined =>
    init?.accounts.find((a) => a.itemId === c.itemId && a.provider === (c.provider ?? undefined));

  /** The account a chain runs with, for its line. */
  const runWho = (c: ChainView | null) => c?.email ?? picked?.subtitle ?? c?.title ?? picked?.title ?? "";

  /**
   * The running line: the account, "Connexion…" under it (or what the user may have to do), and
   * x, which stops the sign-in. What happens now is said to screen readers only.
   */
  function runLine(who: string, sub: string, said: string): { el: HTMLElement; status: HTMLElement; sub: HTMLElement } {
    const status = srOnly(said);
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    const cancelBtn = h("button", { class: "btn-icon ov-close ov-cancel", attrs: { type: "button", "aria-label": t("common.cancel") }, on: { click: guard.wrap(cancel) } }, icon("close", 10));
    // No account known yet: the line itself says what happens.
    const el = line({ tone: "run", art: h("span", { class: "spinner" }), text: who || sub, sub: who ? sub : "" }, status, cancelBtn);
    return { el, status, sub: el.querySelector<HTMLElement>(".t2") ?? el.querySelector<HTMLElement>(".t1")! };
  }

  /**
   * The app was asked to unlock for this card, or is still starting: the running line, its second
   * line saying what the user may have to do (Touch ID in the app). The worker goes on by itself
   * once the vault opens; polls only change that line.
   */
  function renderWaiting(kind: WaitKind, c: ChainView | null): void {
    const said = kind === "locked" ? t("ui.unlockToContinue") : kind === "connecting" ? t("overlay.connectingToOnepass") : t("ui.openingOnepass");
    if (waitUi) {
      if (waitUi.kind !== kind) {
        waitUi.status.textContent = said;
        waitUi.sub.textContent = said;
      }
      waitUi.kind = kind;
      return;
    }
    cancelClose();
    chainUi = null;
    const r = runLine(runWho(c), said, said);
    show(h("div", { class: "ov-pill-wrap" }, r.el));
    waitUi = { kind, status: r.status, sub: r.sub };
  }

  /**
   * Polls arrive every 500 ms: an identical reply renders nothing. While it runs the card is one
   * line ("Connexion…"), nothing else to read; done, "Connecté" a moment, then it leaves. A stop
   * is one line too: the user's turn, a failure ("Réessayer" when it can help), or danger.
   */
  function renderChain(c: ChainView): void {
    waitUi = null;
    const key = JSON.stringify(c);
    if (chainUi && chainUi.last === key) return;
    const said = phaseText(c.phase, { ...c, provider: c.provider ?? picked?.provider, email: c.email ?? picked?.subtitle, title: c.title ?? picked?.title });
    if (c.status === "running") {
      if (!chainUi || chainUi.mode !== "running") {
        const r = runLine(runWho(c), t("overlay.signingIn"), said);
        show(h("div", { class: "ov-pill-wrap" }, r.el));
        chainUi = { mode: "running", status: r.status, last: "" };
      }
      chainUi.status.textContent = said;
      chainUi.last = key;
      return;
    }
    stopPolling();
    const done = c.status === "done";
    let el: HTMLElement;
    if (done) {
      el = line({ tone: "done", art: icon("check", 14), text: t("chain.signedIn"), sub: runWho(c), live: true, cls: "ov-done" });
    } else {
      const reason = c.reason ?? "user";
      const tone = stopTone(c);
      const text = c.reason ? stopText(reason, c.host, c.email, c.provider) : t("chain.stopped");
      const again = c.reason && RETRY.has(c.reason) ? retryFor(c) : undefined;
      el = line(
        { tone, art: icon(tone === "handoff" ? "phone" : "alert", 16), text, live: true, cls: "ov-stop" },
        again ? h("button", { class: "ov-signin", attrs: { type: "button" }, on: { click: guard.wrap(() => void start(again, again.accountId, again.email)()) } }, t("popup.tryAgain")) : null,
        closeButton(),
      );
    }
    show(h("div", { class: "ov-pill-wrap" }, el));
    chainUi = { mode: "ended", status: el.querySelector<HTMLElement>(".t1")!, last: key };
    cancelClose();
    // Success needs nothing more from the user: the card leaves by itself.
    if (done) closer = timers.setTimeout(closeOverlay, DONE_CLOSE_MS);
  }

  async function poll(): Promise<void> {
    if (!token) return;
    const r = await call(deps.send, { type: "overlay_state", token }, parseOverlayState);
    if (!r.ok) {
      renderMessage(r.code);
      return;
    }
    if (r.value.waiting) {
      renderWaiting(r.value.waiting, r.value.chain);
      startPolling();
    } else if (r.value.chain) {
      pageWait = false;
      renderChain(r.value.chain);
    } else if (pageWait && pageLooks-- > 0) {
      // The vault is open; the plan the page runs now may start a chain within a moment.
      startPolling();
    } else renderIdle();
  }

  async function load(): Promise<void> {
    if (!token) {
      renderMessage("invalid");
      return;
    }
    const r = await call(deps.send, { type: "overlay_init", token }, parseOverlayInit);
    if (!r.ok) {
      renderMessage(r.code);
      return;
    }
    if (init?.generic) wasGeneric = true;
    init = r.value;
    if (r.value.waiting) {
      // The chain stopped locked on this page and the app was asked: the card waits, then it goes on.
      renderWaiting(r.value.waiting, init.chain);
      startPolling();
      return;
    }
    // A chain that stopped on an earlier page keeps its reason on screen.
    if (init.chain) {
      renderChain(init.chain);
      if (init.chain.status === "running") startPolling();
    } else {
      renderIdle();
    }
  }

  show(head(null));
  return { ready: load(), poll };
}

if (typeof document !== "undefined" && ext?.runtime?.id) {
  markTouch(document);
  const root = document.getElementById("root");
  if (root) {
    mountOverlay(root, { send: (m) => ext.runtime.sendMessage(m), hash: location.hash });
  }
}
