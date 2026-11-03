// "Connexion en un clic" overlay (spec 8.6, Inline mockup). Three faces of
// one compact card, sized to its content:
//
// - the offer: every way to sign in on this site, each a single row that
//   says how it signs in (password, or "Avec Google · <compte>") and starts
//   the chain on a click; other accounts of a provider unfold inline;
// - the progress, in place of the card the user clicked (or under the field
//   when started from the menu): the account at the top, one line that says
//   what happens now ("Ouverture de Google…"), "Annuler" at any time;
// - the result: "Connecté" (the card then leaves by itself), or a precise
//   stop with what to do next, and "Réessayer" when trying again can help.
//
// The service worker reports the chain (polled every 500 ms while it runs);
// the overlay computes no progress of its own.
import { ext } from "../shared/browser";
import { t, tn } from "../shared/i18n";
import type { ProviderId, UiToBg } from "../shared/messages";
import type { ChainPhase, ChainView, OverlayAccount, OverlayInit, StepState, StopReason } from "../shared/ui";
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
  siteIcon,
  mount,
  observeVisibility,
  otherAccounts,
  providerGlyph,
  providerLabel,
  realTimers,
  srOnly,
  tokenFromHash,
  wayArt,
} from "./components";
import { parseEmpty, parseOverlayInit, parseOverlayState } from "./parse";

export const POLL_MS = 500;
/** "Connecté" stays this long, then the card leaves by itself. */
export const DONE_CLOSE_MS = 4000;

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

/** A step done, worded here (the worker's label is the fallback). */
export function stepText(st: ChainView["steps"][number], c: Pick<ChainView, "provider" | "email">): { label: string; detail?: string } {
  const name = c.provider ? providerLabel(c.provider) : "";
  const on = st.onProvider === true && name !== "";
  switch (st.what) {
    case "click":
      return { label: t("overlay.clickedContinueWithName", { name }) };
    case "account":
      return { label: t("overlay.accountChosenOnName", { name }), ...(c.email ? { detail: c.email } : {}) };
    case "user":
      return { label: on ? t("overlay.nameUsernameFilled", { name }) : t("chain.usernameFilled") };
    case "password":
      return { label: on ? t("overlay.namePasswordFilled", { name }) : t("chain.passwordFilled") };
    case "both":
      return { label: on ? t("overlay.nameUsernameAndPassword", { name }) : t("chain.usernameAndPasswordFilled") };
    case "otp":
      return { label: on ? t("overlay.nameCodeFilled", { name }) : t("chain.oneTimeCodeFilled") };
    default:
      return st.detail !== undefined ? { label: st.label, detail: st.detail } : { label: st.label };
  }
}

/** What to do next after a stop: one or two plain sentences. */
export function stopHint(reason: StopReason, site?: string, provider?: ProviderId): string {
  const p = provider ? providerLabel(provider) : null;
  switch (reason) {
    case "domain":
      if (p) return site ? t("overlay.domainOnlySiteAndProvider", { site, provider: p }) : t("overlay.domainOnlyThisSiteAndProvider", { provider: p });
      return site ? t("overlay.domainOnlySite", { site }) : t("overlay.domainOnlyThisSite");
    case "captcha":
      return t("overlay.onepassNeverSolvesCaptcha");
    case "push":
      return t("overlay.approveRequestOnPhone");
    case "otp":
      return t("overlay.loginHasNoOne");
    case "unknown":
      return t("overlay.onepassDoesntRecognizePage");
    case "timeout":
      return t("overlay.pageTookTooLong");
    case "locked":
      return t("overlay.unlockOnepassThenTry");
    case "repeat":
      return t("overlay.savedPasswordMayOut");
    case "account":
      return p ? t("overlay.accountPickOrSignInProvider", { provider: p }) : t("overlay.accountPickOrSignIn");
    case "user":
      return "";
  }
}

/** Stops where trying again from the site can help. */
const RETRY: ReadonlySet<StopReason> = new Set<StopReason>(["timeout", "locked"]);

const STATE_TEXT: Readonly<Record<StepState, string>> = {
  pending: t("overlay.pending"),
  active: t("overlay.inProgress"),
  done: t("overlay.done"),
  stopped: t("overlay.stopped"),
};

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
  let chainUi: { mode: "running" | "ended"; status: HTMLElement; last: string } | null = null;
  /** The way the user clicked: the progress names its account until the worker reports it. */
  let picked: OverlayAccount | null = null;
  const unfolded = new Set<string>();
  /** The other logins for this site, shown under the first one from the pill's dropdown. */
  let showAll = false;

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
  const closeOverlay = () => {
    stopPolling();
    cancelClose();
    if (token) void call(deps.send, { type: "overlay_close", token }, parseEmpty);
  };

  const show = (...children: (Node | null)[]) => {
    mount(container, ...children);
    guard.reset();
    remeasure();
  };

  const closeButton = () =>
    h(
      "button",
      { class: "btn-icon ov-close", attrs: { type: "button", "aria-label": t("common.close") }, on: { click: guard.wrap(closeOverlay) } },
      icon("close", 10),
    );

  const head = (origin: string | null) =>
    h(
      "div",
      { class: "ov-head" },
      mark("s"),
      h("h1", { class: "ov-title" }, origin ? t("overlay.signInToHost", { host: hostOf(origin) }) : t("overlay.oneClickSignIn")),
      closeButton(),
    );

  const renderMessage = (code: string) => {
    stopPolling();
    chainUi = null;
    const title =
      code === "unpaired"
        ? t("menu.pairOnepassFromToolbar")
        : code === "locked"
          ? t("ui.onepassLocked")
          : errorText(code);
    show(head(init?.origin ?? null), messageBlock(title));
  };

  const start = (a: OverlayAccount, accountId?: string, email?: string) => async () => {
    if (!token) return;
    const msg: UiToBg = { type: "overlay_start", token, itemId: a.itemId };
    if (a.provider) msg.provider = a.provider;
    if (a.provider && accountId !== undefined) msg.accountId = accountId;
    picked = email !== undefined ? { ...a, email, subtitle: email } : a;
    const r = await call(deps.send, msg, parseEmpty);
    if (!r.ok) {
      renderMessage(r.code);
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

  /** One way to sign in: a single button for the whole row. */
  const wayRow = (a: OverlayAccount, primary: boolean) => {
    const name = a.provider ? providerLabel(a.provider) : null;
    const line2 = name
      ? h("span", { class: "line2" }, h("span", { class: "meta" }, t("menu.withName", { name })), h("span", { class: "t2" }, a.email ?? a.subtitle))
      : h(
          "span",
          { class: "line2" },
          h("span", { class: "t2" }, a.subtitle),
          h("span", { class: "meta" }, a.totp ? t("overlay.passwordAndCode") : t("overlay.password")),
        );
    const tileArt = wayArt({ kind: "login", has_password: !a.provider, methods: [], icon_letter: a.iconLetter }, a.provider, "m");
    const art = a.provider ? tileArt : siteIcon(init?.origin ?? null, tileArt);
    const row = h(
      "div",
      { class: "ov-account", attrs: a.provider ? { "data-provider": a.provider } : {} },
      h(
        "button",
        { class: "row ov-row", attrs: { type: "button" }, on: { click: guard.wrap(() => void start(a, a.accountId, a.email)()) } },
        art,
        h("span", { class: "stack" }, h("span", { class: "t1" }, a.title), line2),
        h("span", { class: primary ? "pill pill-primary" : "pill" }, t("popup.signIn")),
      ),
    );
    const out: HTMLElement[] = [row];
    const others = (a.accounts ?? []).filter((x) => x.itemId !== a.accountId);
    if (!a.provider || others.length === 0 || !name) return out;
    const key = `${a.itemId}|${a.provider}`;
    const open = unfolded.has(key);
    out.push(
      h(
        "button",
        {
          class: `row row-fold${open ? " open" : ""}`,
          attrs: { type: "button", "aria-expanded": String(open) },
          on: {
            click: guard.wrap(() => {
              if (open) unfolded.delete(key);
              else unfolded.add(key);
              renderIdle();
            }),
          },
        },
        h("span", { class: "way-fold", attrs: { "aria-hidden": "true" } }, icon("chevron", 10)),
        h("span", { class: "stack" }, h("span", { class: "t1" }, otherAccounts(name, others.length))),
      ),
    );
    if (!open) return out;
    for (const x of others) {
      out.push(
        h(
          "div",
          { class: "ov-account ov-sub", attrs: { "data-provider": a.provider, "data-account": x.itemId } },
          h(
            "button",
            { class: "row ov-row row-sub", attrs: { type: "button" }, on: { click: guard.wrap(() => void start(a, x.itemId, x.email)()) } },
            h("span", { class: "way-glyph", attrs: { "aria-hidden": "true" } }, providerGlyph(a.provider, 14)),
            h("span", { class: "stack" }, h("span", { class: "t1" }, x.email), h("span", { class: "line2" }, h("span", { class: "meta" }, `${name} · `), h("span", { class: "t2" }, x.title))),
            h("span", { class: "pill" }, t("popup.signIn")),
          ),
        ),
      );
    }
    return out;
  };

  function renderIdle(): void {
    stopPolling();
    cancelClose();
    chainUi = null;
    picked = null;
    if (!init) return;
    const list = h("div", { class: "ov-accounts" });
    init.accounts.forEach((a, i) => {
      const rows = wayRow(a, i === 0);
      // Only the first login shows in the pill; the others wait behind the dropdown.
      if (i > 0 && !showAll) rows.forEach((r) => (r.hidden = true));
      list.append(...rows);
    });
    if (init.accounts.length === 0) list.append(messageBlock(t("menu.noLoginForHost", { host: hostOf(init.origin) })));
    const more = init.accounts.length - 1;
    const label = showAll ? t("overlay.hideOtherAccounts") : tn("overlay.moreOtherAccounts", more, { more });
    const dropdown =
      more > 0
        ? h(
            "button",
            {
              class: `btn-icon ov-more${showAll ? " open" : ""}`,
              attrs: { type: "button", "aria-expanded": String(showAll), "aria-label": label, title: label },
              on: {
                click: guard.wrap(() => {
                  showAll = !showAll;
                  renderIdle();
                }),
              },
            },
            icon("chevron", 10),
          )
        : null;
    // A pill: the site, the account, one button; other accounts behind the dropdown; close on hover.
    const heading = h("h1", { class: "sr-only" }, t("overlay.signInToHost", { host: hostOf(init.origin) }));
    show(h("div", { class: `ov-pill${showAll ? " ov-pill-open" : ""}` }, heading, list, dropdown, closeButton()));
  }

  /** The way the chain runs with, as in the offer's row. */
  const whoNode = (c: ChainView, action: Node) => {
    const provider = c.provider ?? picked?.provider;
    const title = c.title ?? picked?.title ?? "";
    const email = c.email ?? picked?.subtitle ?? "";
    const letter = picked?.iconLetter ?? (title.charAt(0).toUpperCase() || "O");
    const name = provider ? providerLabel(provider) : null;
    return h(
      "div",
      { class: "ov-who" },
      provider
        ? wayArt({ kind: "login", has_password: false, methods: [], icon_letter: letter }, provider, "m")
        : siteIcon(init?.origin ?? null, wayArt({ kind: "login", has_password: true, methods: [], icon_letter: letter }, undefined, "m")),
      h(
        "span",
        { class: "stack" },
        h("span", { class: "t1" }, title),
        h("span", { class: "line2" }, name ? h("span", { class: "meta" }, t("menu.withName", { name })) : null, h("span", { class: "t2" }, email)),
      ),
      action,
    );
  };

  const stepNode = (c: ChainView) => (s: ChainView["steps"][number]) => {
    const t = stepText(s, c);
    return h(
      "li",
      { class: `ov-step ${s.state}` },
      s.state === "stopped" ? icon("alert", 12) : icon("check", 10),
      h("span", { class: "ov-step-label" }, t.label),
      t.detail ? h("span", { class: "ov-step-detail" }, t.detail) : null,
      srOnly(STATE_TEXT[s.state]),
    );
  };

  const cancel = () => {
    if (!token) return;
    stopPolling();
    void call(deps.send, { type: "overlay_stop", token }, parseEmpty).then(() => closeOverlay());
  };

  const retryFor = (c: ChainView): OverlayAccount | undefined =>
    init?.accounts.find((a) => a.itemId === c.itemId && a.provider === (c.provider ?? undefined));

  /**
   * Polls arrive every 500 ms: an identical reply renders nothing; while
   * running, only the line that says what happens now changes (the card
   * keeps its size and "Annuler" stays under the pointer). The card is
   * rebuilt when the chain ends, which re-arms the click delay.
   */
  function renderChain(c: ChainView): void {
    const key = JSON.stringify(c);
    if (chainUi && chainUi.last === key) return;
    const mode = c.status === "running" ? "running" : "ended";
    if (mode === "running") {
      if (!chainUi || chainUi.mode !== "running") {
        const status = h("span", { class: "ov-status", attrs: { role: "status" } });
        const cancelBtn = h("button", { class: "btn-link ov-cancel", attrs: { type: "button" }, on: { click: guard.wrap(cancel) } }, t("common.cancel"));
        show(whoNode(c, cancelBtn), h("div", { class: "ov-now" }, h("span", { class: "spinner", attrs: { "aria-hidden": "true" } }), status));
        chainUi = { mode, status, last: "" };
      }
      chainUi.status.textContent = phaseText(c.phase, { ...c, provider: c.provider ?? picked?.provider, email: c.email ?? picked?.subtitle, title: c.title ?? picked?.title });
      chainUi.last = key;
      return;
    }
    stopPolling();
    const status = h("span", { class: "ov-status", attrs: { role: "status" } });
    const done = c.status === "done";
    // What was done; the end (done or stop) is the status line above.
    const steps = c.steps.filter((x) => (x.state === "done" || x.state === "stopped") && x.what !== "end" && !(x.what === undefined && x === c.steps.at(-1)));
    const parts: (Node | null)[] = [];
    if (done) {
      // Success is the pill again, its button turned into a check: no text, no steps.
      status.classList.add("ok", "ov-status-done");
      status.append(h("span", { class: "dot dot-done dot-big", attrs: { "aria-hidden": "true" } }, icon("check", 14)), srOnly(t("chain.signedIn")));
      parts.push(h("div", { class: "ov-pill ov-done" }, whoNode(c, status)));
    } else {
      parts.push(whoNode(c, closeButton()));
      const reason = c.reason ?? "user";
      status.classList.add("warn");
      status.append(icon("alert", 16), c.reason ? stopText(reason, c.host, c.email, c.provider) : t("chain.stopped"));
      const hint = stopHint(reason, c.site, c.provider);
      parts.push(h("div", { class: "ov-result" }, status, hint ? h("p", { class: "ov-hint" }, hint) : null));
    }
    if (!done && steps.length > 0) parts.push(h("ul", { class: "ov-steps", attrs: { "aria-label": t("overlay.stepsDone") } }, ...steps.map(stepNode(c))));
    const again = !done && c.reason && RETRY.has(c.reason) ? retryFor(c) : undefined;
    if (again) {
      parts.push(
        h(
          "div",
          { class: "ov-foot" },
          h("button", { class: "btn btn-primary", attrs: { type: "button" }, on: { click: guard.wrap(() => void start(again, again.accountId, again.email)()) } }, t("popup.tryAgain")),
        ),
      );
    }
    show(...parts);
    chainUi = { mode: "ended", status, last: key };
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
    if (r.value.chain) renderChain(r.value.chain);
    else renderIdle();
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
    init = r.value;
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
  const root = document.getElementById("root");
  if (root) mountOverlay(root, { send: (m) => ext.runtime.sendMessage(m), hash: location.hash });
}
