// Toolbar popup (spec 8.8, Extension mockup, Mac app design language):
// pairing, locked and missing host states, suggestions for the active tab,
// search, item detail with copy buttons, reveal and a TOTP countdown ring,
// "Remplir", the generator with its history, and "Oublier cet appairage"
// (spec 6.4) from the main and locked views. Smart fill: the plan of the
// active tab in one line with its Fill (alternatives listed first below it),
// and "Oublier mes choix sur ce site".
import { ext } from "../shared/browser";
import { t } from "../shared/i18n";
import type { UiToBg } from "../shared/messages";
import {
  CUSTOM_MAX_LENGTH,
  CUSTOM_MIN_LENGTH,
  GENERATOR_PROFILE_KEY,
  type GeneratorEntry,
  type GeneratorKind,
  type GeneratorProfile,
  type PendingSave,
  type PopupPlanLine,
  type PopupStatus,
  type Summary,
  parseGeneratorProfile,
} from "../shared/ui";
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
  UNLOCK_POLL_MS,
  UNLOCK_WAIT_TRIES,
  siteIcon,
  siteTile,
  srOnly,
} from "./components";
import {
  parseEmpty,
  parseFilled,
  parseForgotSite,
  parseGenerated,
  parseHistory,
  parseItem,
  parseItems,
  parseLocked,
  parseNativeVaultState,
  type NativeVaultState,
  parseOutcome,
  parsePaired,
  parsePending,
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
  /** `storage.local`: the profile the extension generates with on pages (`generator_profile`). */
  storage?: {
    get(key: string): Promise<Record<string, unknown>>;
    set(items: Record<string, unknown>): Promise<void>;
  };
}

/** Choices of the profile used on pages (the worker reads it, generate.ts). */
export const PROFILE_CHOICES: readonly { value: "strong" | "readable" | "custom"; label: string }[] = [
  { value: "strong", label: t("popup.strong") },
  { value: "readable", label: t("popup.readable") },
  { value: "custom", label: t("popup.custom") },
];

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
    label: t("popup.smart"),
    help: t("popup.strongPasswordEasyTo"),
  },
  {
    kind: "random",
    label: t("popup.random"),
    help: t("popup.charactersDrawnBySystems"),
  },
  {
    kind: "memorable",
    label: t("popup.memorable"),
    help: t("popup.wordsEasyToType"),
  },
  {
    kind: "pin",
    label: t("popup.pinCode"),
    help: t("popup.digitsOnlyForCodes"),
  },
];

/** The plan line: "Se connecter en tant que tom@… en 2 étapes". */
export function planText(p: PopupPlanLine): string {
  const who = p.label;
  switch (p.intent) {
    case "login":
      if (p.mode === "fill") {
        // Fills this page, sends nothing: no promise of a sign-in.
        if (p.steps > 1) return who === "" ? t("popup.fillUsername") : t("popup.fillUsernameOfWho", { who });
        return who === ""
          ? t("popup.fillUsernameAndPassword")
          : t("popup.fillUsernameAndPassword2", { who });
      }
      if (who === "") return t("popup.signIn");
      return p.steps > 1
        ? t("popup.signInAsWho", { who, steps: p.steps })
        : t("popup.signInAsWho2", { who });
    case "otp":
      return t("popup.fillOneTimeCode");
    case "signup":
      return t("popup.createAccountWithGenerated");
    case "reset":
      return who === "" ? t("popup.changePassword") : t("popup.changePasswordOfWho", { who });
    case "checkout":
      return who === "" ? t("popup.fillPayment") : t("popup.fillPaymentWithWho", { who });
    case "address":
      return who === "" ? t("popup.fillAddress") : t("popup.fillAddressWithWho", { who });
  }
}

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
  if (bits < 40) return t("popup.weak");
  if (bits < 60) return t("popup.fair");
  if (bits < 80) return t("popup.strong");
  return t("popup.veryStrong");
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
      () => toast(t("popup.couldNotCopy"), "error"),
    );

  const button = (label: string, cls: string, fn: () => void, attrs: Record<string, string> = {}) =>
    h("button", { class: cls, attrs: { type: "button", ...attrs }, on: { click: () => fn() } }, label);
  const iconButton = (label: string, glyph: Parameters<typeof icon>[0], fn: () => void, size = 15) =>
    h("button", { class: "btn-icon", attrs: { type: "button", "aria-label": label, title: label }, on: { click: () => fn() } }, icon(glyph, size));

  // ---- full-page states ----
  // Message states (pairing, locked, missing app) get a compact popup sized to their content;
  // the list and detail views keep the full size.
  const compact = (on: boolean) => container.ownerDocument.body.classList.toggle("compact", on);
  const center = (...children: (Node | null)[]) => {
    compact(true);
    mount(container, h("div", { class: "center" }, ...children));
  };

  function renderUnpaired(err?: string): void {
    center(
      mark("l"),
      h("h1", null, t("popup.onepassNotPaired")),
      h(
        "p",
        null,
        t("popup.linkExtensionToOnepass"),
      ),
      h("div", { class: "actions" }, button(t("popup.pairWithOnepass"), "btn btn-primary", () => void track(connect()))),
      err ? h("p", { class: "error-line", attrs: { role: "alert" } }, err) : null,
    );
  }

  /**
   * "Pair with OnePass": first without a code (the app vouches for this browser by its
   * signature), then the code comparison when the app cannot.
   */
  async function connect(): Promise<void> {
    center(mark("l"), h("h1", null, t("popup.connecting")), h("p", null, t("popup.openOnepassAppIf")));
    const r = await call(deps.send, { type: "popup_pair_auto" }, parsePaired);
    if (!r.ok) {
      if (r.code === "host_missing") renderHostMissing();
      else renderUnpaired(errorText(r.code));
      return;
    }
    if (!r.value.paired) return startPairing();
    // The status says "connected" once: load shows the toast.
    await load();
  }

  async function startPairing(): Promise<void> {
    center(
      mark("l"),
      h("h1", null, t("popup.pairing")),
      h("p", null, t("popup.openOnepassAppIf")),
    );
    const r = await call(deps.send, { type: "popup_pair_start" }, parseSas);
    if (!r.ok) {
      if (r.code === "host_missing") renderHostMissing();
      else renderUnpaired(errorText(r.code));
      return;
    }
    center(
      mark("l"),
      h("h1", null, t("popup.compareCodes")),
      h("p", null, t("popup.onepassAppMustShow")),
      h("div", { class: "sas", attrs: { "aria-label": t("popup.pairingCode") } }, r.value.sas),
      h(
        "div",
        { class: "actions" },
        button(t("common.cancel"), "btn", () => {
          void call(deps.send, { type: "popup_pair_cancel" }, parseEmpty);
          renderUnpaired();
        }),
        button(t("popup.codesMatch"), "btn btn-primary", () => void track(approve())),
      ),
    );
  }

  async function approve(): Promise<void> {
    // Approving in the app closes this popup in Safari: the pairing goes on without it.
    center(
      mark("l"),
      h("h1", null, t("popup.approveInOnepassApp")),
      h(
        "p",
        null,
        t("popup.clickApproveInOnepass"),
      ),
    );
    const r = await call(deps.send, { type: "popup_pair_approve" }, parseEmpty);
    if (!r.ok) {
      renderUnpaired(errorText(r.code));
      return;
    }
    await load();
  }

  const forgetButton = () => button(t("popup.forgetPairing"), "btn-link", () => confirmForget());

  /** Confirmation step; "Annuler" goes back to the current state. */
  function confirmForget(): void {
    stopTotp();
    center(
      mark("l"),
      h("h1", null, t("popup.forgetPairing2")),
      h("p", null, t("popup.willHaveToPair")),
      h(
        "div",
        { class: "actions" },
        button(t("common.cancel"), "btn", () => void track(load())),
        button(t("popup.forget"), "btn btn-primary", () => void track(forget())),
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

  /**
   * The app came forward on its lock screen: say so, ask again every second
   * and load once unlocked. After a minute, the locked screen again.
   */
  function waitForUnlock(): void {
    center(mark("l"), h("h1", null, t("ui.unlockToContinue")), h("p", null, t("popup.unlockAppToSee")));
    let left = UNLOCK_WAIT_TRIES;
    const check = (): void => {
      void track(
        call(deps.send, { type: "popup_status" }, parseStatus).then((r) => {
          if (r.ok && !r.value.locked) return load();
          if (r.ok && --left > 0) timers.setTimeout(check, UNLOCK_POLL_MS);
          else if (r.ok) renderLockedPlain();
          else return load();
          return undefined;
        }),
      );
    };
    timers.setTimeout(check, UNLOCK_POLL_MS);
  }

  /** Face ID ran once by itself in this popup: never again without a tap (no loop). */
  let autoBiometricDone = false;
  /** A native unlock is running: the buttons wait. */
  let unlocking = false;
  /** The native vault said unlocked once and the bridge still said locked: no second round. */
  let nativeSettled = false;

  /**
   * Locked. iOS (IOSSAF-01): the native vault of the Safari handler answers, and the popup turns
   * into the unlock sheet (the menu's). Elsewhere it has none: "Déverrouiller dans OnePass".
   */
  function renderLocked(): Promise<void> {
    return track(
      call(deps.send, { type: "popup_vault" }, parseNativeVaultState).then((r) => {
        if (r.ok && r.value.locked) return renderUnlockSheet(r.value);
        if (r.ok && !nativeSettled) {
          nativeSettled = true;
          return load();
        }
        renderLockedPlain();
        return undefined;
      }),
    );
  }

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

  /** Face ID (or Touch ID) once by itself when the policy allows it, then the button; the master password always. */
  function renderUnlockSheet(v: NativeVaultState): void {
    const errLine = h("p", { class: "error-line", attrs: { role: "alert" } });
    const reason = v.error ? unlockErrorText(v) : "";
    if (reason) errLine.textContent = reason;
    const after = (r: Awaited<ReturnType<typeof callVault>>): Promise<void> | undefined => {
      unlocking = false;
      if (!r.ok) {
        renderLockedPlain();
        return undefined;
      }
      if (!r.value.locked) return load();
      renderUnlockSheet(r.value);
      return undefined;
    };
    const biometric = (): void => {
      if (unlocking) return;
      unlocking = true;
      void track(callVault({ type: "popup_unlock_biometric" }).then(after));
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
      if (unlocking || input.value.length === 0) return;
      // The native unlock takes 1 to 1024 UTF-8 bytes (RelayRequest.maxPassword): said, not dropped.
      if (new TextEncoder().encode(input.value).length > 1024) {
        input.value = "";
        errLine.textContent = t("unlock.wrongPassword");
        return;
      }
      unlocking = true;
      const password = input.value;
      input.value = "";
      void track(callVault({ type: "popup_unlock_password", password }).then(after));
    };
    const kind = v.biometry === "none" ? null : v.biometry;
    const bio = kind
      ? h(
          "button",
          { class: "btn btn-primary unlock-bio", attrs: { type: "button" }, on: { click: () => biometric() } },
          icon(kind === "touchID" ? "touchid" : "faceid", 18),
          t(kind === "touchID" ? "unlock.withTouchId" : kind === "opticID" ? "unlock.withOpticId" : "unlock.withFaceId"),
        )
      : null;
    center(
      h(
        "div",
        { class: "unlock-sheet" },
        h("span", { class: "unlock-mark" }, mark("l")),
        h("h1", null, t("ui.onepassLocked")),
        v.account ? h("p", { class: "message-detail unlock-account" }, v.account) : null,
        bio,
        h(
          "form",
          { class: "unlock-form", on: { submit } },
          input,
          h("button", { class: kind ? "btn" : "btn btn-primary", attrs: { type: "submit" } }, t("unlock.unlock")),
        ),
        v.message && v.error === "password_required" ? h("p", { class: "message-detail" }, v.message) : null,
        errLine,
      ),
      forgetButton(),
    );
    // One automatic try per popup, and never after the policy asked for the password.
    if (kind && !autoBiometricDone && !v.error) {
      autoBiometricDone = true;
      biometric();
    } else if (!kind) input.focus();
  }

  const callVault = (m: UiToBg) => call(deps.send, m, parseNativeVaultState);

  function renderLockedPlain(): void {
    center(
      mark("l"),
      h("h1", null, t("ui.onepassLocked")),
      h("p", null, t("popup.unlockAppToSee")),
      h(
        "div",
        { class: "actions" },
        button(t("menu.unlockInOnepass"), "btn btn-primary", () =>
          void track(
            call(deps.send, { type: "popup_unlock" }, parseLocked).then((r) => {
              if (r.ok && !r.value.locked) return load();
              if (r.ok) waitForUnlock();
              else toast(errorText(r.code), "error");
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
      h("h1", null, t("ui.onepassAppNotFound")),
      h("p", null, t("popup.installOrOpenOnepass")),
      h("div", { class: "actions" }, button(t("popup.tryAgain"), "btn btn-primary", () => void track(load()))),
    );
  }

  function renderError(code: string): void {
    center(
      mark("l"),
      h("h1", null, errorText(code)),
      h("div", { class: "actions" }, button(t("popup.tryAgain"), "btn btn-primary", () => void track(load()))),
    );
  }

  // ---- main view ----
  let status: PopupStatus | null = null;
  let domain: string | null = null;
  let suggestions: Summary[] = [];
  let plan: PopupPlanLine | null = null;
  /** Sign-ins whose save card went away unanswered (no password here). */
  let waiting: PendingSave[] = [];
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
    const placeholder = t("popup.searchOnepass");
    const input = h("input", {
      attrs: { type: "search", placeholder, "aria-label": placeholder, maxlength: "256" },
    });
    input.addEventListener("input", () => {
      if (searchTimer !== null) timers.clearTimeout(searchTimer);
      const q = input.value;
      searchTimer = timers.setTimeout(() => void track(search(q)), SEARCH_DEBOUNCE_MS);
    });
    const genLabel = t("popup.passwordGenerator");
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
    compact(false);
    mount(
      container,
      h(
        "div",
        { class: "pp-head" },
        h("span", { class: "brand" }, mark("m"), "OnePass"),
        h("label", { class: "search glass" }, icon("search", 14), input),
        genBtn,
        // The account chip also holds "Oublier cet appairage", out of the way.
        h(
          "button",
          { class: "account", attrs: { type: "button", title: account }, on: { click: () => confirmForget() } },
          h("span", { class: "avatar", attrs: { "aria-hidden": "true" } }, initials(account)),
          h("span", null, account),
          srOnly(t("popup.forgetPairing")),
        ),
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
        h("h2", null, t("popup.pickItem")),
        h("p", null, t("popup.orOpenGeneratorTo")),
      ),
    );
  }

  function renderSide(): void {
    const items = results ?? suggestions;
    let title: string;
    let empty: string | null = null;
    if (results) {
      title = t("popup.results");
      if (items.length === 0) empty = t("popup.noResults");
    } else if (domain) {
      title = t("popup.suggestionsForDomain", { domain });
      if (items.length === 0) empty = t("popup.noLoginForDomain", { domain });
    } else {
      title = t("popup.suggestions");
      empty = t("popup.pageNotHttpsSite");
    }
    const list = h("div", { class: "pp-list", attrs: { role: "listbox", "aria-label": title } });
    // What one click does on this page, then its alternatives (listed first by the worker).
    const line =
      plan && !results
        ? h(
            "div",
            { class: "plan-line glass", attrs: { role: "group", "aria-label": t("popup.oneClickFill") } },
            h("span", { class: "plan-text" }, planText(plan)),
            button(t("common.fill"), "btn btn-primary", () => void track(smartFill())),
          )
        : null;
    const toSave =
      waiting.length > 0 && !results
        ? h(
            "div",
            { class: "pp-pending glass", attrs: { role: "group", "aria-label": t("popup.toSave") } },
            ...waiting.map((w) =>
              h(
                "div",
                { class: "pp-pending-row" },
                siteTile(w.origin, w.site, 28),
                h(
                  "span",
                  { class: "stack" },
                  h("span", { class: "t1" }, w.status === "update" ? t("save.updatePasswordFor", { site: w.site }) : t("save.saveLoginFor", { site: w.site })),
                  h("span", { class: "t2" }, w.vault !== undefined ? `${w.username} · ${w.vault}` : w.username),
                ),
                button(t("save.notNow"), "btn-text sc-quiet", () => void track(decideWaiting(w, "dismiss"))),
                button(w.status === "update" ? t("save.update") : t("common.save"), "btn-text sc-primary", () =>
                  void track(decideWaiting(w, w.status === "update" ? "update" : "save")),
                ),
              ),
            ),
          )
        : null;
    for (const it of items) {
      list.append(
        h(
          "button",
          {
            class: "row",
            attrs: { type: "button", role: "option", "aria-selected": String(view === "detail" && selected === it.item_id) },
            on: { click: () => void track(openItem(it.item_id)) },
          },
          results || !domain ? itemArt(it, "m") : siteIcon(`https://${domain}`, itemArt(it, "m")),
          h("span", { class: "stack" }, h("span", { class: "t1" }, it.title), h("span", { class: "t2" }, it.subtitle)),
        ),
      );
    }
    mount(
      side,
      toSave,
      h("h1", { class: "pp-side-title" }, icon(results ? "search" : "star", 13), title),
      line,
      list,
      empty ? h("p", { class: "pp-empty" }, empty) : null,
      // The pairing's own forget lives in the account chip; this one forgets the site memory only.
      domain && !results
        ? h(
            "div",
            { class: "pp-foot" },
            button(t("popup.forgetMyChoicesOn"), "btn-link", () => void track(forgetSite())),
          )
        : null,
    );
  }

  async function decideWaiting(w: PendingSave, decision: "save" | "update" | "dismiss"): Promise<void> {
    const r = await call(deps.send, { type: "popup_pending_decide", id: w.id, decision }, parseOutcome);
    waiting = waiting.filter((x) => x.id !== w.id);
    renderSide();
    if (!r.ok) {
      toast(errorText(r.code), "error");
      return;
    }
    if (decision === "dismiss") return;
    const o = r.value;
    toast(
      o.outcome === "already"
        ? t("save.alreadyInOnepass")
        : o.outcome === "updated"
          ? t("save.passwordUpdated")
          : o.vault !== undefined
            ? t("save.savedIn", { vault: o.vault })
            : t("save.loginSaved"),
    );
  }

  async function smartFill(): Promise<void> {
    const r = await call(deps.send, { type: "popup_smart_fill" }, parseFilled);
    if (!r.ok) return handleError(r.code);
    toast(t("popup.fillingOnDomain", { domain: r.value.domain }));
  }

  async function forgetSite(): Promise<void> {
    const r = await call(deps.send, { type: "popup_forget_site" }, parseForgotSite);
    if (!r.ok) return handleError(r.code);
    toast(t("popup.choicesForgottenForDomain", { domain: r.value.domain }));
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
    if (code === "locked") void renderLocked();
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
      s.kind === "login" ? t("popup.username") : s.kind === "card" ? t("popup.card") : t("popup.identity");
    card.append(
      fieldRow(
        firstLabel,
        s.subtitle,
        s.kind === "login" && s.subtitle !== ""
          ? iconButton(t("popup.copyUsername"), "copy", () =>
              void track(copy(s.subtitle, t("popup.usernameCopied"))),
            )
          : null,
      ),
    );
    if (s.kind === "login" && s.has_password) {
      const value = h("span", { class: "field-value mono pwd-value" }, MASK);
      let shown: string | null = null;
      const label = { show: t("common.show"), hide: t("common.hide") };
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
      const copyPwd = iconButton(t("popup.copyPassword"), "copy", () =>
        void track(
          (async () => {
            let secret = shown;
            if (secret === null) {
              const v = await call(deps.send, { type: "popup_reveal", itemId }, parseValue);
              if (!v.ok) return handleError(v.code);
              secret = v.value.value;
            }
            await copy(secret, t("popup.passwordCopied"));
          })(),
        ),
      );
      card.append(fieldRow(t("menu.password"), value, toggle, copyPwd));
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
        pill.setAttribute("aria-label", t("popup.remainingSecondsLeft", { remaining }));
      };
      const copyCode = iconButton(t("popup.copyCode"), "copy", () => {
        if (current !== "") void track(copy(current, t("popup.codeCopied")));
      });
      card.append(fieldRow(t("popup.oneTimeCode"), code, pill, copyCode));
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
      card.append(h("div", { class: "field-row website" }, h("span", { class: "stack" }, h("span", { class: "cell-label" }, t("popup.website")), h("span", { class: "field-value" }, website))));
    }
    const fill = button(t("common.fill"), "btn btn-primary", () =>
      void track(
        call(deps.send, { type: "popup_fill", itemId }, parseFilled).then((f) => {
          if (f.ok) toast(t("popup.filledOnDomain", { domain: f.value.domain }));
          else handleError(f.code);
        }),
      ),
    );
    mount(
      main,
      h(
        "div",
        { class: "pp-bar" },
        siteIcon(website, itemArt(s, 52), 52),
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
  let profile: GeneratorProfile = "strong";

  async function loadProfile(): Promise<void> {
    if (!deps.storage) return;
    try {
      profile = parseGeneratorProfile((await deps.storage.get(GENERATOR_PROFILE_KEY))[GENERATOR_PROFILE_KEY]);
    } catch {
      profile = "strong";
    }
  }

  async function saveProfile(p: GeneratorProfile): Promise<void> {
    profile = p;
    try {
      await deps.storage?.set({ [GENERATOR_PROFILE_KEY]: p });
    } catch {
      toast(errorText("internal"), "error");
    }
    await renderGenerator();
  }

  /** The length slider (8 to 64), its value shown beside it. */
  function lengthLine(value: number, onChange: (n: number) => void): HTMLElement {
    const range = h("input", {
      attrs: { type: "range", min: String(CUSTOM_MIN_LENGTH), max: String(CUSTOM_MAX_LENGTH), value: String(value), "aria-label": t("popup.length") },
    });
    const shown = h("span", { class: "field-note" }, String(value));
    range.addEventListener("input", () => (shown.textContent = range.value));
    range.addEventListener("change", () => onChange(Number(range.value)));
    return h("label", { class: "gen-line" }, t("popup.length"), range, shown);
  }

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
    await loadProfile();
    await generate();
  }

  function colored(pw: string): HTMLElement {
    const out = h("div", { class: "gen-out", attrs: { "aria-label": t("popup.generatedPassword") } });
    for (const ch of pw) {
      const cls = /[0-9]/.test(ch) ? "ch-digit" : /\p{L}/u.test(ch) ? "" : "ch-symbol";
      out.append(cls ? h("span", { class: cls }, ch) : ch);
    }
    return out;
  }

  async function renderGenerator(): Promise<void> {
    const select = h("select", { class: "select", attrs: { "aria-label": t("popup.passwordType") } });
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
    const settings = h("div", { class: "card" }, h("label", { class: "gen-line" }, t("popup.type"), select));
    if (genKind === "random") {
      settings.append(
        lengthLine(genLength, (n) => {
          genLength = n;
          void track(generate());
        }),
      );
    }
    if (genKind === "smart") {
      // The profile the extension generates with on sites (menu, fill, save prompt).
      const current = typeof profile === "string" ? profile : "custom";
      const pick = h("select", { class: "select", attrs: { "aria-label": t("popup.profileOnSites") } });
      for (const c of PROFILE_CHOICES) {
        const o = h("option", { attrs: { value: c.value } }, c.label);
        if (c.value === current) o.selected = true;
        pick.append(o);
      }
      pick.addEventListener("change", () => {
        const v = pick.value;
        if (v === "strong" || v === "readable") void track(saveProfile(v));
        else if (v === "custom") void track(saveProfile({ kind: "custom", length: Math.min(CUSTOM_MAX_LENGTH, Math.max(CUSTOM_MIN_LENGTH, genLength)), symbols: true }));
      });
      settings.append(h("label", { class: "gen-line" }, t("popup.onSites"), pick));
      if (typeof profile === "object") {
        const custom = profile;
        settings.append(lengthLine(custom.length, (n) => void track(saveProfile({ ...custom, length: n }))));
        const symbols = h("input", { attrs: { type: "checkbox", "aria-label": t("popup.symbols") } });
        symbols.checked = custom.symbols;
        symbols.addEventListener("change", () => void track(saveProfile({ ...custom, symbols: symbols.checked })));
        settings.append(h("label", { class: "gen-line" }, t("popup.symbols"), symbols));
      }
    }
    let historyList: HTMLElement | null = null;
    if (historyOpen) {
      const r = await call(deps.send, { type: "popup_history" }, parseHistory);
      const entries: GeneratorEntry[] = r.ok ? r.value.entries : [];
      historyList = h("ul", { class: "history-list" });
      for (const e of entries) historyList.append(h("li", null, e.password));
      if (entries.length === 0) historyList.append(h("li", null, t("popup.noGeneratedPassword")));
    }
    const strength = h("div", { class: "strength" }, h("div"));
    (strength.firstChild as HTMLElement).style.width = `${Math.min(100, Math.round((genEntropy / 100) * 100))}%`;
    mount(
      main,
      h(
        "div",
        { class: "gen-head" },
        h("h2", null, t("popup.passwordGenerator")),
        h(
          "button",
          {
            class: "btn-icon",
            attrs: { type: "button", "aria-label": t("popup.closeGenerator") },
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
          srOnly(t("popup.entropyValueBits", { value: Math.round(genEntropy) })),
        ),
        h(
          "div",
          { class: "actions" },
          button(t("common.copy"), "btn", () => void track(copy(genPassword, t("common.copied")))),
          h(
            "button",
            {
              class: "btn-icon",
              attrs: { type: "button", "aria-label": t("popup.generateAnother"), title: t("popup.generateAnother") },
              on: { click: () => void track(generate()) },
            },
            icon("refresh", 16),
          ),
          h("span", { class: "stack" }),
          button(t("common.fill"), "btn btn-primary", () =>
            void track(
              call(deps.send, { type: "popup_fill_generated", password: genPassword }, parseFilled).then((f) => {
                if (f.ok) toast(t("popup.filledOnDomain", { domain: f.value.domain }));
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
          h("span", { class: "stack" }, t("popup.generatorHistory")),
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
      else if (r.code === "locked") await renderLocked();
      else renderError(r.code);
      return;
    }
    status = r.value;
    // The extension paired itself with the app while opening: said once, over the rendered view.
    const connected = status.connected === true;
    if (status.locked) {
      await renderLocked();
      if (connected) toast(t("popup.connectedToOnepass"));
      return;
    }
    const s = await call(deps.send, { type: "popup_suggestions" }, parseSuggestions);
    if (!s.ok) return handleError(s.code);
    domain = s.value.domain;
    suggestions = s.value.items;
    plan = s.value.plan ?? null;
    const p = await call(deps.send, { type: "popup_pending" }, parsePending);
    waiting = p.ok ? p.value : [];
    results = null;
    view = "none";
    renderMain();
    if (connected) toast(t("popup.connectedToOnepass"));
  }

  center(mark("l"));
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
  if (root) mountPopup(root, { send: (m) => ext.runtime.sendMessage(m), storage: ext.storage.local });
  if (__LAB_RECORDER__) void import("../dev/recorder-ui").then((m) => m.default(document));
}
