// Two-factor setup card (spec 2026-11-13, section 1): `setup.html#<token>` in the top frame of the
// tab the popup scanned. It asks which login gets the code the page shows as a QR ("Add the 2FA
// code to <login>?"), or for the setup key when no QR was read, then says it was saved and, when
// no code field took it, shows the current code with its countdown. A second card of the same page
// asks to keep the recovery codes the site then showed.
//
// The card never sees the seed: the worker holds it. The pasted key goes to the worker once and
// leaves the field at once. Everything the page or the vault named (issuer, account, titles,
// usernames) is rendered as text only (`h`, text nodes).
//
// Default button: Add, except when the QR account differs from the login's username and in the
// "Replace?" question, where it is Cancel. The card closes on Cancel, on Escape and
// SAVED_CLOSE_MS after "Saved" (with a code shown: once that code ran out, if later).
import { ext } from "../shared/browser";
import { t, tn } from "../shared/i18n";
import type { SetupCandidate, SetupCardState, SetupRefusal, SetupSaveResult, UiToBg } from "../shared/messages";
import { pastedSecret } from "../setup/otpauth";
import {
  ClickGuard,
  type FrameDeps,
  accountNotes,
  autosize,
  call,
  errorText,
  h,
  icon,
  mark,
  messageBlock,
  mount,
  observeVisibility,
  realTimers,
  tokenFromHash,
} from "./components";
import { parseEmpty, parsePasteRefused, parseSetupCodes, parseSetupSave, parseSetupState } from "./parse";

/** "Saved" closes itself after this delay. */
export const SAVED_CLOSE_MS = 8000;

export interface SetupHandle {
  ready: Promise<void>;
}

const norm = (s: string) => s.trim().toLowerCase();

type SaveArgs = { itemId: string | null; username?: string };

export function mountSetup(root: HTMLElement, deps: FrameDeps): SetupHandle {
  const now = deps.now ?? (() => performance.now());
  const timers = deps.timers ?? realTimers;
  const guard = new ClickGuard({ now, ...(deps.trusted ? { trusted: deps.trusted } : {}) });
  const token = tokenFromHash(deps.hash);
  const container = h("div", { class: "save fit setup" });
  mount(root, container);
  (deps.observe ?? observeVisibility)(container, (v) => guard.setVisibility(v));
  const remeasure = autosize(
    container,
    (height) => {
      if (token) void call(deps.send, { type: "setup_resize", token, height }, parseEmpty);
    },
    deps.observeSize,
  );

  let st: SetupCardState | null = null;
  /** The login picked; null with `newLogin`. */
  let sel: string | null = null;
  let newLogin = false;
  let username = "";
  let more = false;
  let busy = false;
  let closeTimer: unknown = null;
  let tick: unknown = null;

  const stopTimers = () => {
    if (closeTimer !== null) timers.clearTimeout(closeTimer);
    if (tick !== null) timers.clearInterval(tick);
    closeTimer = null;
    tick = null;
  };

  const close = () => {
    stopTimers();
    if (token) void call(deps.send, { type: "setup_close", token }, parseEmpty);
  };

  const keydown = (e: KeyboardEvent) => {
    if (e.key !== "Escape" || !guard.accepts(e)) return;
    e.preventDefault();
    close();
  };
  if (typeof document !== "undefined") document.addEventListener("keydown", keydown);

  const show = (...children: (HTMLElement | null)[]) => {
    mount(container, ...children);
    guard.reset();
    remeasure();
  };

  const btn = (label: string, cls: string, fn: () => void, attrs: Record<string, string> = {}) =>
    h("button", { class: cls, attrs: { type: "button", ...attrs }, on: { click: guard.wrap(fn) } }, label);

  const errLine = () => h("p", { class: "error-line", attrs: { role: "alert" } });

  const focus = (el: HTMLElement | null | undefined) => el?.focus({ preventScroll: true });

  const head = (title: string, sub: string | null, withMore = false) =>
    h(
      "div",
      { class: "sc-row" },
      mark("m"),
      h("span", { class: "stack" }, h("span", { class: "sc-title" }, title), sub ? h("span", { class: "sc-sub" }, sub) : null),
      withMore
        ? h(
            "button",
            {
              class: "btn-icon sc-more",
              attrs: { type: "button", "aria-label": t("save.options"), "aria-haspopup": "menu", "aria-expanded": String(more) },
              on: {
                click: guard.wrap(() => {
                  more = !more;
                  renderConfirm();
                }),
              },
            },
            icon("more", 12),
          )
        : null,
    );

  const card = (label: string, ...children: (HTMLElement | null)[]) =>
    h("div", { class: "save-card", attrs: { role: "dialog", "aria-label": label } }, ...children);

  const foot = (...buttons: HTMLElement[]) => h("div", { class: "sc-foot" }, h("span", { class: "sc-gap" }), ...buttons);

  const candidate = (): SetupCandidate | undefined => (newLogin ? undefined : st?.candidates.find((c) => c.itemId === sel));
  /** The name of the login the code goes to (a new login: the site that issued the code). */
  const itemName = () => candidate()?.title ?? st?.issuer ?? "";
  const fromLine = (s: SetupCardState) => (s.account !== "" ? t("setup.from", { issuer: s.issuer, account: s.account }) : s.issuer);

  // ---- the confirmation ----

  function pick(id: string | null): void {
    if (id === null) {
      newLogin = true;
      sel = null;
    } else {
      newLogin = false;
      sel = id;
    }
    more = false;
    renderConfirm();
  }

  const option = (selected: boolean, onClick: () => void, title: string, sub: string | null, notes: HTMLElement[] = []) =>
    h(
      "button",
      { class: "sc-vault sc-pick", attrs: { type: "button", role: "option", "aria-selected": String(selected) }, on: { click: guard.wrap(onClick) } },
      h("span", { class: "stack" }, h("span", { class: "t1" }, title), sub !== null ? h("span", { class: "t2" }, sub, ...notes) : null),
      selected ? icon("check", 11) : null,
    );

  function renderConfirm(): void {
    const s = st;
    if (!s) return;
    stopTimers();
    // No login on this site: only a new one.
    if (s.candidates.length === 0) newLogin = true;
    const c = candidate();
    const mismatch = c !== undefined && norm(s.account) !== "" && norm(c.username) !== norm(s.account);
    const err = errLine();
    const add = btn(t("setup.add"), "btn-text sc-primary", () => void save({ itemId: newLogin ? null : sel, ...(newLogin ? { username: username.trim() } : {}) }, false, err));
    const cancel = btn(t("setup.cancel"), "btn-text sc-quiet", close);
    const blocked = () => busy || (newLogin ? username.trim() === "" : c === undefined);
    add.disabled = blocked();
    let field: HTMLInputElement | null = null;
    if (newLogin) {
      field = h("input", {
        class: "input sc-identifier",
        attrs: { type: "text", "aria-label": t("save.username"), placeholder: t("save.username"), maxlength: "1024", autocomplete: "off", spellcheck: "false" },
      });
      field.value = username;
      field.addEventListener("input", () => {
        username = field?.value ?? "";
        add.disabled = blocked();
      });
    }
    const several = s.candidates.length > 1;
    const list = several
      ? h(
          "div",
          { class: "sc-vaults", attrs: { role: "listbox", "aria-label": t("save.whichLogin") } },
          ...s.candidates.map((x) => option(!newLogin && x.itemId === sel, () => pick(x.itemId), x.title, x.username, accountNotes(x.associated ? { associated: true } : {}))),
          option(newLogin, () => pick(null), t("setup.newLogin"), null),
        )
      : null;
    // One login: no list; "New login" sits in the options menu.
    const menu =
      !several && s.candidates.length === 1 && more
        ? h("div", { class: "more", attrs: { role: "menu" } }, btn(t("setup.newLogin"), "", () => pick(null), { role: "menuitem" }))
        : null;
    const title = t("setup.title", { item: itemName() });
    show(
      card(
        title,
        head(title, fromLine(s), !several && s.candidates.length === 1),
        menu,
        list,
        mismatch && c ? h("p", { class: "sc-note sc-warn" }, t("setup.mismatch", { account: s.account, username: c.username })) : null,
        field ? h("div", { class: "sc-ask" }, field) : null,
        foot(cancel, add),
        err,
      ),
    );
    // Several logins and none picked yet: Add waits, the first login takes the focus.
    const firstOption = list?.querySelector<HTMLElement>('[role="option"]') ?? null;
    focus(mismatch ? cancel : add.disabled && field ? field : add.disabled && firstOption ? firstOption : add);
  }

  // ---- saving ----

  async function save(args: SaveArgs, replace: boolean, err: HTMLElement): Promise<void> {
    if (!token || busy) return;
    busy = true;
    const msg: Extract<UiToBg, { type: "setup_save" }> = { type: "setup_save", token, itemId: args.itemId };
    if (args.username !== undefined) msg.username = args.username;
    if (replace) msg.replace = true;
    const name = itemName();
    const r = await call(deps.send, msg, parseSetupSave);
    busy = false;
    if (!r.ok) {
      if (r.code === "locked") renderLocked(() => save(args, replace, errLine()));
      else err.textContent = errorText(r.code);
      return;
    }
    answer(r.value, args, name, replace);
  }

  function answer(v: SetupSaveResult, args: SaveArgs, name: string, replace: boolean): void {
    switch (v.status) {
      case "saved":
      case "same":
      case "replaced":
        renderSaved(v.code, v.remaining);
        return;
      case "exists":
        renderReplace(args, name);
        return;
      case "locked":
        // A Replace click stays a Replace through the unlock.
        renderLocked(() => save(args, replace, errLine()));
        return;
      case "refused":
        renderRefused(v.reason);
        return;
    }
  }

  function renderReplace(args: SaveArgs, name: string): void {
    stopTimers();
    const err = errLine();
    const title = t("setup.replaceTitle", { item: name });
    const cancel = btn(t("setup.cancel"), "btn-text sc-quiet", close);
    const replace = btn(t("setup.replace"), "btn-text sc-primary", () => void save(args, true, err));
    show(card(title, head(title, null), h("p", { class: "sc-note" }, t("setup.replaceNote")), foot(cancel, replace), err));
    // A replacement is never the default.
    focus(cancel);
  }

  /** The vault is locked: the worker asked the app to unlock; the click tries again. */
  function renderLocked(retry: () => Promise<void>): void {
    stopTimers();
    const err = errLine();
    const cancel = btn(t("setup.cancel"), "btn-text sc-quiet", close);
    const unlock = btn(t("setup.unlock"), "btn-text sc-primary", () => void retry());
    show(card(t("setup.unlock"), head(errorText("locked"), st ? fromLine(st) : null), foot(cancel, unlock), err));
    focus(unlock);
  }

  /** Why the write was refused (spec error table), from the worker's stable code. */
  function renderRefused(reason: SetupRefusal = "invalid"): void {
    stopTimers();
    const cancel = btn(t("common.close"), "btn-text sc-quiet", close);
    const why = errorText(reason);
    show(card(why, head(why, st ? fromLine(st) : null), foot(cancel)));
    focus(cancel);
  }

  function renderSaved(code?: string, remaining?: number): void {
    stopTimers();
    let left = remaining ?? 0;
    const count = h("span", { class: "sc-count", attrs: { "aria-hidden": "true" } }, String(left));
    const box =
      code !== undefined
        ? h(
            "div",
            { class: "sc-codebox" },
            h("span", { class: "cell-label" }, t("setup.code")),
            h("span", { class: "sc-code-row" }, h("span", { class: "sc-code" }, code), count),
          )
        : null;
    show(
      h(
        "div",
        { class: "saved quiet", attrs: { role: "status" } },
        h("span", { class: "ok-dot", attrs: { "aria-hidden": "true" } }, icon("check", 11)),
        h("span", { class: "stack" }, h("span", { class: "t1" }, t("setup.saved"))),
        btn(t("common.close"), "btn-link", close),
      ),
      box,
    );
    if (code !== undefined) {
      tick = timers.setInterval(() => {
        left = Math.max(0, left - 1);
        count.textContent = String(left);
        if (left === 0 && tick !== null) {
          timers.clearInterval(tick);
          tick = null;
          box?.classList.add("sc-expired");
        }
      }, 1000);
    }
    closeTimer = timers.setTimeout(close, Math.max(SAVED_CLOSE_MS, (remaining ?? 0) * 1000));
  }

  // ---- the setup key ----

  function renderPaste(): void {
    stopTimers();
    const err = errLine();
    const field = h("input", {
      class: "input sc-key",
      attrs: {
        type: "text",
        "aria-label": t("setup.pasteTitle"),
        maxlength: "512",
        autocomplete: "off",
        autocapitalize: "characters",
        spellcheck: "false",
      },
    });
    const add = btn(t("setup.add"), "btn-text sc-primary", () => void paste(field, add, err));
    add.disabled = true;
    field.addEventListener("input", () => {
      add.disabled = busy || pastedSecret(field.value) === null;
      err.textContent = "";
    });
    const cancel = btn(t("setup.cancel"), "btn-text sc-quiet", close);
    const title = t("setup.pasteTitle");
    show(card(title, head(title, st?.issuer ?? null), h("div", { class: "sc-ask" }, field), foot(cancel, add), err));
    focus(field);
  }

  async function paste(field: HTMLInputElement, add: HTMLButtonElement, err: HTMLElement): Promise<void> {
    if (!token || busy || pastedSecret(field.value) === null) return;
    const key = field.value;
    busy = true;
    add.disabled = true;
    const r = await call(deps.send, { type: "setup_paste", token, key }, (v) => parseSetupState(v) ?? parsePasteRefused(v));
    busy = false;
    if (!r.ok || "error" in r.value) {
      err.textContent = errorText(r.ok ? "invalid" : r.code);
      add.disabled = pastedSecret(field.value) === null;
      return;
    }
    // The key now lives in the worker only.
    field.value = "";
    begin(r.value);
  }

  // ---- recovery codes ----

  function renderCodes(): void {
    const s = st;
    if (!s) return;
    stopTimers();
    const err = errLine();
    const c = s.candidates.find((x) => x.itemId === s.selected);
    const title = tn("setup.codesTitle", s.codeCount ?? 0, { item: c?.title ?? s.issuer });
    const cancel = btn(t("setup.cancel"), "btn-text sc-quiet", close);
    const saveBtn = btn(t("setup.codesSave"), "btn-text sc-primary", () => void saveCodes(err));
    saveBtn.disabled = (s.codeCount ?? 0) === 0;
    show(card(t("setup.recoveryLabel"), head(title, c?.username ?? null), foot(cancel, saveBtn), err));
    focus(saveBtn);
  }

  async function saveCodes(err: HTMLElement): Promise<void> {
    if (!token || busy) return;
    busy = true;
    const r = await call(deps.send, { type: "setup_codes_save", token }, parseSetupCodes);
    busy = false;
    if (!r.ok) {
      if (r.code === "locked") renderLocked(() => saveCodes(errLine()));
      else err.textContent = errorText(r.code);
      return;
    }
    if (r.value.status === "saved") close();
    else if (r.value.status === "locked") renderLocked(() => saveCodes(errLine()));
    else renderRefused(r.value.reason);
  }

  // ---- load ----

  function begin(s: SetupCardState): void {
    st = s;
    sel = s.selected;
    newLogin = false;
    username = s.account;
    more = false;
    if (s.mode === "paste") renderPaste();
    else if (s.mode === "codes") renderCodes();
    else renderConfirm();
  }

  async function load(): Promise<void> {
    if (!token) {
      show(messageBlock(errorText("invalid")));
      return;
    }
    const r = await call(deps.send, { type: "setup_init", token }, parseSetupState);
    if (!r.ok) {
      // Locked meanwhile (the popup offers the scan only unlocked): unlock in the app, then again.
      if (r.code === "locked") renderLocked(load);
      else show(messageBlock(r.code === "unpaired" ? t("menu.pairOnepassFromToolbar") : errorText(r.code), undefined, btn(t("common.close"), "btn-link", close)));
      return;
    }
    begin(r.value);
  }

  return { ready: load() };
}

if (typeof document !== "undefined" && ext?.runtime?.id) {
  const root = document.getElementById("root");
  if (root) mountSetup(root, { send: (m) => ext.runtime.sendMessage(m), hash: location.hash });
}
