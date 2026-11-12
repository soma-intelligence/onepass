// Passkey choice window (spec 3.2): `passkey.html#<token>`, a popup window
// the worker opens for one `navigator.credentials` request of one document.
// Sign-in lists the accounts of OnePass holding a passkey for the site;
// creation names the account the site asked for and the vault. "Autre
// appareil" hands the request back to the browser's own dialog, "Annuler"
// gives the page NotAllowedError. Nothing is signed before a trusted click
// past the click guard (300 ms after the content appeared or the window came
// back into view). The page never sees a key: the worker signs through the host.
import { ext } from "../shared/browser";
import { t } from "../shared/i18n";
import type { PasskeyAccount, PasskeyInit } from "../shared/messages";
import {
  ClickGuard,
  FALLBACK_COLOR,
  type FrameDeps,
  call,
  errorText,
  h,
  icon,
  mark,
  messageBlock,
  mount,
  observeVisibility,
  tile,
  tokenFromHash,
} from "./components";

const MAX_TEXT = 1024;

export interface PasskeyHandle {
  ready: Promise<void>;
}

// ---- reply checks ----

const str = (v: unknown, max = MAX_TEXT): string => {
  if (typeof v !== "string" || v.length > max) throw new Error("str");
  return v;
};

function account(v: unknown): PasskeyAccount {
  const o = v as Record<string, unknown>;
  return {
    itemId: str(o.itemId, 128),
    credentialId: str(o.credentialId, 1400),
    title: str(o.title),
    userName: str(o.userName),
    vaultName: str(o.vaultName),
  };
}

export function parsePasskeyInit(v: unknown): PasskeyInit | null {
  try {
    if (typeof v !== "object" || v === null) return null;
    const o = v as Record<string, unknown>;
    if (o.kind !== "get" && o.kind !== "create") return null;
    if (!Array.isArray(o.accounts) || o.accounts.length > 64) return null;
    const out: PasskeyInit = { kind: o.kind, origin: str(o.origin, 2048), rpId: str(o.rpId, 253), accounts: o.accounts.map(account) };
    if (o.userName !== undefined) out.userName = str(o.userName);
    if (o.vaults !== undefined) {
      if (!Array.isArray(o.vaults) || o.vaults.length > 256) return null;
      out.vaults = o.vaults.map((x) => {
        const w = x as Record<string, unknown>;
        return { id: str(w.id, 128), name: str(w.name) };
      });
    }
    return out;
  } catch {
    return null;
  }
}

const parseEmpty = (v: unknown): object | null => (typeof v === "object" && v !== null ? v : null);

/** Shown length of a site's userName (characters, the ellipsis included). */
export const MAX_SHOWN_NAME = 64;

/**
 * A userName as the window shows it: no control or format characters (bidi
 * overrides and isolates, zero widths), cut to MAX_SHOWN_NAME with an ellipsis.
 * A site picks this string: it must not pass for another account or file name.
 */
export function displayName(v: string): string {
  const chars = Array.from(v.replace(/[\p{Cc}\p{Cf}]/gu, ""));
  return chars.length <= MAX_SHOWN_NAME ? chars.join("") : `${chars.slice(0, MAX_SHOWN_NAME - 1).join("")}…`;
}

const initial = (s: string) => (s.trim().charAt(0) || "O").toUpperCase();

export function mountPasskey(root: HTMLElement, deps: FrameDeps): PasskeyHandle {
  const now = deps.now ?? (() => performance.now());
  const guard = new ClickGuard({ now, ...(deps.trusted ? { trusted: deps.trusted } : {}) });
  const token = tokenFromHash(deps.hash);
  const container = h("div", { class: "passkey" });
  mount(root, container);
  (deps.observe ?? observeVisibility)(container, (v) => guard.setVisibility(v));
  // A window brought back to the front, or shown again, re-arms the guard.
  if (typeof document !== "undefined" && !deps.observe) {
    document.addEventListener("visibilitychange", () => guard.reset());
    globalThis.addEventListener?.("focus", () => guard.reset());
  }

  let busy = false;
  const buttons: HTMLButtonElement[] = [];
  const setBusy = (on: boolean) => {
    busy = on;
    for (const b of buttons) b.disabled = on;
    container.classList.toggle("busy", on);
  };

  const errLine = h("p", { class: "error-line", attrs: { role: "alert" } });

  const act = async (msg: Parameters<typeof call>[1]) => {
    if (busy || !token) return;
    setBusy(true);
    errLine.textContent = "";
    const r = await call(deps.send, msg, parseEmpty);
    setBusy(false);
    // Success: the worker closes the window.
    if (!r.ok) errLine.textContent = errorText(r.code);
  };

  const btn = (label: string, cls: string, fn: () => void, extra: Record<string, string> = {}) => {
    const b = h("button", { class: cls, attrs: { type: "button", ...extra }, on: { click: guard.wrap(fn) } }, label);
    buttons.push(b);
    return b;
  };

  const other = () => btn(t("passkey.otherDevice"), "btn", () => void act({ type: "passkey_other", token: token ?? "" }));
  const cancel = () => btn(t("common.cancel"), "btn", () => void act({ type: "passkey_cancel", token: token ?? "" }));

  // The rpId the passkey is for, and the exact origin asking (the browser's, from the worker).
  const header = (title: string, i: PasskeyInit) =>
    h(
      "header",
      { class: "pk-head" },
      mark("m"),
      h(
        "span",
        { class: "stack" },
        h("h1", null, title),
        h("span", { class: "pk-site" }, icon("lock", 11), h("span", null, i.rpId)),
        h("span", { class: "pk-origin", attrs: { title: i.origin } }, t("passkey.askedByOrigin", { origin: i.origin })),
      ),
    );

  const show = (...children: (HTMLElement | null)[]) => {
    mount(container, ...children);
    guard.reset();
  };

  function renderGet(i: PasskeyInit): void {
    const rows = i.accounts.map((a) => {
      const name = displayName(a.userName);
      const b = h(
        "button",
        {
          class: "row pk-row",
          attrs: { type: "button", "aria-label": t("passkey.signInAsName", { name }) },
          on: { click: guard.wrap(() => void act({ type: "passkey_pick", token: token ?? "", itemId: a.itemId, credentialId: a.credentialId })) },
        },
        tile(initial(a.title), FALLBACK_COLOR, "m"),
        h("span", { class: "stack" }, h("span", { class: "t1" }, name), h("span", { class: "t2" }, `${a.title} · ${a.vaultName}`)),
        h("span", { class: "pk-key" }, icon("key", 14)),
      );
      buttons.push(b);
      return b;
    });
    show(
      h(
        "div",
        { class: "pk-body", attrs: { role: "dialog", "aria-label": t("term.passkey") } },
        header(t("passkey.signInWithPasskey"), i),
        h("p", { class: "pk-lead" }, t("passkey.chooseAccountOnepassSigns")),
        h("div", { class: "pk-list", attrs: { role: "list" } }, ...rows),
        errLine,
        h("footer", { class: "pk-actions" }, other(), h("span", { class: "pk-gap" }), cancel()),
      ),
    );
  }

  function renderCreate(i: PasskeyInit): void {
    const vaults = i.vaults ?? [];
    let vaultId = vaults[0]?.id;
    const sel = h("select", { class: "select", attrs: { "aria-label": t("term.vault") } });
    for (const v of vaults) sel.append(h("option", { attrs: { value: v.id } }, v.name));
    sel.addEventListener("change", () => {
      vaultId = sel.value;
    });
    const save = btn(t("common.save"), "btn btn-primary", () => {
      const msg: { type: "passkey_save"; token: string; vaultId?: string } = { type: "passkey_save", token: token ?? "" };
      if (vaultId !== undefined) msg.vaultId = vaultId;
      void act(msg);
    });
    const userName = displayName(i.userName ?? "");
    const cancelButton = cancel();
    show(
      h(
        "div",
        { class: "pk-body", attrs: { role: "dialog", "aria-label": t("term.passkey") } },
        header(t("passkey.savePasskey"), i),
        h(
          "div",
          { class: "pk-card" },
          tile(initial(i.rpId), FALLBACK_COLOR, "l"),
          h("span", { class: "stack" }, h("span", { class: "t1" }, userName), h("span", { class: "t2" }, i.rpId)),
        ),
        h(
          "p",
          { class: "pk-lead" },
          t("passkey.privateKeyStaysIn"),
        ),
        vaults.length > 1 ? h("label", { class: "pk-field" }, h("span", { class: "t2" }, t("term.vault")), sel) : null,
        errLine,
        h("footer", { class: "pk-actions" }, other(), h("span", { class: "pk-gap" }), cancelButton, save),
      ),
    );
    // A creation starts on "Annuler": Enter alone never saves a passkey.
    cancelButton.focus({ preventScroll: true });
  }

  const keydown = (e: KeyboardEvent) => {
    if (e.key !== "Escape" || !guard.accepts(e)) return;
    e.preventDefault();
    void act({ type: "passkey_cancel", token: token ?? "" });
  };
  if (typeof document !== "undefined") document.addEventListener("keydown", keydown);

  const ready = (async () => {
    if (!token) {
      show(messageBlock(errorText("invalid")));
      return;
    }
    const r = await call(deps.send, { type: "passkey_init", token }, parsePasskeyInit);
    if (!r.ok) {
      show(messageBlock(errorText(r.code)));
      return;
    }
    if (r.value.kind === "get") {
      renderGet(r.value);
      (container.querySelector("button.pk-row") as HTMLButtonElement | null)?.focus({ preventScroll: true });
    } else renderCreate(r.value);
  })();
  return { ready };
}

// ---- real start (not in tests: no extension runtime there) ----

if (ext?.runtime?.id && typeof document !== "undefined") {
  const root = document.getElementById("root");
  if (root) mountPasskey(root, { send: (m) => ext.runtime.sendMessage(m), hash: location.hash });
}
