// Passkey choice window (spec 3.2): `passkey.html#<token>`, a popup window
// the worker opens for one `navigator.credentials` request of one document.
// Sign-in lists the accounts of OnePass holding a passkey for the site;
// creation names the account the site asked for and the vault. "Autre
// appareil" hands the request back to the browser's own dialog, "Annuler"
// gives the page NotAllowedError. Nothing is signed before a trusted click
// past the click guard (300 ms after the content appeared or the window came
// back into view). The page never sees a key: the worker signs through the host.
import { ext } from "../shared/browser";
import { tr } from "../shared/i18n";
import type { PasskeyAccount, PasskeyInit } from "../shared/messages";
import {
  ClickGuard,
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

const TILE = "#3F3DB8";
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

  const other = () => btn(tr("Autre appareil", "Other device"), "btn", () => void act({ type: "passkey_other", token: token ?? "" }));
  const cancel = () => btn(tr("Annuler", "Cancel"), "btn", () => void act({ type: "passkey_cancel", token: token ?? "" }));

  const header = (title: string, site: string) =>
    h(
      "header",
      { class: "pk-head" },
      mark("m"),
      h("span", { class: "stack" }, h("h1", null, title), h("span", { class: "pk-site" }, icon("lock", 11), h("span", null, site))),
    );

  const show = (...children: (HTMLElement | null)[]) => {
    mount(container, ...children);
    guard.reset();
  };

  function renderGet(i: PasskeyInit): void {
    const rows = i.accounts.map((a) => {
      const b = h(
        "button",
        {
          class: "row pk-row",
          attrs: { type: "button", "aria-label": tr(`Se connecter en tant que ${a.userName}`, `Sign in as ${a.userName}`) },
          on: { click: guard.wrap(() => void act({ type: "passkey_pick", token: token ?? "", itemId: a.itemId, credentialId: a.credentialId })) },
        },
        tile(initial(a.title), TILE, "m"),
        h("span", { class: "stack" }, h("span", { class: "t1" }, a.userName), h("span", { class: "t2" }, `${a.title} · ${a.vaultName}`)),
        h("span", { class: "pk-key" }, icon("key", 14)),
      );
      buttons.push(b);
      return b;
    });
    show(
      h(
        "div",
        { class: "pk-body", attrs: { role: "dialog", "aria-label": tr("Passkey", "Passkey") } },
        header(tr("Se connecter avec une passkey", "Sign in with a passkey"), i.rpId),
        h("p", { class: "pk-lead" }, tr("Choisis le compte. OnePass signe pour ce site, sans mot de passe.", "Choose the account. OnePass signs for this site, no password.")),
        h("div", { class: "pk-list", attrs: { role: "list" } }, ...rows),
        errLine,
        h("footer", { class: "pk-actions" }, other(), h("span", { class: "pk-gap" }), cancel()),
      ),
    );
  }

  function renderCreate(i: PasskeyInit): void {
    const vaults = i.vaults ?? [];
    let vaultId = vaults[0]?.id;
    const sel = h("select", { class: "select", attrs: { "aria-label": tr("Coffre", "Vault") } });
    for (const v of vaults) sel.append(h("option", { attrs: { value: v.id } }, v.name));
    sel.addEventListener("change", () => {
      vaultId = sel.value;
    });
    const save = btn(tr("Enregistrer", "Save"), "btn btn-primary", () => {
      const msg: { type: "passkey_save"; token: string; vaultId?: string } = { type: "passkey_save", token: token ?? "" };
      if (vaultId !== undefined) msg.vaultId = vaultId;
      void act(msg);
    });
    const userName = i.userName ?? "";
    show(
      h(
        "div",
        { class: "pk-body", attrs: { role: "dialog", "aria-label": tr("Passkey", "Passkey") } },
        header(tr("Enregistrer une passkey", "Save a passkey"), i.rpId),
        h(
          "div",
          { class: "pk-card" },
          tile(initial(i.rpId), TILE, "l"),
          h("span", { class: "stack" }, h("span", { class: "t1" }, userName), h("span", { class: "t2" }, i.rpId)),
        ),
        h(
          "p",
          { class: "pk-lead" },
          tr("La clé privée reste dans OnePass. Le site ne reçoit que la clé publique.", "The private key stays in OnePass. The site only gets the public key."),
        ),
        vaults.length > 1 ? h("label", { class: "pk-field" }, h("span", { class: "t2" }, tr("Coffre", "Vault")), sel) : null,
        errLine,
        h("footer", { class: "pk-actions" }, other(), h("span", { class: "pk-gap" }), cancel(), save),
      ),
    );
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
    if (r.value.kind === "get") renderGet(r.value);
    else renderCreate(r.value);
    (container.querySelector("button.pk-row, button.btn-primary") as HTMLButtonElement | null)?.focus({ preventScroll: true });
  })();
  return { ready };
}

// ---- real start (not in tests: no extension runtime there) ----

if (ext?.runtime?.id && typeof document !== "undefined") {
  const root = document.getElementById("root");
  if (root) mountPasskey(root, { send: (m) => ext.runtime.sendMessage(m), hash: location.hash });
}
