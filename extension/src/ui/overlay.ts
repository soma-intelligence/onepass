// "Connexion en un clic" overlay (spec 8.6, Inline mockup). It lists the
// ways to sign in, starts the chain on a click, then renders the steps the
// service worker reports (it polls `overlay_state` while the chain runs).
// The overlay computes no progress of its own.
import { ext } from "../shared/browser";
import { tr } from "../shared/i18n";
import type { ChainView, OverlayAccount, OverlayInit, StepState, StopReason } from "../shared/ui";
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
  realTimers,
  srOnly,
  tile,
  tokenFromHash,
} from "./components";
import { parseEmpty, parseOverlayInit, parseOverlayState } from "./parse";

export const POLL_MS = 500;

export const HELP_TEXT = tr(
  "Un clic enchaîne toutes les étapes. Arrêt automatique si le domaine change ou sur un CAPTCHA.",
  "One click runs every step. It stops by itself if the domain changes or on a CAPTCHA.",
);

/** Spec 8.6 stop reasons, word for word. */
export function stopText(reason: StopReason, host?: string): string {
  switch (reason) {
    case "domain":
      return tr(`Le domaine a changé : ${host ?? ""}`, `The domain changed: ${host ?? ""}`).trimEnd();
    case "captcha":
      return tr("CAPTCHA détecté, à toi de jouer", "CAPTCHA detected, your turn");
    case "push":
      return tr("Valide la connexion sur ton téléphone", "Approve the sign-in on your phone");
    case "otp":
      return tr("Code reçu par SMS ou email : saisis-le", "Code sent by SMS or email: type it in");
    case "unknown":
      return tr("Étape inconnue, termine à la main", "Unknown step, finish by hand");
    case "timeout":
      return tr("Délai de 60 s dépassé", "60 s limit reached");
    case "user":
      return tr("Arrêté", "Stopped");
    case "locked":
      return tr("OnePass est verrouillé", "OnePass is locked");
    case "repeat":
      return tr("Mot de passe refusé par le site", "Password refused by the site");
  }
}

const STATE_TEXT: Readonly<Record<StepState, string>> = {
  pending: tr("en attente", "pending"),
  active: tr("en cours", "in progress"),
  done: tr("fait", "done"),
  stopped: tr("arrêté", "stopped"),
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
  const container = h("div", { class: "overlay", attrs: { role: "dialog", "aria-label": tr("Connexion en un clic", "One-click sign-in") } });
  mount(root, container);
  (deps.observe ?? observeVisibility)(container, (v) => guard.setVisibility(v));

  let init: OverlayInit | null = null;
  let timer: unknown = null;
  let chainUi: { mode: "running" | "ended"; steps: HTMLElement; status: HTMLElement; last: string } | null = null;

  const stopPolling = () => {
    if (timer !== null) timers.clearInterval(timer);
    timer = null;
  };
  const startPolling = () => {
    if (timer === null) timer = timers.setInterval(() => void poll(), POLL_MS);
  };

  const head = (origin: string | null) =>
    h(
      "div",
      { class: "ov-head" },
      mark("m"),
      h("h1", { class: "ov-title" }, origin ? tr(`Se connecter à ${hostOf(origin)}`, `Sign in to ${hostOf(origin)}`) : tr("Connexion en un clic", "One-click sign-in")),
      h(
        "button",
        {
          class: "btn-icon",
          attrs: { type: "button", "aria-label": tr("Fermer", "Close") },
          on: {
            click: guard.wrap(() => {
              stopPolling();
              if (token) void call(deps.send, { type: "overlay_close", token }, parseEmpty);
            }),
          },
        },
        icon("close", 10),
      ),
    );

  const renderMessage = (code: string) => {
    stopPolling();
    chainUi = null;
    const title =
      code === "unpaired"
        ? tr("Appairer OnePass depuis la barre d'outils", "Pair OnePass from the toolbar")
        : code === "locked"
          ? tr("OnePass est verrouillé", "OnePass is locked")
          : errorText(code);
    mount(container, head(init?.origin ?? null), messageBlock(title));
    guard.reset();
  };

  const start = (a: OverlayAccount) => async () => {
    if (!token) return;
    const msg = a.provider
      ? ({ type: "overlay_start", token, itemId: a.itemId, provider: a.provider } as const)
      : ({ type: "overlay_start", token, itemId: a.itemId } as const);
    const r = await call(deps.send, msg, parseEmpty);
    if (!r.ok) {
      renderMessage(r.code);
      return;
    }
    renderChain({ itemId: a.itemId, status: "running", steps: [] });
    startPolling();
  };

  function renderIdle(): void {
    stopPolling();
    chainUi = null;
    if (!init) return;
    const list = h("div", { class: "ov-accounts" });
    const card = h("div", { class: "card" });
    for (const a of init.accounts) {
      card.append(
        h(
          "div",
          { class: "ov-account" },
          tile(a.iconLetter, a.iconColor, "m"),
          h("span", { class: "stack" }, h("span", { class: "t1" }, a.title), h("span", { class: "t2" }, a.subtitle)),
          h(
            "button",
            { class: "btn btn-primary", attrs: { type: "button" }, on: { click: guard.wrap(() => void start(a)()) } },
            tr("Se connecter", "Sign in"),
          ),
        ),
      );
    }
    if (init.accounts.length > 0) list.append(card);
    else list.append(messageBlock(tr(`Aucun login pour ${hostOf(init.origin)}`, `No login for ${hostOf(init.origin)}`)));
    mount(container, head(init.origin), list, h("p", { class: "ov-help" }, HELP_TEXT));
    guard.reset();
  }

  const stepNode = (s: ChainView["steps"][number]) => {
    const dot = h("span", { class: `dot dot-${s.state}`, attrs: { "aria-hidden": "true" } });
    if (s.state === "done") dot.append(icon("check", 10));
    if (s.state === "stopped") dot.append("!");
    return h(
      "div",
      { class: `ov-step ${s.state}`, attrs: { role: "listitem" } },
      dot,
      h("span", { class: "stack" }, h("span", { class: "ov-step-label" }, s.label), s.detail ? h("span", { class: "t2" }, s.detail) : null),
      srOnly(STATE_TEXT[s.state]),
    );
  };

  /**
   * Polls arrive every 500 ms: an identical reply renders nothing, a changed
   * one updates the steps and status in place. The skeleton (and its
   * "Arrêter" / "Recommencer" button) is rebuilt only when the chain moves
   * between running and ended, which also re-arms the click delay.
   */
  function renderChain(c: ChainView): void {
    const key = JSON.stringify(c);
    if (chainUi && chainUi.last === key) return;
    const mode = c.status === "running" ? "running" : "ended";
    if (!chainUi || chainUi.mode !== mode) {
      const steps = h("div", { class: "ov-steps", attrs: { role: "list" } });
      const status = h("span", { class: "ov-status", attrs: { role: "status" } });
      const foot = h("div", { class: "ov-foot" }, status);
      if (mode === "running") {
        foot.append(
          h(
            "button",
            {
              class: "btn",
              attrs: { type: "button" },
              on: {
                click: guard.wrap(() => {
                  if (token) void call(deps.send, { type: "overlay_stop", token }, parseEmpty).then(() => poll());
                }),
              },
            },
            tr("Arrêter", "Stop"),
          ),
        );
      } else {
        stopPolling();
        foot.append(
          h("button", { class: "btn btn-primary", attrs: { type: "button" }, on: { click: guard.wrap(() => renderIdle()) } }, tr("Recommencer", "Start over")),
        );
      }
      mount(container, head(init?.origin ?? null), steps, foot);
      // New buttons under the pointer ("Recommencer" where "Arrêter" was).
      guard.reset();
      chainUi = { mode, steps, status, last: "" };
    }
    mount(chainUi.steps, ...c.steps.map(stepNode));
    let text = tr("En cours…", "In progress…");
    let tone = "";
    if (c.status === "done") {
      text = tr("Connecté", "Signed in");
      tone = "ok";
    } else if (c.status !== "running") {
      text = c.reason ? stopText(c.reason, c.host) : tr("Arrêté", "Stopped");
      tone = "warn";
    }
    const lead = tone === "ok" ? h("span", { class: "dot dot-done", attrs: { "aria-hidden": "true" } }, icon("check", 10)) : tone === "warn" ? icon("alert", 16) : null;
    mount(chainUi.status, lead, text);
    chainUi.status.className = `ov-status ${tone}`.trimEnd();
    chainUi.last = key;
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

  mount(container, head(null));
  return { ready: load(), poll };
}

if (typeof document !== "undefined" && ext?.runtime?.id) {
  const root = document.getElementById("root");
  if (root) mountOverlay(root, { send: (m) => ext.runtime.sendMessage(m), hash: location.hash });
}
