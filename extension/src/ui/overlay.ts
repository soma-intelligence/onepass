// "Connexion en un clic" overlay (spec 8.6, Inline mockup). It lists the
// ways to sign in, starts the chain on a click, then renders the steps the
// service worker reports (it polls `overlay_state` while the chain runs).
// The overlay computes no progress of its own.
import { ext } from "../shared/browser";
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

export const HELP_TEXT = "Un clic enchaîne toutes les étapes. Arrêt automatique si le domaine change ou sur un CAPTCHA.";

/** Spec 8.6 stop reasons, word for word. */
export function stopText(reason: StopReason, host?: string): string {
  switch (reason) {
    case "domain":
      return `Le domaine a changé : ${host ?? ""}`.trimEnd();
    case "captcha":
      return "CAPTCHA détecté, à toi de jouer";
    case "push":
      return "Valide la connexion sur ton téléphone";
    case "otp":
      return "Code reçu par SMS ou email : saisis-le";
    case "unknown":
      return "Étape inconnue, termine à la main";
    case "timeout":
      return "Délai de 60 s dépassé";
    case "user":
      return "Arrêté";
    case "locked":
      return "OnePass est verrouillé";
    case "repeat":
      return "Mot de passe refusé par le site";
  }
}

const STATE_TEXT: Readonly<Record<StepState, string>> = {
  pending: "en attente",
  active: "en cours",
  done: "fait",
  stopped: "arrêté",
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
  const container = h("div", { class: "overlay", attrs: { role: "dialog", "aria-label": "Connexion en un clic" } });
  mount(root, container);
  (deps.observe ?? observeVisibility)(container, (v) => guard.setVisibility(v));

  let init: OverlayInit | null = null;
  let timer: unknown = null;
  let shownStatus: ChainView["status"] | null = null;

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
      h("h1", { class: "ov-title" }, origin ? `Se connecter à ${hostOf(origin)}` : "Connexion en un clic"),
      h(
        "button",
        {
          class: "btn-icon",
          attrs: { type: "button", "aria-label": "Fermer" },
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
    const title =
      code === "unpaired" ? "Appairer OnePass depuis la barre d'outils" : code === "locked" ? "OnePass est verrouillé" : errorText(code);
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
    shownStatus = null;
    if (!init) return;
    const list = h("div", { class: "ov-accounts" });
    for (const a of init.accounts) {
      list.append(
        h(
          "div",
          { class: "ov-account" },
          tile(a.iconLetter, a.iconColor, "m"),
          h("span", { class: "stack" }, h("span", { class: "t1" }, a.title), h("span", { class: "t2" }, a.subtitle)),
          h(
            "button",
            { class: "btn btn-primary", attrs: { type: "button" }, on: { click: guard.wrap(() => void start(a)()) } },
            "Se connecter",
          ),
        ),
      );
    }
    if (init.accounts.length === 0) list.append(messageBlock(`Aucun login pour ${hostOf(init.origin)}`));
    mount(container, head(init.origin), list, h("p", { class: "ov-help" }, HELP_TEXT));
    guard.reset();
  }

  function renderChain(c: ChainView): void {
    const steps = h("div", { class: "ov-steps", attrs: { role: "list" } });
    for (const s of c.steps) {
      const dot = h("span", { class: `dot dot-${s.state}`, attrs: { "aria-hidden": "true" } });
      if (s.state === "done") dot.append(icon("check", 10));
      if (s.state === "stopped") dot.append("!");
      steps.append(
        h(
          "div",
          { class: `ov-step ${s.state}`, attrs: { role: "listitem" } },
          dot,
          h(
            "span",
            { class: "stack" },
            h("span", { class: "ov-step-label" }, s.label),
            s.detail ? h("span", { class: "t2" }, s.detail) : null,
          ),
          srOnly(STATE_TEXT[s.state]),
        ),
      );
    }
    let status = "En cours…";
    let tone = "";
    if (c.status === "done") {
      status = "Connecté";
      tone = "ok";
    } else if (c.status !== "running") {
      status = c.reason ? stopText(c.reason, c.host) : "Arrêté";
      tone = "warn";
    }
    const foot = h("div", { class: "ov-foot" }, h("span", { class: `ov-status ${tone}`, attrs: { role: "status" } }, status));
    if (c.status === "running") {
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
          "Arrêter",
        ),
      );
    } else {
      stopPolling();
      foot.append(
        h("button", { class: "btn btn-primary", attrs: { type: "button" }, on: { click: guard.wrap(() => renderIdle()) } }, "Recommencer"),
      );
    }
    mount(container, head(init?.origin ?? null), steps, foot);
    // New buttons under the pointer ("Recommencer" where "Arrêter" was).
    if (c.status !== shownStatus) guard.reset();
    shownStatus = c.status;
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
