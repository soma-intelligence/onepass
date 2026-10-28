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
import { tr } from "../shared/i18n";
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

export const HELP_TEXT = tr(
  "Un clic enchaîne toutes les étapes. Arrêt automatique si le domaine change ou sur un CAPTCHA.",
  "One click runs every step. It stops by itself if the domain changes or on a CAPTCHA.",
);

/** Spec 8.6 stop reasons, word for word. */
export function stopText(reason: StopReason, host?: string, email?: string, provider?: ProviderId): string {
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
    case "account": {
      const p = provider ? providerLabel(provider) : tr("le fournisseur", "the provider");
      return email ? tr(`${email} n'est pas proposé par ${p}`, `${p} does not offer ${email}`) : tr(`Compte introuvable sur ${p}`, `Account not found on ${p}`);
    }
  }
}

/** The progress line of a running chain. */
export function phaseText(p: ChainPhase | undefined, c: Pick<ChainView, "provider" | "email" | "title">): string {
  const name = c.provider ? providerLabel(c.provider) : "";
  switch (p) {
    case "opening":
      return tr(`Ouverture de ${name}…`, `Opening ${name}…`);
    case "choosing":
      return tr(`Choix de ${c.email ?? ""}…`, `Choosing ${c.email ?? ""}…`);
    case "provider":
      return tr(`Connexion à ${name}…`, `Signing in to ${name}…`);
    case "back":
      return tr(`Retour sur ${c.title ?? ""}…`, `Back to ${c.title ?? ""}…`);
    case "code":
      return tr("Vérification du code…", "Checking the code…");
    default:
      return tr("Connexion…", "Signing in…");
  }
}

/** A step done, worded here (the worker's label is the fallback). */
export function stepText(st: ChainView["steps"][number], c: Pick<ChainView, "provider" | "email">): { label: string; detail?: string } {
  const name = c.provider ? providerLabel(c.provider) : "";
  const on = st.onProvider === true && name !== "";
  switch (st.what) {
    case "click":
      return { label: tr(`Clic sur « Continuer avec ${name} »`, `Clicked "Continue with ${name}"`) };
    case "account":
      return { label: tr(`Compte choisi sur ${name}`, `Account chosen on ${name}`), ...(c.email ? { detail: c.email } : {}) };
    case "user":
      return { label: on ? tr(`Identifiant ${name} rempli`, `${name} username filled`) : tr("Identifiant rempli", "Username filled") };
    case "password":
      return { label: on ? tr(`Mot de passe ${name} rempli`, `${name} password filled`) : tr("Mot de passe rempli", "Password filled") };
    case "both":
      return { label: on ? tr(`Identifiant et mot de passe ${name} remplis`, `${name} username and password filled`) : tr("Identifiant et mot de passe remplis", "Username and password filled") };
    case "otp":
      return { label: on ? tr(`Code ${name} rempli`, `${name} code filled`) : tr("Code à usage unique rempli", "One-time code filled") };
    default:
      return st.detail !== undefined ? { label: st.label, detail: st.detail } : { label: st.label };
  }
}

/** What to do next after a stop: one or two plain sentences. */
export function stopHint(reason: StopReason, site?: string, provider?: ProviderId): string {
  const p = provider ? providerLabel(provider) : null;
  switch (reason) {
    case "domain":
      return p
        ? tr(
            `OnePass n'agit que sur ${site ?? "ce site"} et les pages officielles de ${p}. Vérifie l'adresse avant de saisir quoi que ce soit.`,
            `OnePass only acts on ${site ?? "this site"} and ${p}'s official pages. Check the address before typing anything.`,
          )
        : tr(
            `OnePass n'agit que sur ${site ?? "ce site"}. Vérifie l'adresse avant de saisir quoi que ce soit.`,
            `OnePass only acts on ${site ?? "this site"}. Check the address before typing anything.`,
          );
    case "captcha":
      return tr("OnePass ne résout jamais de CAPTCHA. Fais la vérification sur la page, puis termine la connexion.", "OnePass never solves a CAPTCHA. Do the check on the page, then finish signing in.");
    case "push":
      return tr("Approuve la demande sur ton téléphone : la page continuera toute seule.", "Approve the request on your phone: the page carries on by itself.");
    case "otp":
      return tr("Ce login n'a pas de code à usage unique dans OnePass. Saisis celui que tu as reçu.", "This login has no one-time code in OnePass. Type the one you received.");
    case "unknown":
      return tr("OnePass ne reconnaît pas cette page et n'y a rien rempli. Termine la connexion toi-même.", "OnePass doesn't recognize this page and filled nothing on it. Finish signing in yourself.");
    case "timeout":
      return tr("La page a mis trop de temps à répondre. Réessaie quand elle est prête.", "The page took too long to answer. Try again once it's ready.");
    case "locked":
      return tr("Déverrouille OnePass, puis réessaie.", "Unlock OnePass, then try again.");
    case "repeat":
      return tr("Le mot de passe enregistré n'est peut-être plus le bon. Saisis-le toi-même : OnePass proposera de le mettre à jour.", "The saved password may be out of date. Type it yourself: OnePass will offer to update it.");
    case "account":
      return tr(
        `Choisis le compte sur la page, ou connecte-le d'abord à ${p ?? "ce fournisseur"}. La prochaine fois, OnePass le trouvera.`,
        `Pick the account on the page, or sign it in to ${p ?? "this provider"} first. Next time OnePass will find it.`,
      );
    case "user":
      return "";
  }
}

/** Stops where trying again from the site can help. */
const RETRY: ReadonlySet<StopReason> = new Set<StopReason>(["timeout", "locked"]);

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
      { class: "btn-icon", attrs: { type: "button", "aria-label": tr("Fermer", "Close") }, on: { click: guard.wrap(closeOverlay) } },
      icon("close", 10),
    );

  const head = (origin: string | null) =>
    h(
      "div",
      { class: "ov-head" },
      mark("s"),
      h("h1", { class: "ov-title" }, origin ? tr(`Se connecter à ${hostOf(origin)}`, `Sign in to ${hostOf(origin)}`) : tr("Connexion en un clic", "One-click sign-in")),
      closeButton(),
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
      ? h("span", { class: "line2" }, h("span", { class: "meta" }, tr(`Avec ${name} · `, `With ${name} · `)), h("span", { class: "t2" }, a.email ?? a.subtitle))
      : h(
          "span",
          { class: "line2" },
          h("span", { class: "t2" }, a.subtitle),
          h("span", { class: "meta" }, a.totp ? tr(" · mot de passe et code", " · password and code") : tr(" · mot de passe", " · password")),
        );
    const art = wayArt({ kind: "login", has_password: !a.provider, methods: [], icon_letter: a.iconLetter }, a.provider, "m");
    const row = h(
      "div",
      { class: "ov-account", attrs: a.provider ? { "data-provider": a.provider } : {} },
      h(
        "button",
        { class: "row ov-row", attrs: { type: "button" }, on: { click: guard.wrap(() => void start(a, a.accountId, a.email)()) } },
        art,
        h("span", { class: "stack" }, h("span", { class: "t1" }, a.title), line2),
        h("span", { class: primary ? "pill pill-primary" : "pill" }, tr("Se connecter", "Sign in")),
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
            h("span", { class: "pill" }, tr("Se connecter", "Sign in")),
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
    init.accounts.forEach((a, i) => list.append(...wayRow(a, i === 0)));
    if (init.accounts.length === 0) list.append(messageBlock(tr(`Aucun login pour ${hostOf(init.origin)}`, `No login for ${hostOf(init.origin)}`)));
    show(
      head(init.origin),
      list,
      h("p", { class: "ov-help" }, tr("Un clic suffit. OnePass s'arrête si le domaine change ou sur un CAPTCHA.", "One click is enough. OnePass stops if the domain changes or on a CAPTCHA.")),
    );
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
      wayArt({ kind: "login", has_password: !provider, methods: [], icon_letter: letter }, provider, "m"),
      h(
        "span",
        { class: "stack" },
        h("span", { class: "t1" }, title),
        h("span", { class: "line2" }, name ? h("span", { class: "meta" }, tr(`Avec ${name} · `, `With ${name} · `)) : null, h("span", { class: "t2" }, email)),
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
        const cancelBtn = h("button", { class: "btn-link ov-cancel", attrs: { type: "button" }, on: { click: guard.wrap(cancel) } }, tr("Annuler", "Cancel"));
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
    const parts: (Node | null)[] = [whoNode(c, closeButton())];
    if (done) {
      status.classList.add("ok");
      status.append(h("span", { class: "dot dot-done", attrs: { "aria-hidden": "true" } }, icon("check", 10)), tr("Connecté", "Signed in"));
      parts.push(h("div", { class: "ov-result" }, status));
    } else {
      const reason = c.reason ?? "user";
      status.classList.add("warn");
      status.append(icon("alert", 16), c.reason ? stopText(reason, c.host, c.email, c.provider) : tr("Arrêté", "Stopped"));
      const hint = stopHint(reason, c.site, c.provider);
      parts.push(h("div", { class: "ov-result" }, status, hint ? h("p", { class: "ov-hint" }, hint) : null));
    }
    if (steps.length > 0) parts.push(h("ul", { class: "ov-steps", attrs: { "aria-label": tr("Étapes faites", "Steps done") } }, ...steps.map(stepNode(c))));
    const again = !done && c.reason && RETRY.has(c.reason) ? retryFor(c) : undefined;
    if (again) {
      parts.push(
        h(
          "div",
          { class: "ov-foot" },
          h("button", { class: "btn btn-primary", attrs: { type: "button" }, on: { click: guard.wrap(() => void start(again, again.accountId, again.email)()) } }, tr("Réessayer", "Try again")),
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
