import { describe, expect, it } from "vitest";
import type { UiToBg } from "../../src/shared/messages";
import type { ChainView, OverlayAccount, StopReason } from "../../src/shared/ui";
import type { Timers } from "../../src/ui/components";
import { setLang } from "../../src/shared/i18n";
import { DONE_CLOSE_MS, STEPS_PREF, mountOverlay, stopHint, stopText } from "../../src/ui/overlay";
import { Clock, FakeWorker, HASH, type Reply, TOKEN, button, flush, root, text } from "./helpers";

const SITE = "https://atlas-cloud.test";
const accounts: OverlayAccount[] = [
  { itemId: "it_01", title: "Atlas Cloud", subtitle: "alex@atlas.dev", iconLetter: "A", iconColor: "#14532D", totp: true },
  {
    itemId: "it_02",
    title: "Atlas Perso",
    subtitle: "alex.perso@example.com",
    iconLetter: "A",
    iconColor: "#14532D",
    provider: "google",
    email: "alex.perso@example.com",
    accountId: "g_perso",
    accounts: [
      { itemId: "g_perso", email: "alex.perso@example.com", title: "Google perso" },
      { itemId: "g_pro", email: "alex.pro@example.com", title: "Google pro" },
    ],
  },
];

class ManualTimers implements Timers {
  intervals = new Map<number, () => void>();
  timeouts = new Map<number, { fn: () => void; ms: number }>();
  private n = 0;
  setTimeout(fn: () => void, ms: number) {
    this.timeouts.set(++this.n, { fn, ms });
    return this.n;
  }
  clearTimeout(id: unknown) {
    this.timeouts.delete(id as number);
  }
  setInterval(fn: () => void) {
    this.intervals.set(++this.n, fn);
    return this.n;
  }
  clearInterval(id: unknown) {
    this.intervals.delete(id as number);
  }
  /** Runs every pending timeout of `ms`. */
  fire(ms: number) {
    for (const [id, t] of [...this.timeouts]) {
      if (t.ms !== ms) continue;
      this.timeouts.delete(id);
      t.fn();
    }
  }
}

function setup(
  chainState: () => ChainView | null,
  initChain: ChainView | null = null,
  extra?: (m: UiToBg) => Reply | null,
  prefs?: Map<string, unknown>,
) {
  const r = root();
  const clock = new Clock();
  const timers = new ManualTimers();
  const sizes: (() => void)[] = [];
  const worker = new FakeWorker((m) => {
    const x = extra?.(m);
    if (x) return x;
    if (m.type === "overlay_init") return { ok: { origin: SITE, accounts, chain: initChain } };
    if (m.type === "overlay_state") return { ok: { chain: chainState() } };
    return { ok: {} };
  });
  const handle = mountOverlay(r, {
    send: worker.send,
    hash: HASH,
    now: clock.now,
    trusted: () => true,
    observe: () => undefined,
    observeSize: (_el, cb) => void sizes.push(cb),
    timers,
    ...(prefs
      ? {
          prefs: {
            get: async (k: string) => prefs.get(k),
            set: async (k: string, v: unknown) => void prefs.set(k, v),
          },
        }
      : {}),
  });
  // Clicks are accepted 300 ms after the content appeared.
  const ready = handle.ready.then(() => clock.advance(300));
  return { r, clock, worker, handle: { ready, poll: handle.poll }, timers, sizes };
}

const running: ChainView = {
  itemId: "it_02",
  status: "running",
  title: "Atlas Perso",
  provider: "google",
  email: "alex.perso@example.com",
  site: "atlas-cloud.test",
  phase: "opening",
  steps: [{ label: "Clic sur « Continuer avec Google »", state: "done" }],
};

const rows = (r: HTMLElement) => [...r.querySelectorAll<HTMLButtonElement>(".ov-account > button.row")];
/** What a row says, part by part: title, second line, action. */
const says = (el: Element) => [...el.querySelectorAll(".t1, .line2, .pill")].map((x) => x.textContent).join(" | ");
const frame = () => new Promise((r) => setTimeout(r, 40));
/** Opens the pill's dropdown (the other ways); clicks are accepted again 300 ms later. */
const openAll = (r: HTMLElement, clock: Clock) => {
  r.querySelector<HTMLButtonElement>(".ov-more")!.click();
  clock.advance(300);
};

describe("overlay", () => {
  it("offer: one row per way to sign in, each saying how, one filled action", async () => {
    const { r, handle, worker, clock } = setup(() => null);
    await handle.ready;
    expect(worker.sent[0]).toEqual({ type: "overlay_init", token: TOKEN });
    expect(text(r)).toContain("Se connecter à atlas-cloud.test");
    openAll(r, clock);
    const [pwd, google] = rows(r);
    expect(says(pwd!)).toBe("Atlas Cloud | alex@atlas.dev · mot de passe et code | Se connecter");
    expect(says(google!)).toBe("Atlas Perso | Avec Google · alex.perso@example.com | Se connecter");
    // The provider's glyph rides on the item's art; no brand artwork.
    expect(google!.querySelector(".way-badge svg.glyph-p_google")).not.toBeNull();
    expect(pwd!.querySelector(".way-badge")).toBeNull();
    expect(r.querySelectorAll(".pill-primary")).toHaveLength(1);
    expect(r.querySelector(".row-fold")!.textContent).toBe("Autre compte Google");
  });

  it("the pill shows one way only: the other ways and their accounts row are not rendered until the dropdown opens", async () => {
    // Two Google ways with other accounts each (the linear.app report: "Other Google accounts" twice).
    const google = accounts[1]!;
    const two: OverlayAccount[] = [
      { ...google, itemId: "it_02", title: "Linear" },
      { ...google, itemId: "it_03", title: "Linear" },
    ];
    const { r, handle, clock } = setup(() => null, null, (m) => (m.type === "overlay_init" ? { ok: { origin: SITE, accounts: two, chain: null } } : null));
    await handle.ready;
    expect(r.querySelectorAll(".ov-account")).toHaveLength(1);
    expect(r.querySelectorAll(".row-fold")).toHaveLength(1);
    expect(r.querySelectorAll("[hidden]")).toHaveLength(0);
    openAll(r, clock);
    expect(rows(r)).toHaveLength(2);
    expect(r.querySelectorAll(".row-fold")).toHaveLength(2);
  });

  it("a click on a row starts the chain; the progress replaces the offer in place", async () => {
    const { r, handle, worker, timers, clock } = setup(() => running);
    await handle.ready;
    openAll(r, clock);
    rows(r)[1]!.click();
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "overlay_start", token: TOKEN, itemId: "it_02", provider: "google", accountId: "g_perso" });
    expect(timers.intervals.size).toBe(1);
    // Before the first poll: the account and the first line, at once.
    expect(says(r.querySelector(".ov-who")!)).toBe("Atlas Perso | Avec Google · alex.perso@example.com");
    expect(r.querySelector(".ov-status")!.textContent).toBe("Ouverture de Google…");
    expect(button(r, "Annuler")).toBeTruthy();
  });

  it("the inline picker starts with the other account of the provider", async () => {
    const { r, handle, worker, clock } = setup(() => running);
    await handle.ready;
    openAll(r, clock);
    button(r, "Autre compte Google").click();
    expect(r.querySelector(".row-fold")!.getAttribute("aria-expanded")).toBe("true");
    const sub = r.querySelector<HTMLButtonElement>('.ov-sub[data-account="g_pro"] > button')!;
    expect(says(sub)).toBe("alex.pro@example.com | Google · Google pro | Se connecter");
    clock.advance(300);
    sub.click();
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "overlay_start", token: TOKEN, itemId: "it_02", provider: "google", accountId: "g_pro" });
    expect(text(r.querySelector(".ov-who")!)).toContain("alex.pro@example.com");
  });

  it("polls update only the line that says what happens now; Annuler keeps its node and focus", async () => {
    let state: ChainView = running;
    const { r, handle } = setup(() => state, running);
    await handle.ready;
    const cancel = button(r, "Annuler");
    cancel.focus();
    const status = r.querySelector(".ov-status");
    await handle.poll();
    state = { ...running, phase: "choosing", steps: [...running.steps, { label: "Compte choisi : alex.perso@example.com", state: "done" }] };
    await handle.poll();
    expect(button(r, "Annuler")).toBe(cancel);
    expect(document.activeElement).toBe(cancel);
    expect(r.querySelector(".ov-status")).toBe(status);
    expect(status!.textContent).toBe("Choix de alex.perso@example.com…");
  });

  it("a password login lists its steps: done ones checked, the one under way, the ones ahead", async () => {
    const pwd: ChainView = { itemId: "it_01", status: "running", title: "Atlas Cloud", email: "alex@atlas.dev", phase: "signin", steps: [] };
    let now: ChainView = { ...pwd, steps: [{ label: "x", state: "done", what: "user" }] };
    const { r, handle } = setup(() => now, pwd, undefined, new Map([[STEPS_PREF, true]]));
    await handle.ready;
    const items = () => [...r.querySelectorAll(".ov-steps > li")].map((li) => `${li.className}: ${li.querySelector(".ov-step-label, .ov-status")!.textContent}`);
    // At load: the username under way, the password and the code ahead.
    expect(items()).toEqual(["ov-step ov-now: Connexion…", "ov-step pending: Mot de passe", "ov-step pending: Code de vérification"]);
    const status = r.querySelector(".ov-status");
    await handle.poll();
    expect(items()).toEqual(["ov-step done: Identifiant rempli", "ov-step ov-now: Connexion…", "ov-step pending: Code de vérification"]);
    now = { ...now, steps: [...now.steps, { label: "y", state: "done", what: "password" }] };
    await handle.poll();
    expect(items()).toEqual(["ov-step done: Identifiant rempli", "ov-step done: Mot de passe rempli", "ov-step ov-now: Connexion…"]);
    // The line under way keeps its node.
    expect(r.querySelector(".ov-status")).toBe(status);
  });

  it("while it runs: one line, the steps folded under Détails, the choice kept", async () => {
    const pwd: ChainView = { itemId: "it_01", status: "running", title: "Atlas Cloud", email: "alex@atlas.dev", phase: "signin", steps: [{ label: "x", state: "done", what: "user" }] };
    const prefs = new Map<string, unknown>();
    const { r, handle, clock } = setup(() => pwd, pwd, undefined, prefs);
    await handle.ready;
    const shown = () => [...r.querySelectorAll<HTMLElement>(".ov-steps > li")].filter((li) => !li.hidden).map((li) => li.querySelector(".ov-step-label, .ov-status")!.textContent);
    const details = r.querySelector<HTMLButtonElement>("button.ov-details")!;
    // Folded by default: only what happens now, read out by a live region.
    expect(shown()).toEqual(["Connexion…"]);
    expect(r.querySelector(".ov-status")!.getAttribute("role")).toBe("status");
    expect(details.textContent).toBe("Détails");
    expect(details.getAttribute("aria-expanded")).toBe("false");
    expect(details.getAttribute("aria-controls")).toBe(r.querySelector(".ov-steps")!.id);
    details.click();
    expect(shown()).toEqual(["Identifiant rempli", "Connexion…", "Code de vérification"]);
    expect(details.getAttribute("aria-expanded")).toBe("true");
    expect(prefs.get(STEPS_PREF)).toBe(true);
    // A poll keeps the choice and the button's node.
    await handle.poll();
    expect(r.querySelector("button.ov-details")).toBe(details);
    expect(shown()).toHaveLength(3);
    clock.advance(0);
    details.click();
    expect(shown()).toEqual(["Connexion…"]);
    expect(prefs.get(STEPS_PREF)).toBe(false);
  });

  it("the steps open at load when this browser kept them open; Details in English", async () => {
    setLang("en");
    try {
      const pwd: ChainView = { itemId: "it_01", status: "running", title: "Atlas Cloud", email: "alex@atlas.dev", phase: "signin", steps: [] };
      const { r, handle } = setup(() => pwd, pwd, undefined, new Map([[STEPS_PREF, true]]));
      await handle.ready;
      const details = r.querySelector<HTMLButtonElement>("button.ov-details")!;
      expect(details.textContent).toBe("Details");
      expect(details.getAttribute("aria-expanded")).toBe("true");
      expect([...r.querySelectorAll<HTMLElement>(".ov-steps > li")].every((li) => !li.hidden)).toBe(true);
      expect(r.querySelector(".ov-cancel")!.textContent).toBe("Cancel");
    } finally {
      setLang("fr");
    }
  });

  it("the close button beside a running chain stops it", async () => {
    const { r, handle, worker } = setup(() => running, running);
    await handle.ready;
    r.querySelector<HTMLButtonElement>("button[aria-label=Fermer]")!.click();
    await flush();
    await flush();
    expect(worker.types().slice(-2)).toEqual(["overlay_stop", "overlay_close"]);
  });

  it("Annuler stops the chain and closes the card", async () => {
    const { r, handle, worker } = setup(() => running, running);
    await handle.ready;
    button(r, "Annuler").click();
    await flush();
    await flush();
    expect(worker.types().slice(-2)).toEqual(["overlay_stop", "overlay_close"]);
  });

  it("done: a single check, no steps, then the card leaves by itself", async () => {
    const done: ChainView = {
      ...running,
      status: "done",
      steps: [
        { label: "Clicked \"Continue with Google\"", state: "done", what: "click" },
        { label: "Account chosen: alex.perso@example.com", state: "done", what: "account", onProvider: true },
        { label: "Google password filled", state: "done", what: "password", onProvider: true },
        { label: "Back on Atlas Perso", state: "done", what: "end" },
      ],
    };
    const { r, handle, worker, timers } = setup(() => done, running);
    await handle.ready;
    await handle.poll();
    expect(r.querySelector(".ov-status")!.textContent).toBe("Connecté");
    // Only the check: the words stay for screen readers, the steps are not listed.
    expect(r.querySelector(".ov-status .dot-big")).not.toBeNull();
    expect(r.querySelectorAll(".ov-step-label")).toHaveLength(0);
    expect(timers.intervals.size).toBe(0);
    timers.fire(DONE_CLOSE_MS);
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "overlay_close", token: TOKEN });
  });

  it("every stop reason, word for word, with what to do next", async () => {
    const want: Record<StopReason, string> = {
      domain: "Le domaine a changé : evil.test",
      captcha: "CAPTCHA détecté, à toi de jouer",
      push: "Valide la connexion sur ton téléphone",
      otp: "Code reçu par SMS ou email : saisis-le",
      unknown: "Étape inconnue, termine à la main",
      timeout: "Délai de 60 s dépassé",
      user: "Arrêté",
      locked: "OnePass est verrouillé",
      repeat: "Mot de passe refusé par le site",
      account: "alex.perso@example.com n'est pas proposé par Google",
    };
    for (const [reason, sentence] of Object.entries(want) as [StopReason, string][]) {
      expect(stopText(reason, "evil.test", "alex.perso@example.com", "google")).toBe(sentence);
      const { r, handle } = setup(() => ({ ...running, status: reason === "user" ? "stopped" : "handoff", reason, host: "evil.test" }), running);
      await handle.ready;
      await handle.poll();
      expect(r.querySelector(".ov-status")!.textContent).toBe(sentence);
      if (reason !== "user") {
        expect(stopHint(reason, "atlas-cloud.test", "google").length).toBeGreaterThan(20);
        expect(r.querySelector(".ov-hint")!.textContent).toBe(stopHint(reason, "atlas-cloud.test", "google"));
      }
    }
    expect(stopHint("domain", "atlas-cloud.test", "google")).toContain("atlas-cloud.test et les pages officielles de Google");
  });

  it("Réessayer only where trying again can help, with the same way to sign in", async () => {
    const timeout: ChainView = { ...running, status: "handoff", reason: "timeout" };
    let s = setup(() => timeout, running);
    await s.handle.ready;
    await s.handle.poll();
    s.clock.advance(300);
    button(s.r, "Réessayer").click();
    await flush();
    expect(s.worker.sent.find((m) => m.type === "overlay_start")).toEqual({
      type: "overlay_start",
      token: TOKEN,
      itemId: "it_02",
      provider: "google",
      accountId: "g_perso",
    });
    s = setup(() => ({ ...running, status: "handoff", reason: "captcha" }), running);
    await s.handle.ready;
    await s.handle.poll();
    expect(text(s.r)).not.toContain("Réessayer");
  });

  it("resumes a running chain at load and closes on ×", async () => {
    const ended: ChainView = { ...running, status: "handoff", reason: "captcha" };
    const { r, handle, worker, timers, clock } = setup(() => ended, running);
    await handle.ready;
    expect(r.querySelector(".ov-status")!.textContent).toBe("Ouverture de Google…");
    expect(timers.intervals.size).toBe(1);
    await handle.poll();
    clock.advance(300);
    r.querySelector<HTMLButtonElement>("button[aria-label=Fermer]")!.click();
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "overlay_close", token: TOKEN });
    expect(timers.intervals.size).toBe(0);
  });

  it("reports its content height for the frame", async () => {
    const { handle, worker, sizes } = setup(() => null);
    await handle.ready;
    expect(sizes).toHaveLength(1);
    // jsdom has no layout: whatever the height, it is reported once per change.
    Object.defineProperty(document.querySelector(".overlay")!, "scrollHeight", { configurable: true, value: 212 });
    sizes[0]!();
    await frame();
    sizes[0]!();
    await frame();
    expect(worker.sent.filter((m) => m.type === "overlay_resize")).toEqual([{ type: "overlay_resize", token: TOKEN, height: 212 }]);
  });

  it("locked and unpaired states", async () => {
    let s = setup(() => null, null, (m) => (m.type === "overlay_init" ? { err: "locked" } : null));
    await s.handle.ready;
    expect(text(s.r)).toContain("OnePass est verrouillé");
    s = setup(() => null, null, (m) => (m.type === "overlay_init" ? { err: "unpaired" } : null));
    await s.handle.ready;
    expect(text(s.r)).toContain("Appairer OnePass depuis la barre d'outils");
  });

  it("rejects a malformed chain view", async () => {
    const { r, handle } = setup(() => ({ itemId: "it_01", status: "pwned", steps: [] }) as unknown as ChainView, running);
    await handle.ready;
    await handle.poll();
    expect(text(r)).toContain("Erreur interne de OnePass.");
  });
});
