import { describe, expect, it } from "vitest";
import type { UiToBg } from "../../src/shared/messages";
import type { ChainView, StopReason } from "../../src/shared/ui";
import type { Timers } from "../../src/ui/components";
import { HELP_TEXT, mountOverlay, stopText } from "../../src/ui/overlay";
import { Clock, FakeWorker, HASH, type Reply, TOKEN, button, flush, root, text } from "./helpers";

const SITE = "https://atlas-cloud.test";
const accounts = [
  { itemId: "it_01", title: "Atlas Cloud", subtitle: "alex@atlas.dev", iconLetter: "A", iconColor: "#14532D" },
  {
    itemId: "it_02",
    title: "Atlas Perso via Google",
    subtitle: "Se connecter avec Google (alex.perso@example.com)",
    iconLetter: "A",
    iconColor: "#14532D",
    provider: "google",
    email: "alex.perso@example.com",
  },
];

class ManualTimers implements Timers {
  intervals = new Map<number, () => void>();
  private n = 0;
  setTimeout() {
    return 0;
  }
  clearTimeout() {}
  setInterval(fn: () => void) {
    this.intervals.set(++this.n, fn);
    return this.n;
  }
  clearInterval(id: unknown) {
    this.intervals.delete(id as number);
  }
}

function setup(chainState: () => ChainView | null, initChain: ChainView | null = null, extra?: (m: UiToBg) => Reply | null) {
  const r = root();
  const clock = new Clock();
  const timers = new ManualTimers();
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
    timers,
  });
  // Clicks are accepted 300 ms after the content appeared.
  const ready = handle.ready.then(() => clock.advance(300));
  return { r, clock, worker, handle: { ready, poll: handle.poll }, timers };
}

const running: ChainView = {
  itemId: "it_01",
  status: "running",
  steps: [
    { label: "Identifiant rempli", detail: "alex@atlas.dev", state: "done" },
    { label: "Mot de passe rempli", state: "active" },
    { label: "Code à usage unique", state: "pending" },
  ],
};

describe("overlay", () => {
  it("idle: accounts, Se connecter, help text", async () => {
    const { r, handle, worker } = setup(() => null);
    await handle.ready;
    expect(worker.sent[0]).toEqual({ type: "overlay_init", token: TOKEN });
    expect(text(r)).toContain("Se connecter à atlas-cloud.test");
    expect(text(r)).toContain("Atlas Cloud");
    expect(text(r)).toContain("Se connecter avec Google (alex.perso@example.com)");
    expect(r.querySelectorAll("button.btn-primary")).toHaveLength(2);
    expect(text(r)).toContain(HELP_TEXT);
  });

  it("Se connecter starts the chain, then renders the pushed steps", async () => {
    let state: ChainView | null = running;
    const { r, handle, worker, timers, clock } = setup(() => state);
    await handle.ready;
    const buttons = [...r.querySelectorAll<HTMLButtonElement>("button.btn-primary")];
    buttons[1]!.click();
    await flush();
    clock.advance(300);
    expect(worker.sent.at(-1)).toEqual({ type: "overlay_start", token: TOKEN, itemId: "it_02", provider: "google" });
    expect(timers.intervals.size).toBe(1);
    await handle.poll();
    expect(text(r)).toContain("Identifiant rempli");
    expect(text(r)).toContain("alex@atlas.dev");
    for (const s of ["fait", "en cours", "en attente"]) expect(text(r)).toContain(s);
    expect(text(r)).toContain("En cours…");
    expect(button(r, "Arrêter")).toBeTruthy();
    // Arrêter asks the worker; the worker's answer decides what is shown.
    state = { ...running, status: "stopped", reason: "user", steps: [{ label: "Identifiant rempli", state: "done" }, { label: "Mot de passe rempli", state: "stopped" }] };
    button(r, "Arrêter").click();
    await flush();
    expect(worker.types()).toContain("overlay_stop");
    expect(text(r)).toContain("Arrêté");
    expect(text(r)).toContain("arrêté");
    expect(timers.intervals.size).toBe(0);
    button(r, "Recommencer").click();
    expect(text(r)).not.toContain(HELP_TEXT);
    clock.advance(300);
    button(r, "Recommencer").click();
    expect(text(r)).toContain(HELP_TEXT);
  });

  it("polls keep the Arrêter node and its focus; changes update in place", async () => {
    let state: ChainView = running;
    const { r, handle } = setup(() => state, running);
    await handle.ready;
    const stop = button(r, "Arrêter");
    stop.focus();
    const steps = r.querySelector(".ov-steps");
    await handle.poll();
    await handle.poll();
    expect(button(r, "Arrêter")).toBe(stop);
    expect(document.activeElement).toBe(stop);
    // Identical reply: nothing re-rendered at all.
    expect(r.querySelector(".ov-steps")).toBe(steps);
    const firstStep = r.querySelector(".ov-step");
    await handle.poll();
    expect(r.querySelector(".ov-step")).toBe(firstStep);
    state = {
      ...running,
      steps: [running.steps[0]!, { label: "Mot de passe rempli", state: "done" }, { label: "Code à usage unique", state: "active" }],
    };
    await handle.poll();
    expect(button(r, "Arrêter")).toBe(stop);
    expect(document.activeElement).toBe(stop);
    expect(r.querySelector(".ov-step.active .ov-step-label")!.textContent).toBe("Code à usage unique");
  });

  it("done: Connecté", async () => {
    const { r, handle } = setup(() => ({ itemId: "it_01", status: "done", steps: [{ label: "Connecté", state: "done" }] }), running);
    await handle.ready;
    await handle.poll();
    expect(text(r)).toContain("Connecté");
    expect(button(r, "Recommencer")).toBeTruthy();
  });

  it("every stop reason, word for word", async () => {
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
    };
    for (const [reason, sentence] of Object.entries(want) as [StopReason, string][]) {
      expect(stopText(reason, "evil.test")).toBe(sentence);
      const { r, handle } = setup(() => ({ itemId: "it_01", status: "handoff", reason, host: "evil.test", steps: [] }), running);
      await handle.ready;
      await handle.poll();
      expect(text(r)).toContain(sentence);
    }
  });

  it("resumes a running chain at load and closes on ×", async () => {
    const { r, handle, worker, timers } = setup(() => running, running);
    await handle.ready;
    expect(text(r)).toContain("Mot de passe rempli");
    expect(timers.intervals.size).toBe(1);
    r.querySelector<HTMLButtonElement>("button[aria-label=Fermer]")!.click();
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "overlay_close", token: TOKEN });
    expect(timers.intervals.size).toBe(0);
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
