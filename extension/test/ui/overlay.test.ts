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

/** What a row says, part by part: title, second line, action. */
const says = (el: Element) => [...el.querySelectorAll(".t1, .line2")].map((x) => x.textContent).join(" | ");
const frame = () => new Promise((r) => setTimeout(r, 40));
/** Opens "Other logins"; clicks are accepted again 300 ms later. */
const openPicker = (r: HTMLElement, clock: Clock) => {
  r.querySelector<HTMLButtonElement>(".ov-others")!.click();
  clock.advance(300);
};
const opts = (r: HTMLElement) => [...r.querySelectorAll<HTMLElement>(".ov-opt")];
/** An option, part by part: title, then the account line. */
const optSays = (el: Element) => [...el.querySelectorAll(".t1, .ov-line2")].map((x) => x.textContent).join(" | ");
const key = (el: Element, k: string) => el.dispatchEvent(new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true }));
const typeIn = (input: HTMLInputElement, v: string) => {
  input.value = v;
  input.dispatchEvent(new Event("input", { bubbles: true }));
};
const withInit = (list: OverlayAccount[]) => (m: UiToBg): Reply | null => (m.type === "overlay_init" ? { ok: { origin: SITE, accounts: list, chain: null } } : null);

describe("overlay", () => {
  it("pill: the first login with its account in full, a text Sign in and x inside; Other logins hangs under it", async () => {
    const { r, handle, worker } = setup(() => null);
    await handle.ready;
    expect(worker.sent[0]).toEqual({ type: "overlay_init", token: TOKEN });
    expect(text(r)).toContain("Se connecter à atlas-cloud.test");
    const pill = r.querySelector(".ov-pill")!;
    expect(optSays(pill)).toBe("Atlas Cloud | alex@atlas.dev");
    expect(pill.querySelector(".ov-signin")!.textContent).toBe("Se connecter");
    expect(pill.querySelector(".ov-close")).not.toBeNull();
    expect(r.querySelector(".ov-others")!.textContent).toBe("Autres identifiants");
    // No chevron button, no rows to unfold inside the capsule.
    expect(r.querySelector(".ov-more, .row-fold, .pill-primary")).toBeNull();
    expect(r.querySelectorAll(".ov-pill")).toHaveLength(1);
  });

  it("pill with one login only: no Other logins", async () => {
    const { r, handle } = setup(() => null, null, withInit([accounts[0]!]));
    await handle.ready;
    expect(r.querySelector(".ov-others")).toBeNull();
  });

  it("exactly two logins: the other one hangs under the pill as its own row, one click signs in with it (no list to open)", async () => {
    const two: OverlayAccount[] = [
      { ...accounts[0]!, itemId: "it_last", title: "Atlas Cloud (2)", subtitle: "second@atlas.dev" },
      accounts[0]!,
    ];
    const { r, handle, worker, clock } = setup(() => null, null, withInit(two));
    await handle.ready;
    // The pill is the account used last on this site (the worker lists it first).
    expect(optSays(r.querySelector(".ov-pill")!)).toBe("Atlas Cloud (2) | second@atlas.dev");
    const other = r.querySelector<HTMLButtonElement>("button.ov-other")!;
    expect(optSays(other)).toBe("Atlas Cloud | alex@atlas.dev");
    expect(text(r)).not.toContain("Autres identifiants");
    expect(r.querySelector(".ov-picker")).toBeNull();
    clock.advance(300);
    other.click();
    await flush();
    expect(worker.sent.filter((m) => m.type === "overlay_start")).toEqual([{ type: "overlay_start", token: TOKEN, itemId: "it_01" }]);
    expect(text(r)).toContain("Connexion…");
  });

  it("three logins or more keep the searchable list behind Other logins", async () => {
    const three: OverlayAccount[] = [accounts[0]!, { ...accounts[0]!, itemId: "it_b", title: "B" }, { ...accounts[0]!, itemId: "it_c", title: "C" }];
    const { r, handle } = setup(() => null, null, withInit(three));
    await handle.ready;
    expect(r.querySelector("button.ov-other")).toBeNull();
    expect(r.querySelector(".ov-others")!.textContent).toBe("Autres identifiants");
  });

  it("two Google ways with other accounts each: one Other logins, never a row per hidden way", async () => {
    // The linear.app report: "Other Google accounts" twice.
    const google = accounts[1]!;
    const two: OverlayAccount[] = [
      { ...google, itemId: "it_02", title: "Linear" },
      { ...google, itemId: "it_03", title: "Linear" },
    ];
    const { r, handle, clock } = setup(() => null, null, withInit(two));
    await handle.ready;
    expect(r.querySelectorAll(".ov-others")).toHaveLength(1);
    expect(r.querySelectorAll("[hidden]")).toHaveLength(0);
    expect(text(r)).not.toContain("Autre compte Google");
    openPicker(r, clock);
    // Each way with its default account, then the provider's other account.
    expect(opts(r)).toHaveLength(4);
  });

  it("a Sign in with login: the provider's official mark on the icon, the provider before the account", async () => {
    const { r, handle, worker, timers } = setup(() => running, null, withInit([accounts[1]!, accounts[0]!]));
    await handle.ready;
    const pill = r.querySelector(".ov-pill")!;
    expect(optSays(pill)).toBe("Atlas Perso | Google · alex.perso@example.com");
    const mark = pill.querySelector(".brand-badge svg.mark-google")!;
    expect(mark.querySelectorAll("path")).toHaveLength(4);
    expect([...mark.querySelectorAll("path")].map((p) => p.getAttribute("fill"))).toEqual(["#EA4335", "#4285F4", "#FBBC05", "#34A853"]);
    button(r, "Se connecter").click();
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "overlay_start", token: TOKEN, itemId: "it_02", provider: "google", accountId: "g_perso" });
    expect(timers.intervals.size).toBe(1);
    // Before the first poll: the account and the first line, at once.
    expect(says(r.querySelector(".ov-who")!)).toBe("Atlas Perso | Avec Google · alex.perso@example.com");
    expect(r.querySelector(".ov-status")!.textContent).toBe("Ouverture de Google…");
    expect(button(r, "Annuler")).toBeTruthy();
  });

  it("Other logins: the search focused, every login with a key, the first selected; arrows and Enter start one", async () => {
    const { r, handle, worker, clock } = setup(() => running);
    await handle.ready;
    openPicker(r, clock);
    const input = r.querySelector<HTMLInputElement>(".ov-search")!;
    expect(input.placeholder).toBe("Tapez pour trouver un identifiant…");
    expect(input.ownerDocument.activeElement).toBe(input);
    expect(r.querySelector(".ov-picker .mark")).not.toBeNull();
    expect(opts(r).map(optSays)).toEqual([
      "Atlas Cloud | alex@atlas.dev",
      "Atlas Perso | Google · alex.perso@example.com",
      "Atlas Perso | Google · alex.pro@example.com",
    ]);
    expect(opts(r).every((o) => o.querySelector(".ov-key svg"))).toBe(true);
    const selected = () => opts(r).findIndex((o) => o.getAttribute("aria-selected") === "true");
    expect(selected()).toBe(0);
    key(input, "ArrowDown");
    key(input, "ArrowDown");
    expect(selected()).toBe(2);
    expect(opts(r)[2]!.classList.contains("selected")).toBe(true);
    key(input, "ArrowDown");
    expect(selected()).toBe(0);
    key(input, "ArrowUp");
    expect(selected()).toBe(2);
    key(input, "Enter");
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "overlay_start", token: TOKEN, itemId: "it_02", provider: "google", accountId: "g_pro" });
    expect(text(r.querySelector(".ov-who")!)).toContain("alex.pro@example.com");
  });

  it("Other logins: typing filters, nothing found says so, Escape goes back to the pill; the pointer selects and a click starts", async () => {
    const { r, handle, worker, clock } = setup(() => running);
    await handle.ready;
    openPicker(r, clock);
    const input = r.querySelector<HTMLInputElement>(".ov-search")!;
    typeIn(input, "PRO");
    expect(opts(r).map(optSays)).toEqual(["Atlas Perso | Google · alex.pro@example.com"]);
    typeIn(input, "zzz");
    expect(opts(r)).toHaveLength(0);
    expect(r.querySelector(".ov-none")!.textContent).toBe("Aucun identifiant ne correspond");
    key(input, "Escape");
    expect(r.querySelector(".ov-picker")).toBeNull();
    expect(r.querySelector(".ov-pill")).not.toBeNull();
    clock.advance(300);
    openPicker(r, clock);
    const second = opts(r)[1]!;
    second.dispatchEvent(new MouseEvent("mouseenter"));
    expect(second.getAttribute("aria-selected")).toBe("true");
    second.click();
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "overlay_start", token: TOKEN, itemId: "it_02", provider: "google", accountId: "g_perso" });
  });

  it("logins from several vaults name their vault on a coloured chip, in the pill and the picker; one vault, no chip", async () => {
    const soma = { id: "v_soma", name: "Soma" };
    const augura = { id: "v_augura", name: "Augura" };
    const mixed: OverlayAccount[] = [
      { ...accounts[0]!, vault: soma },
      { ...accounts[1]!, vault: augura },
    ];
    const { r, handle, clock } = setup(() => null, null, withInit(mixed));
    await handle.ready;
    const chip = r.querySelector<HTMLElement>(".ov-pill .vault-chip")!;
    expect(chip.textContent).toBe("Soma");
    expect(chip.style.getPropertyValue("--vault")).toMatch(/^#[0-9A-F]{6}$/);
    openPicker(r, clock);
    expect(opts(r).map((o) => o.querySelector(".vault-chip")?.textContent)).toEqual(["Soma", "Augura", "Augura"]);

    const same = setup(() => null, null, withInit(mixed.map((a) => ({ ...a, vault: soma }))));
    await same.handle.ready;
    expect(same.r.querySelector(".vault-chip")).toBeNull();
  });

  it("names the account on the card when the host says several accounts answer, and marks an associated site", async () => {
    const list: OverlayAccount[] = [
      { ...accounts[0]!, account: "Soma Labs", associated: true },
      { ...accounts[0]!, itemId: "it_09", title: "Atlas Team", account: "Perso" },
    ];
    const { r, handle } = setup(() => null, null, withInit(list));
    await handle.ready;
    const pill = r.querySelector(".ov-pill")!;
    expect(pill.textContent).toContain("Soma Labs");
    expect(pill.textContent).toContain("Site associé");
    // The other login's row (and the list, with more of them) names its account too.
    expect(r.querySelector(".ov-other")!.textContent).toContain("Perso");
    const more = setup(() => null, null, withInit([...list, { ...accounts[0]!, itemId: "it_10", title: "Third", account: "Team" }]));
    await more.handle.ready;
    openPicker(more.r, more.clock);
    expect(opts(more.r).map((o) => o.textContent).join(" | ")).toContain("Team");
    // Malformed: refused.
    const bad = setup(() => null, null, (m) => (m.type === "overlay_init" ? { ok: { origin: SITE, accounts: [{ ...accounts[0]!, associated: false }], chain: null } } : null));
    await bad.handle.ready;
    expect(bad.r.querySelector(".ov-pill")).toBeNull();
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

  describe("locked at the click: the card waits for the unlock already asked, then goes on by itself", () => {
    const lockedStop: ChainView = { ...running, status: "handoff", reason: "locked" };

    it("Se connecter on a locked vault: waiting card, polled; unlocked, the progress, with no second click", async () => {
      let state: { chain: ChainView | null; waiting?: string } = { chain: null, waiting: "locked" };
      const { r, handle, worker, clock, timers } = setup(
        () => null,
        null,
        (m) => (m.type === "overlay_start" ? { ok: { waiting: "locked" } } : m.type === "overlay_state" ? { ok: state } : null),
      );
      await handle.ready;
      button(r, "Se connecter").click();
      await flush();
      expect(text(r)).toContain("Déverrouille OnePass pour continuer");
      // The account that was clicked stays named, and the wait can be cancelled.
      expect(text(r)).toContain("Atlas Cloud");
      expect(button(r, "Annuler")).toBeTruthy();
      expect(r.querySelector(".spinner")).not.toBeNull();
      expect(timers.intervals.size).toBe(1);
      // Polls while waiting change nothing (the buttons keep their place).
      const card = r.querySelector(".ov-card");
      await handle.poll();
      expect(r.querySelector(".ov-card")).toBe(card);
      // Touch ID in the app: the worker started the chain.
      state = { chain: { ...running, itemId: "it_01", provider: undefined, title: "Atlas Cloud", email: "alex@atlas.dev", phase: "signin", steps: [] } as ChainView };
      await handle.poll();
      expect(text(r)).toContain("Connexion…");
      expect(text(r)).not.toContain("Déverrouille OnePass pour continuer");
      expect(worker.types().filter((t) => t === "overlay_start")).toHaveLength(1);
      void clock;
    });

    it("the wait ends without an unlock: the offer again, its button is the retry", async () => {
      let state: { chain: ChainView | null; waiting?: string } = { chain: null, waiting: "locked" };
      const { r, handle, timers } = setup(
        () => null,
        null,
        (m) => (m.type === "overlay_start" ? { ok: { waiting: "locked" } } : m.type === "overlay_state" ? { ok: state } : null),
      );
      await handle.ready;
      button(r, "Se connecter").click();
      await flush();
      state = { chain: null };
      await handle.poll();
      expect(text(r)).not.toContain("Déverrouille OnePass pour continuer");
      expect(button(r, "Se connecter")).toBeTruthy();
      expect(timers.intervals.size).toBe(0);
    });

    it("the app is launching: the card says so, then follows it to its unlock", async () => {
      let state: { chain: ChainView | null; waiting?: string } = { chain: null, waiting: "host_missing" };
      const { r, handle } = setup(
        () => null,
        null,
        (m) => (m.type === "overlay_start" ? { ok: { waiting: "host_missing" } } : m.type === "overlay_state" ? { ok: state } : null),
      );
      await handle.ready;
      button(r, "Se connecter").click();
      await flush();
      expect(text(r)).toContain("Ouverture de OnePass…");
      state = { chain: null, waiting: "locked" };
      await handle.poll();
      expect(text(r)).toContain("Déverrouille OnePass pour continuer");
    });

    it("Annuler while waiting stops the wait and closes the card", async () => {
      const { r, handle, worker, clock } = setup(
        () => null,
        null,
        (m) => (m.type === "overlay_start" ? { ok: { waiting: "locked" } } : m.type === "overlay_state" ? { ok: { chain: null, waiting: "locked" } } : null),
      );
      await handle.ready;
      button(r, "Se connecter").click();
      await flush();
      clock.advance(300);
      button(r, "Annuler").click();
      await flush();
      expect(worker.types().slice(-2)).toEqual(["overlay_stop", "overlay_close"]);
    });

    it("a chain locked mid-way waits the same way, then continues; past the wait, the stop with Réessayer", async () => {
      let state: { chain: ChainView | null; waiting?: string } = { chain: lockedStop, waiting: "locked" };
      const { r, handle, timers } = setup(() => null, running, (m) => (m.type === "overlay_state" ? { ok: state } : null));
      await handle.ready;
      await handle.poll();
      // No dead end "unlock then retry": the unlock was asked, the card waits.
      expect(text(r)).toContain("Déverrouille OnePass pour continuer");
      expect(text(r)).not.toContain("puis réessaie");
      expect(text(r)).toContain("Atlas Perso");
      expect(timers.intervals.size).toBe(1);
      // Unlocked: the worker continued the chain.
      state = { chain: running };
      await handle.poll();
      expect(text(r)).toContain("Ouverture de Google…");
      // Locked again later, the wait over: the stop, with its retry.
      state = { chain: lockedStop };
      await handle.poll();
      expect(text(r)).toContain("OnePass est verrouillé");
      expect(button(r, "Réessayer")).toBeTruthy();
      expect(timers.intervals.size).toBe(0);
    });

    it("a card that comes up on a page whose chain is locked waits from its first render", async () => {
      const state: { chain: ChainView | null; waiting?: string } = { chain: running };
      const { r, handle, timers } = setup(
        () => null,
        null,
        (m) => (m.type === "overlay_init" ? { ok: { origin: SITE, accounts: [], chain: lockedStop, waiting: "locked" } } : m.type === "overlay_state" ? { ok: state } : null),
      );
      await handle.ready;
      expect(text(r)).toContain("Déverrouille OnePass pour continuer");
      expect(text(r)).toContain("Atlas Perso");
      expect(timers.intervals.size).toBe(1);
      await handle.poll();
      expect(text(r)).toContain("Ouverture de Google…");
    });

    it("a malformed waiting state is refused", async () => {
      const { r, handle } = setup(() => null, null, (m) => (m.type === "overlay_state" ? { ok: { chain: null, waiting: "<b>x</b>" } } : null));
      await handle.ready;
      await handle.poll();
      expect(text(r)).toContain("Erreur interne de OnePass.");
    });
  });

  describe("generic card: a sign-in page reached with the vault locked", () => {
    const genericInit = (m: UiToBg): Reply | null => (m.type === "overlay_init" ? { ok: { origin: SITE, accounts: [], chain: null, generic: true } } : null);

    it("names no account: the site's host, that OnePass is locked, one Sign in button and x", async () => {
      const { r, handle } = setup(() => null, null, genericInit);
      await handle.ready;
      expect(text(r)).toContain("Se connecter avec OnePass");
      expect(text(r)).toContain("OnePass est verrouillé");
      expect(text(r)).not.toContain("Atlas Cloud");
      expect(text(r)).not.toContain("alex");
      expect(r.querySelector(".ov-others")).toBeNull();
      expect(button(r, "Se connecter")).toBeTruthy();
      expect(r.querySelector(".ov-close")).not.toBeNull();
      // A letter tile: a card that shows only while locked asks the site's server for nothing.
      expect(r.querySelector("img")).toBeNull();
      expect(r.querySelector(".site-tile.letter")?.textContent).toBe("A");
    });

    it("its click asks the worker to unlock, waits like any card, then shows the chain the worker started; no second click", async () => {
      let state: { chain: ChainView | null; waiting?: string } = { chain: null, waiting: "locked" };
      const { r, handle, worker, timers } = setup(() => null, null, (m) => genericInit(m) ?? (m.type === "overlay_unlock" ? { ok: { waiting: "locked" } } : m.type === "overlay_state" ? { ok: state } : null));
      await handle.ready;
      button(r, "Se connecter").click();
      await flush();
      expect(worker.types()).toContain("overlay_unlock");
      expect(text(r)).toContain("Déverrouille OnePass pour continuer");
      expect(timers.intervals.size).toBe(1);
      // Still waiting on the locked vault: still no request to the site.
      expect(r.querySelector("img")).toBeNull();
      state = { chain: { ...running, itemId: "it_01", provider: undefined, title: "Atlas Cloud", email: "alex@atlas.dev", phase: "signin", steps: [] } as ChainView };
      await handle.poll();
      expect(text(r)).toContain("Connexion…");
      expect(worker.types().filter((t) => t === "overlay_unlock")).toHaveLength(1);
      expect(worker.types()).not.toContain("overlay_start");
    });

    it("unlocked and no chain (the plan opened the menu, or filled): the card loads again; a site without a login closes it", async () => {
      // The vault now lists the site's logins: the ordinary offer.
      let unlocked = false;
      let state: { chain: ChainView | null; waiting?: string } = { chain: null, waiting: "locked" };
      const a = setup(() => null, null, (m) =>
        m.type === "overlay_init" ? (unlocked ? { ok: { origin: SITE, accounts, chain: null } } : genericInit(m)) : m.type === "overlay_unlock" ? { ok: { waiting: "locked" } } : m.type === "overlay_state" ? { ok: state } : null,
      );
      await a.handle.ready;
      button(a.r, "Se connecter").click();
      await flush();
      unlocked = true;
      state = { chain: null };
      // The page's plan gets a few looks to start a chain; then the card loads again.
      for (let i = 0; i < 8; i++) await a.handle.poll();
      await flush();
      expect(text(a.r)).toContain("Atlas Cloud");
      expect(a.worker.types().filter((t) => t === "overlay_init")).toHaveLength(2);

      // Nothing for this site: the card leaves.
      let open = false;
      const b = setup(() => null, null, (m) =>
        m.type === "overlay_init" ? (open ? { ok: { origin: SITE, accounts: [], chain: null } } : genericInit(m)) : m.type === "overlay_unlock" ? { ok: {} } : null,
      );
      await b.handle.ready;
      open = true;
      button(b.r, "Se connecter").click();
      await flush();
      for (let i = 0; i < 8; i++) await b.handle.poll();
      await flush();
      expect(b.worker.types()).toContain("overlay_close");
    });

    it("the app cannot be opened: said on the card", async () => {
      const { r, handle } = setup(() => null, null, (m) => genericInit(m) ?? (m.type === "overlay_unlock" ? { err: "locked" } : null));
      await handle.ready;
      button(r, "Se connecter").click();
      await flush();
      expect(text(r)).toContain("OnePass est verrouillé");
    });

    it("a generic card that lists an account is refused (nothing of the vault may ride on it)", async () => {
      const { r, handle } = setup(() => null, null, (m) => (m.type === "overlay_init" ? { ok: { origin: SITE, accounts, chain: null, generic: true } } : null));
      await handle.ready;
      expect(text(r)).not.toContain("Atlas Cloud");
    });
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
