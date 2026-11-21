import { describe, expect, it } from "vitest";
import { DESIGN_TOKENS } from "../../src/shared/design-tokens";
import type { UiToBg } from "../../src/shared/messages";
import type { ChainView, OverlayAccount, StopReason } from "../../src/shared/ui";
import type { Timers } from "../../src/ui/components";
import { setLang } from "../../src/shared/i18n";
import { CONNECT_SLOW_MS, DONE_CLOSE_MS, NOTCH_MAX, mountOverlay, stopText } from "../../src/ui/overlay";
import { AUTO_PILL_MS } from "../../src/shared/auto-pill";
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

function setup(chainState: () => ChainView | null, initChain: ChainView | null = null, extra?: (m: UiToBg) => Reply | null) {
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

/** A line, part by part: what it says first, then under it. */
const says = (el: Element) => [...el.querySelectorAll(".t1, .t2")].map((x) => x.textContent).join(" | ");
/** The running line, its x (which stops the sign-in) and what it says to screen readers. */
const runEl = (r: HTMLElement) => r.querySelector<HTMLElement>(".ov-pill.ov-line.ov-tone-run")!;
const cancelX = (r: HTMLElement) => r.querySelector<HTMLButtonElement>(".ov-cancel")!;
const liveStatus = (r: HTMLElement) => r.querySelector<HTMLElement>(".ov-tone-run .sr-only[role=status]")!;
/** Seven logins: more than NOTCH_MAX others, so "N autres comptes" opens the search. */
const crowd: OverlayAccount[] = [
  ...accounts,
  ...["B", "C", "D", "E"].map((x) => ({ ...accounts[0]!, itemId: `it_${x}`, title: `Atlas ${x}`, subtitle: `${x.toLowerCase()}@atlas.dev` })),
];
/** The generic card's one button: the unlock, then the page's own plan. */
const unlockBtn = (r: HTMLElement) => r.querySelector<HTMLButtonElement>('.ov-signin[aria-label="Déverrouiller et se connecter"]')!;
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
  it("pill: the first login's account in full, a text Sign in named for it and x inside; Other logins hangs under it", async () => {
    const { r, handle, worker } = setup(() => null);
    await handle.ready;
    expect(worker.sent[0]).toEqual({ type: "overlay_init", token: TOKEN });
    expect(text(r)).toContain("Se connecter à atlas-cloud.test");
    const pill = r.querySelector(".ov-pill")!;
    // One line: the account, the login's title only on hover.
    expect(says(pill)).toBe("alex@atlas.dev");
    expect(pill.querySelector(".t1")!.getAttribute("title")).toBe("Atlas Cloud");
    expect(pill.querySelector(".ov-line2")).toBeNull();
    const signIn = pill.querySelector(".ov-signin")!;
    expect(signIn.textContent).toBe("Se connecter");
    expect(signIn.getAttribute("aria-label")).toBe("Se connecter avec alex@atlas.dev");
    expect(pill.querySelector(".ov-close")).not.toBeNull();
    expect(r.querySelector(".ov-others")!.getAttribute("aria-label")).toBe("2 autres comptes");
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
    expect(says(r.querySelector(".ov-pill")!)).toBe("second@atlas.dev");
    const other = r.querySelector<HTMLButtonElement>("button.ov-others.ov-other")!;
    expect(says(other)).toBe("alex@atlas.dev");
    expect(other.querySelector(".brand-art")).not.toBeNull();
    expect(text(r)).not.toContain("Autres identifiants");
    expect(r.querySelector(".ov-picker, .ov-notch-open")).toBeNull();
    clock.advance(300);
    other.click();
    await flush();
    expect(worker.sent.filter((m) => m.type === "overlay_start")).toEqual([{ type: "overlay_start", token: TOKEN, itemId: "it_01" }]);
    expect(text(r)).toContain("Connexion…");
  });

  it("three logins: the others wait behind one notch button, no row of their own", async () => {
    const three: OverlayAccount[] = [accounts[0]!, { ...accounts[0]!, itemId: "it_b", title: "B" }, { ...accounts[0]!, itemId: "it_c", title: "C" }];
    const { r, handle } = setup(() => null, null, withInit(three));
    await handle.ready;
    expect(r.querySelector("button.ov-other")).toBeNull();
    expect(r.querySelector(".ov-others")!.getAttribute("aria-label")).toBe("2 autres comptes");
    expect(r.querySelector(".ov-others")!.getAttribute("aria-expanded")).toBe("false");
  });

  it("the notch opens in place: one row per other login, a click starts it; the fold closes it again", async () => {
    const three: OverlayAccount[] = [
      accounts[0]!,
      { ...accounts[0]!, itemId: "it_b", title: "B", subtitle: "b@atlas.dev" },
      { ...accounts[0]!, itemId: "it_c", title: "C", subtitle: "c@atlas.dev" },
    ];
    const { r, handle, worker, clock } = setup(() => null, null, (m) =>
      m.type === "overlay_init" ? { ok: { origin: SITE, accounts: three, chain: null, auto: "signin" } } : null,
    );
    await handle.ready;
    expect(r.querySelector(".ov-never")).not.toBeNull();
    openPicker(r, clock);
    expect(r.querySelector(".ov-picker")).toBeNull();
    const rows = () => [...r.querySelectorAll<HTMLButtonElement>(".ov-notch-open .ov-notch-row")];
    expect(rows().map(says)).toEqual(["b@atlas.dev", "c@atlas.dev"]);
    expect(rows()[1]!.getAttribute("aria-label")).toBe("Se connecter avec c@atlas.dev");
    // The pill stays as it was above the open notch; "Jamais sur ce site" hides meanwhile.
    expect(says(r.querySelector(".ov-pill")!)).toBe("alex@atlas.dev");
    expect(r.querySelector(".ov-never")).toBeNull();
    expect(worker.types()).toEqual(["overlay_init"]);
    // The fold: back to the closed notch.
    r.querySelector<HTMLButtonElement>(".ov-notch-fold")!.click();
    clock.advance(300);
    expect(r.querySelector(".ov-notch-open")).toBeNull();
    expect(r.querySelector("button.ov-others")!.getAttribute("aria-label")).toBe("2 autres comptes");
    // Two others: both initials, no "+N".
    expect([...r.querySelectorAll(".ov-lip .ov-lip-av")].map((a) => a.textContent)).toEqual(["B", "C"]);
    expect(r.querySelector(".ov-lip .ov-lip-more")).toBeNull();
    openPicker(r, clock);
    rows()[1]!.click();
    await flush();
    expect(worker.sent.filter((m) => m.type === "overlay_start")).toEqual([{ type: "overlay_start", token: TOKEN, itemId: "it_c" }]);
    expect(says(runEl(r))).toBe("c@atlas.dev | Connexion…");
  });

  it(`more than ${NOTCH_MAX} other logins: the notch opens the search instead`, async () => {
    const { r, handle, clock } = setup(() => null, null, withInit(crowd));
    await handle.ready;
    expect(r.querySelector(".ov-others")!.getAttribute("aria-label")).toBe("6 autres comptes");
    // The closed lip: three initials, then the rest as "+3".
    expect(r.querySelectorAll(".ov-lip .ov-lip-av")).toHaveLength(3);
    expect(r.querySelector(".ov-lip .ov-lip-more")!.textContent).toBe("+3");
    openPicker(r, clock);
    expect(r.querySelector(".ov-notch-open, .ov-notch-row")).toBeNull();
    expect(r.querySelector(".ov-picker .ov-search")).not.toBeNull();
    expect(opts(r)).toHaveLength(7);
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
    // Each way with its default account, then the provider's other account: the pill holds the first, the notch the three others.
    expect([...r.querySelectorAll(".ov-notch-row")].map((x) => [x.getAttribute("data-provider"), x.getAttribute("data-account"), says(x)])).toEqual([
      ["google", "g_pro", "alex.pro@example.com"],
      ["google", "g_perso", "alex.perso@example.com"],
      ["google", "g_pro", "alex.pro@example.com"],
    ]);
  });

  it("a Sign in with login: the provider's official mark on the icon, the account it signs in", async () => {
    const { r, handle, worker, timers } = setup(() => running, null, withInit([accounts[1]!, accounts[0]!]));
    await handle.ready;
    const pill = r.querySelector(".ov-pill")!;
    expect(pill.getAttribute("data-provider")).toBe("google");
    expect(says(pill)).toBe("alex.perso@example.com");
    expect(pill.querySelector(".t1")!.getAttribute("title")).toBe("Atlas Perso");
    const mark = pill.querySelector(".brand-badge svg.mark-google")!;
    expect(mark.querySelectorAll("path")).toHaveLength(4);
    const google = ["red", "blue", "yellow", "green"].map((c) => DESIGN_TOKENS.dark[`brand-google-${c}`]);
    expect(google).toEqual(["#EA4335", "#4285F4", "#FBBC05", "#34A853"]);
    expect([...mark.querySelectorAll("path")].map((p) => p.getAttribute("fill"))).toEqual(google);
    button(r, "Se connecter").click();
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "overlay_start", token: TOKEN, itemId: "it_02", provider: "google", accountId: "g_perso" });
    expect(timers.intervals.size).toBe(1);
    // Before the first poll: the account and "Connexion…" at once, what happens now for screen readers.
    expect(says(runEl(r))).toBe("alex.perso@example.com | Connexion…");
    expect(liveStatus(r).textContent).toBe("Ouverture de Google…");
    expect(cancelX(r).getAttribute("aria-label")).toBe("Annuler");
  });

  it("Other logins: the search focused, every login with a key, the first selected; arrows and Enter start one", async () => {
    const { r, handle, worker, clock } = setup(() => running, null, withInit(crowd));
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
      "Atlas B | b@atlas.dev",
      "Atlas C | c@atlas.dev",
      "Atlas D | d@atlas.dev",
      "Atlas E | e@atlas.dev",
    ]);
    expect(opts(r).every((o) => o.querySelector(".ov-key svg"))).toBe(true);
    const selected = () => opts(r).findIndex((o) => o.getAttribute("aria-selected") === "true");
    expect(selected()).toBe(0);
    key(input, "ArrowUp");
    expect(selected()).toBe(6);
    key(input, "ArrowDown");
    expect(selected()).toBe(0);
    key(input, "ArrowDown");
    key(input, "ArrowDown");
    expect(selected()).toBe(2);
    expect(opts(r)[2]!.classList.contains("selected")).toBe(true);
    key(input, "Enter");
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "overlay_start", token: TOKEN, itemId: "it_02", provider: "google", accountId: "g_pro" });
    expect(runEl(r).querySelector(".t1")!.textContent).toBe("alex.pro@example.com");
  });

  it("Other logins: typing filters, nothing found says so, Escape goes back to the pill; the pointer selects and a click starts", async () => {
    const { r, handle, worker, clock } = setup(() => running, null, withInit(crowd));
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

  it("logins from several vaults name their vault on a coloured chip in the picker, never on the pill; one vault, no chip", async () => {
    const soma = { id: "v_soma", name: "Soma" };
    const augura = { id: "v_augura", name: "Augura" };
    const mixed: OverlayAccount[] = crowd.map((a) => ({ ...a, vault: a.itemId === "it_02" ? augura : soma }));
    const { r, handle, clock } = setup(() => null, null, withInit(mixed));
    await handle.ready;
    expect(r.querySelector(".ov-pill .vault-chip")).toBeNull();
    openPicker(r, clock);
    expect(opts(r).map((o) => o.querySelector(".vault-chip")?.textContent)).toEqual(["Soma", "Augura", "Augura", "Soma", "Soma", "Soma", "Soma"]);
    const chip = r.querySelector<HTMLElement>(".ov-opt .vault-chip")!;
    expect(chip.style.getPropertyValue("--vault")).toMatch(/^#[0-9A-F]{6}$/);

    const same = setup(() => null, null, withInit(mixed.map((a) => ({ ...a, vault: soma }))));
    await same.handle.ready;
    openPicker(same.r, same.clock);
    expect(opts(same.r)).toHaveLength(7);
    expect(same.r.querySelector(".vault-chip")).toBeNull();
  });

  it("names the account in the picker when the host says several accounts answer, and marks an associated site; the pill stays one line", async () => {
    const list: OverlayAccount[] = [
      { ...accounts[0]!, account: "Soma Labs", associated: true },
      { ...accounts[0]!, itemId: "it_09", title: "Atlas Team", account: "Perso" },
    ];
    const { r, handle } = setup(() => null, null, withInit(list));
    await handle.ready;
    expect(says(r.querySelector(".ov-pill")!)).toBe("alex@atlas.dev");
    expect(r.querySelector(".row-account, .row-assoc")).toBeNull();
    // With more logins than the notch holds, the list names each one's account.
    const more = setup(() => null, null, withInit([...list, ...crowd.slice(1).map((a) => ({ ...a, account: "Team" }))]));
    await more.handle.ready;
    openPicker(more.r, more.clock);
    const said = opts(more.r).map((o) => o.textContent).join(" | ");
    expect(said).toContain("Soma Labs");
    expect(said).toContain("Site associé");
    expect(said).toContain("Perso");
    expect(said).toContain("Team");
    // Malformed: refused.
    const bad = setup(() => null, null, (m) => (m.type === "overlay_init" ? { ok: { origin: SITE, accounts: [{ ...accounts[0]!, associated: false }], chain: null } } : null));
    await bad.handle.ready;
    // Refused means no offer, only the failure line.
    expect(bad.r.querySelector(".ov-pill:not(.ov-line)")).toBeNull();
    expect(bad.r.querySelector(".ov-fail")).not.toBeNull();
  });

  it("polls update only what screen readers hear; the line and its x keep their nodes and focus", async () => {
    let state: ChainView = running;
    const { r, handle } = setup(() => state, running);
    await handle.ready;
    const cancel = cancelX(r);
    cancel.focus();
    const line = runEl(r);
    const status = liveStatus(r);
    expect(status.getAttribute("aria-live")).toBe("polite");
    expect(status.textContent).toBe("Ouverture de Google…");
    await handle.poll();
    state = { ...running, phase: "choosing", steps: [...running.steps, { label: "Compte choisi : alex.perso@example.com", state: "done" }] };
    await handle.poll();
    expect(cancelX(r)).toBe(cancel);
    expect(document.activeElement).toBe(cancel);
    expect(runEl(r)).toBe(line);
    expect(liveStatus(r)).toBe(status);
    expect(status.textContent).toBe("Choix de alex.perso@example.com…");
    expect(says(line)).toBe("alex.perso@example.com | Connexion…");
  });

  it("a password login runs on one line: the account, Connexion…, x; no steps, no Détails, no bar", async () => {
    const pwd: ChainView = { itemId: "it_01", status: "running", title: "Atlas Cloud", email: "alex@atlas.dev", phase: "signin", steps: [] };
    let now: ChainView = pwd;
    const { r, handle } = setup(() => now, pwd);
    await handle.ready;
    expect(r.querySelectorAll(".ov-pill")).toHaveLength(1);
    expect(says(runEl(r))).toBe("alex@atlas.dev | Connexion…");
    expect(liveStatus(r).textContent).toBe("Connexion…");
    expect(runEl(r).querySelector(".spinner")).not.toBeNull();
    expect(r.querySelectorAll("button")).toHaveLength(1);
    expect(r.querySelector(".ov-steps, .ov-details, .ov-bar, .ov-step-label")).toBeNull();
    now = { ...pwd, steps: [{ label: "x", state: "done", what: "user" }] };
    await handle.poll();
    expect(says(runEl(r))).toBe("alex@atlas.dev | Connexion…");
    expect(r.querySelector(".ov-steps, .ov-bar")).toBeNull();
  });

  it("the running line in English", async () => {
    setLang("en");
    try {
      const pwd: ChainView = { itemId: "it_01", status: "running", title: "Atlas Cloud", email: "alex@atlas.dev", phase: "signin", steps: [] };
      const { r, handle } = setup(() => pwd, pwd);
      await handle.ready;
      expect(says(runEl(r))).toBe("alex@atlas.dev | Signing in…");
      expect(cancelX(r).getAttribute("aria-label")).toBe("Cancel");
    } finally {
      setLang("fr");
    }
  });

  it("the x beside a running chain is Annuler, the only way out: it stops the chain", async () => {
    const { r, handle, worker } = setup(() => running, running);
    await handle.ready;
    expect(r.querySelectorAll(".ov-close")).toHaveLength(1);
    expect(cancelX(r).getAttribute("aria-label")).toBe("Annuler");
    expect(r.querySelector("button[aria-label=Fermer]")).toBeNull();
    cancelX(r).click();
    await flush();
    await flush();
    expect(worker.types().slice(-2)).toEqual(["overlay_stop", "overlay_close"]);
  });

  it("Annuler stops the chain and closes the card; a poll after that brings nothing back", async () => {
    const { r, handle, worker, timers } = setup(() => running, running);
    await handle.ready;
    cancelX(r).click();
    await flush();
    await flush();
    expect(worker.types().slice(-2)).toEqual(["overlay_stop", "overlay_close"]);
    expect(timers.intervals.size).toBe(0);
    expect(r.querySelector(".ov-line")).toBeNull();
    await handle.poll();
    expect(r.querySelector(".ov-line, .ov-pill")).toBeNull();
  });

  it("done: Connecté and the account, no steps, then the card leaves by itself", async () => {
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
    const line = r.querySelector(".ov-line.ov-tone-done.ov-done")!;
    expect(says(line)).toBe("Connecté | alex.perso@example.com");
    expect(line.querySelector(".t1")!.getAttribute("role")).toBe("status");
    expect(r.querySelectorAll(".ov-step-label")).toHaveLength(0);
    expect(timers.intervals.size).toBe(0);
    expect(DONE_CLOSE_MS).toBe(1_200);
    timers.fire(DONE_CLOSE_MS);
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "overlay_close", token: TOKEN });
  });

  it("the app slow to answer: Connexion à OnePass… after 1.5 s; it fails: the cause and Réessayer", async () => {
    let seen = "";
    let starts = 0;
    const s: ReturnType<typeof setup> = setup(() => null, null, (m) => {
      if (m.type !== "overlay_start") return null;
      starts++;
      // Still no answer when the slow timer fires: the card says it is reaching the app.
      s.timers.fire(CONNECT_SLOW_MS);
      seen = text(s.r);
      return { err: "host_missing" };
    });
    await s.handle.ready;
    button(s.r, "Se connecter").click();
    await flush();
    expect(seen).toContain("Connexion à OnePass…");
    const fail = s.r.querySelector(".ov-line.ov-stop.ov-fail.ov-tone-warn")!;
    expect(fail.getAttribute("data-code")).toBe("host_missing");
    expect(fail.querySelector(".t1")!.textContent).toBe("App OnePass introuvable");
    expect(fail.querySelector(".ov-close")).not.toBeNull();
    s.clock.advance(300);
    button(s.r, "Réessayer").click();
    await flush();
    expect(starts).toBe(2);
  });

  it("a failure a second try cannot fix has no Réessayer", async () => {
    const s = setup(() => null, null, (m) => (m.type === "overlay_start" ? { err: "not_allowed" } : null));
    await s.handle.ready;
    button(s.r, "Se connecter").click();
    await flush();
    expect([...s.r.querySelectorAll("button")].map((b) => text(b))).not.toContain("Réessayer");
  });

  it("every stop reason, word for word, on one line with its tone", async () => {
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
      const handoff = ["push", "otp", "captcha", "unknown"].includes(reason);
      const stop = r.querySelector(".ov-line.ov-stop")!;
      // One sentence: the stop itself, read out; no title above it, no hint under it.
      expect(says(stop)).toBe(sentence);
      expect(stop.querySelector(".t1")!.getAttribute("role")).toBe("status");
      expect(stop.getAttribute("data-tone")).toBe(handoff ? "handoff" : reason === "domain" ? "danger" : "warn");
      expect(text(r)).not.toContain("À toi de jouer");
      expect(r.querySelector(".ov-hint")).toBeNull();
      expect(stop.querySelector(".ov-close")).not.toBeNull();
      expect(stop.querySelector(".ov-signin") !== null).toBe(reason === "timeout" || reason === "locked");
    }
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
    expect(liveStatus(r).textContent).toBe("Ouverture de Google…");
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
      // The run line: the account that was clicked, what the user has to do, said to screen readers too.
      expect(says(runEl(r))).toBe("alex@atlas.dev | Déverrouille Kelid pour continuer");
      expect(liveStatus(r).textContent).toBe("Déverrouille Kelid pour continuer");
      // The wait can be cancelled.
      expect(cancelX(r).getAttribute("aria-label")).toBe("Annuler");
      expect(r.querySelector(".spinner")).not.toBeNull();
      expect(timers.intervals.size).toBe(1);
      // Polls while waiting change nothing (the line and its x keep their place).
      const line = runEl(r);
      const x = cancelX(r);
      await handle.poll();
      expect(runEl(r)).toBe(line);
      expect(cancelX(r)).toBe(x);
      // Touch ID in the app: the worker started the chain.
      state = { chain: { ...running, itemId: "it_01", provider: undefined, title: "Atlas Cloud", email: "alex@atlas.dev", phase: "signin", steps: [] } as ChainView };
      await handle.poll();
      expect(text(r)).toContain("Connexion…");
      expect(text(r)).not.toContain("Déverrouille Kelid pour continuer");
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
      expect(text(r)).not.toContain("Déverrouille Kelid pour continuer");
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
      expect(runEl(r).querySelector(".t2")!.textContent).toBe("Ouverture de Kelid…");
      expect(liveStatus(r).textContent).toBe("Ouverture de Kelid…");
      state = { chain: null, waiting: "locked" };
      await handle.poll();
      expect(runEl(r).querySelector(".t2")!.textContent).toBe("Déverrouille Kelid pour continuer");
      expect(liveStatus(r).textContent).toBe("Déverrouille Kelid pour continuer");
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
      cancelX(r).click();
      await flush();
      expect(worker.types().slice(-2)).toEqual(["overlay_stop", "overlay_close"]);
    });

    it("a chain locked mid-way waits the same way, then continues; past the wait, the stop with Réessayer", async () => {
      let state: { chain: ChainView | null; waiting?: string } = { chain: lockedStop, waiting: "locked" };
      const { r, handle, timers } = setup(() => null, running, (m) => (m.type === "overlay_state" ? { ok: state } : null));
      await handle.ready;
      await handle.poll();
      // No dead end "unlock then retry": the unlock was asked, the card waits.
      expect(text(r)).toContain("Déverrouille Kelid pour continuer");
      expect(text(r)).not.toContain("puis réessaie");
      expect(runEl(r).querySelector(".t1")!.textContent).toBe("alex.perso@example.com");
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
      expect(text(r)).toContain("Déverrouille Kelid pour continuer");
      expect(runEl(r).querySelector(".t1")!.textContent).toBe("alex.perso@example.com");
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

    it("names no account: the site's host on one line, one Sign in button and x", async () => {
      const { r, handle } = setup(() => null, null, genericInit);
      await handle.ready;
      const pill = r.querySelector(".ov-pill[data-generic]")!;
      expect(says(pill)).toBe("atlas-cloud.test");
      // Nothing about the lock: the click asks Touch ID and goes on by itself.
      expect(text(r)).not.toContain("OnePass est verrouillé");
      expect(text(r)).not.toContain("Atlas Cloud");
      expect(text(r)).not.toContain("alex");
      expect(r.querySelector(".ov-others")).toBeNull();
      expect(r.querySelectorAll(".ov-signin")).toHaveLength(1);
      expect(unlockBtn(r).textContent).toBe("Se connecter");
      expect(r.querySelector(".ov-close")).not.toBeNull();
      // A letter tile: a card that shows only while locked asks the site's server for nothing.
      expect(r.querySelector("img")).toBeNull();
      expect(r.querySelector(".site-tile.letter")?.textContent).toBe("A");
    });

    it("its click asks the worker to unlock, waits like any card, then shows the chain the worker started; no second click", async () => {
      let state: { chain: ChainView | null; waiting?: string } = { chain: null, waiting: "locked" };
      const { r, handle, worker, timers } = setup(() => null, null, (m) => genericInit(m) ?? (m.type === "overlay_unlock" ? { ok: { waiting: "locked" } } : m.type === "overlay_state" ? { ok: state } : null));
      await handle.ready;
      unlockBtn(r).click();
      await flush();
      expect(worker.types()).toContain("overlay_unlock");
      expect(text(r)).toContain("Déverrouille Kelid pour continuer");
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
      unlockBtn(a.r).click();
      await flush();
      unlocked = true;
      state = { chain: null };
      // The page's plan gets a few looks to start a chain; then the card loads again.
      for (let i = 0; i < 8; i++) await a.handle.poll();
      await flush();
      expect(says(a.r.querySelector(".ov-pill")!)).toBe("alex@atlas.dev");
      expect(a.worker.types().filter((t) => t === "overlay_init")).toHaveLength(2);

      // Nothing for this site: the card leaves.
      let open = false;
      const b = setup(() => null, null, (m) =>
        m.type === "overlay_init" ? (open ? { ok: { origin: SITE, accounts: [], chain: null } } : genericInit(m)) : m.type === "overlay_unlock" ? { ok: {} } : null,
      );
      await b.handle.ready;
      open = true;
      unlockBtn(b.r).click();
      await flush();
      for (let i = 0; i < 8; i++) await b.handle.poll();
      await flush();
      expect(b.worker.types()).toContain("overlay_close");
    });

    it("the app cannot be opened: said on the card", async () => {
      const { r, handle } = setup(() => null, null, (m) => genericInit(m) ?? (m.type === "overlay_unlock" ? { err: "locked" } : null));
      await handle.ready;
      unlockBtn(r).click();
      await flush();
      expect(text(r)).toContain("OnePass est verrouillé");
    });

    it("a generic card that lists an account is refused (nothing of the vault may ride on it)", async () => {
      const { r, handle } = setup(() => null, null, (m) => (m.type === "overlay_init" ? { ok: { origin: SITE, accounts, chain: null, generic: true } } : null));
      await handle.ready;
      // Neither the account (the pill's text) nor the login's title (its tooltip) shows.
      expect(text(r)).not.toContain("alex");
      expect(r.innerHTML).not.toContain("Atlas Cloud");
      expect(r.querySelector(".ov-fail")).not.toBeNull();
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

describe("the card that appeared by itself (auto sign-in pill)", () => {
  const autoInit =
    (over: Record<string, unknown>, more?: (m: UiToBg) => Reply | null) =>
    (m: UiToBg): Reply | null =>
      m.type === "overlay_init" ? { ok: { origin: SITE, accounts: [accounts[0]!], chain: null, auto: "signin", ...over } } : (more?.(m) ?? null);
  const closes = (worker: FakeWorker) => worker.sent.filter((m) => m.type === "overlay_close");

  it("case 1: the one-login pill, its button named for the login; nothing sent but the init until a click", async () => {
    const { r, handle, worker } = setup(() => null, null, autoInit({}));
    await handle.ready;
    const signIn = r.querySelector<HTMLButtonElement>(".ov-signin")!;
    expect(signIn.textContent).toBe("Se connecter");
    expect(signIn.getAttribute("aria-label")).toBe("Se connecter avec alex@atlas.dev");
    expect(worker.types()).toEqual(["overlay_init"]);
    signIn.click();
    await flush();
    expect(worker.sent.filter((m) => m.type === "overlay_start")).toEqual([{ type: "overlay_start", token: TOKEN, itemId: "it_01" }]);
  });

  it(`folds away after ${AUTO_PILL_MS} ms untouched`, async () => {
    const { handle, worker, timers } = setup(() => null, null, autoInit({}));
    await handle.ready;
    expect(closes(worker)).toEqual([]);
    timers.fire(AUTO_PILL_MS);
    await flush();
    expect(closes(worker)).toEqual([{ type: "overlay_close", token: TOKEN }]);
  });

  it("a click on its button stops the fold: the sign-in it started keeps the card", async () => {
    const { r, handle, worker, timers } = setup(() => null, null, autoInit({}));
    await handle.ready;
    r.querySelector<HTMLButtonElement>(".ov-signin")!.click();
    await flush();
    timers.fire(AUTO_PILL_MS);
    await flush();
    expect(closes(worker)).toEqual([]);
  });

  it("x closes it at once", async () => {
    const { r, handle, worker } = setup(() => null, null, autoInit({}));
    await handle.ready;
    r.querySelector<HTMLButtonElement>(".ov-close")!.click();
    await flush();
    expect(closes(worker)).toEqual([{ type: "overlay_close", token: TOKEN }]);
  });

  it("x on the locked card: gone at once, even when the worker refuses", async () => {
    const refuse = (m: UiToBg): Reply | null => (m.type === "overlay_close" ? { err: "invalid" } : null);
    const { r, handle, worker } = setup(() => null, null, autoInit({ accounts: [], generic: true }, refuse));
    await handle.ready;
    r.querySelector<HTMLButtonElement>(".ov-close")!.click();
    // Before any answer of the worker: the card is empty.
    expect(r.querySelector(".ov-pill")).toBeNull();
    await flush();
    expect(closes(worker)).toEqual([{ type: "overlay_close", token: TOKEN }]);
    // A poll after that (a late timer, a late answer) brings nothing back.
    await handle.poll();
    await flush();
    expect(r.querySelector(".ov-pill, .ov-card, .ov-stop")).toBeNull();
  });

  it("\"Never on this site\" asks the worker to keep the site away", async () => {
    const { r, handle, worker } = setup(() => null, null, autoInit({}));
    await handle.ready;
    button(r, "Jamais sur ce site").click();
    await flush();
    expect(worker.sent.filter((m) => m.type === "overlay_never")).toEqual([{ type: "overlay_never", token: TOKEN }]);
  });

  it("a card opened by a gesture has no fold and no \"Never on this site\"", async () => {
    const { r, handle, timers } = setup(() => null);
    await handle.ready;
    expect(text(r)).not.toContain("Jamais sur ce site");
    expect([...timers.timeouts.values()].some((x) => x.ms === AUTO_PILL_MS)).toBe(false);
  });

  it("case 2: the generic card of a locked vault folds too, and its click (the unlock) stops the fold", async () => {
    const { r, handle, worker, timers } = setup(() => null, null, autoInit({ accounts: [], generic: true }, (m) => (m.type === "overlay_unlock" ? { ok: { waiting: "locked" } } : null)));
    await handle.ready;
    expect(says(r.querySelector(".ov-pill[data-generic]")!)).toBe("atlas-cloud.test");
    expect(text(r)).toContain("Jamais sur ce site");
    unlockBtn(r).click();
    await flush();
    expect(worker.sent.filter((m) => m.type === "overlay_unlock")).toHaveLength(1);
    timers.fire(AUTO_PILL_MS);
    await flush();
    expect(closes(worker)).toEqual([]);
  });

  it("case 3: \"Create with OnePass\" on a signup page; its click asks the fill, nothing else", async () => {
    const { r, handle, worker, timers } = setup(() => null, null, autoInit({ accounts: [], auto: "signup" }));
    await handle.ready;
    const pill = r.querySelector(".ov-pill[data-create]")!;
    expect(says(pill)).toBe("Créer avec OnePass");
    expect(pill.querySelector(".t1")!.getAttribute("title")).toBe("Un mot de passe fort pour ce site");
    expect(pill.querySelector(".ov-signin")!.textContent).toBe("Créer");
    expect(text(r)).toContain("Jamais sur ce site");
    expect(r.querySelector(".ov-others:not(.ov-never)")).toBeNull();
    expect(worker.types()).toEqual(["overlay_init"]);
    button(r, "Créer").click();
    await flush();
    expect(worker.sent.filter((m) => m.type === "overlay_create")).toEqual([{ type: "overlay_create", token: TOKEN }]);
    timers.fire(AUTO_PILL_MS);
    await flush();
    expect(closes(worker)).toEqual([]);
  });

  it("case 3: a fill the site refuses says so on the card", async () => {
    const { r, handle } = setup(() => null, null, autoInit({ accounts: [], auto: "signup" }, (m) => (m.type === "overlay_create" ? { err: "site_refused" } : null)));
    await handle.ready;
    button(r, "Créer").click();
    await flush();
    expect(r.querySelector(".ov-signin")).toBeNull();
  });

  it("an auto signup card that lists an account is refused", async () => {
    const { r, handle } = setup(() => null, null, autoInit({ auto: "signup" }));
    await handle.ready;
    // Neither the account (the pill's text) nor the login's title (its tooltip) shows.
    expect(text(r)).not.toContain("alex");
    expect(r.innerHTML).not.toContain("Atlas Cloud");
    expect(r.querySelector(".ov-fail")).not.toBeNull();
  });
});
