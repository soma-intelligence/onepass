import { describe, expect, it, vi } from "vitest";
import type { UiToBg } from "../../src/shared/messages";
import { UNLOCK_WAIT_MS } from "../../src/shared/unlock";
import { UNLOCK_POLL_MS, UNLOCK_WAIT_TRIES } from "../../src/ui/components";
import { mountMenu } from "../../src/ui/menu";
import { Clock, FakeVisibility, FakeWorker, HASH, ManualTimers, type Reply, TOKEN, button, flush, login, root, text } from "./helpers";

const SITE = "https://atlas-cloud.test";

const CHOICES = [
  {
    itemId: "it_02",
    provider: "google",
    accountId: "g_perso",
    accounts: [
      { itemId: "g_perso", email: "alex.perso@example.com", title: "Google perso" },
      { itemId: "g_pro", email: "alex.pro@example.com", title: "Google pro" },
    ],
  },
];

/** What a row says, part by part: title, second line, action. */
const says = (el: Element) => [...el.querySelectorAll(".t1, .line2, .act")].map((x) => x.textContent).join(" | ");

function setup(answer: (m: UiToBg) => Reply | Promise<Reply>, formKind = "login", choices?: unknown) {
  const r = root();
  const clock = new Clock();
  const vis = new FakeVisibility();
  const worker = new FakeWorker((m) => {
    if (m.type === "menu_init") {
      const res = answer(m) as Reply;
      return "ok" in res && res.ok === "default"
        ? {
            ok: {
              origin: SITE,
              formKind,
              items: [login("it_01"), login("it_02", { title: "Atlas Perso", has_password: false, methods: [{ provider: "google", account_email: "alex.perso@example.com" }] })],
              ...(choices ? { choices } : {}),
            },
          }
        : res;
    }
    return answer(m);
  });
  const timers = new ManualTimers();
  const handle = mountMenu(r, { send: worker.send, hash: HASH, now: clock.now, trusted: () => true, observe: vis.observe, timers });
  return { r, clock, vis, worker, handle, timers };
}

const ok = (v: unknown = {}): Reply => ({ ok: v });
const def = () => ok("default");

describe("inline menu", () => {
  it("renders the header, the logins and the provider entry", async () => {
    const { r, handle, worker } = setup(def);
    await handle.ready;
    expect(worker.sent[0]).toEqual({ type: "menu_init", token: TOKEN });
    // The site and how many logins it has (the provider-only login counts).
    expect(r.querySelector(".menu-host")!.textContent).toBe("atlas-cloud.test");
    expect(r.querySelector(".menu-count")!.textContent).toBe("2 logins");
    const opts = [...r.querySelectorAll("[role=option]")];
    // Each row says how it signs in and what a click does.
    expect(says(opts[0]!)).toBe("Atlas Cloud | alex@atlas.dev · mot de passe | Remplir");
    expect(says(opts[1]!)).toBe("Atlas Perso | Avec Google · alex.perso@example.com | Continuer");
    expect(opts[1]!.querySelector(".way-badge svg.glyph-p_google")).not.toBeNull();
    // A provider-only login has no password row; then "Enregistrer un nouveau login".
    expect(opts).toHaveLength(3);
    // Logins show the site's own icon over HTTPS, with no referrer.
    const img = opts[0]!.querySelector<HTMLImageElement>(".site-tile img");
    expect(img!.getAttribute("src")).toBe("https://atlas-cloud.test/favicon.ico");
    expect(img!.getAttribute("referrerpolicy")).toBe("no-referrer");
    // No icon: the tile keeps the login's initial.
    img!.dispatchEvent(new Event("error"));
    expect(opts[0]!.querySelector(".site-tile")!.textContent).toBe("A");
  });

  it("names the account of a row when the host says several accounts answer, and marks an associated site", async () => {
    const { r, handle } = setup(() =>
      ok({
        origin: SITE,
        formKind: "login",
        items: [login("it_01", { account: "Soma Labs" }), login("it_03", { title: "Atlas ID", account: "Perso", associated: true }), login("it_04", { title: "Plain" })],
      }),
    );
    await handle.ready;
    const rows = [...r.querySelectorAll("button.row:not(.row-quiet)")].map(says);
    expect(rows[0]).toContain("Soma Labs");
    expect(rows[0]).not.toContain("Site associé");
    expect(rows[1]).toContain("Perso");
    expect(rows[1]).toContain("Site associé");
    expect(rows[2]).not.toContain("Site associé");
    expect(r.querySelectorAll(".row-account")).toHaveLength(2);
  });

  it("refuses a summary whose new optional fields are malformed", async () => {
    for (const bad of [{ account: 7 }, { account: "x".repeat(300) }, { associated: false }, { associated: "yes" }]) {
      const { r, handle } = setup(() => ok({ origin: SITE, formKind: "login", items: [login("it_01", bad)] }));
      await handle.ready;
      expect(r.querySelector("button.row")).toBeNull();
    }
  });

  it("says the site refused the generated password, and on a refused Générer", async () => {
    const init = { origin: SITE, formKind: "signup", items: [], notice: "site_refused" };
    const { r, handle, clock } = setup((m) => (m.type === "menu_init" ? ok(init) : m.type === "menu_generate" ? { err: "site_refused" } : ok()), "signup");
    await handle.ready;
    expect(r.querySelector(".error-line")!.textContent).toBe("Ce site refuse le mot de passe généré");
    r.querySelector(".error-line")!.textContent = "";
    clock.advance(300);
    button(r, "Générer un mot de passe").click();
    await new Promise((x) => setTimeout(x, 0));
    expect(r.querySelector(".error-line")!.textContent).toBe("Ce site refuse le mot de passe généré");
  });

  it("Enregistrer un nouveau login opens the save prompt (menu_new_login)", async () => {
    const { r, handle, worker, clock } = setup(def);
    await handle.ready;
    clock.advance(300);
    button(r, "Enregistrer un nouveau login").click();
    await Promise.resolve();
    expect(worker.sent.at(-1)).toEqual({ type: "menu_new_login", token: TOKEN });
  });

  it("no new login entry on card forms", async () => {
    const { r, handle } = setup(() => ok({ origin: SITE, formKind: "card", items: [] }));
    await handle.ready;
    expect(text(r)).not.toContain("Enregistrer un nouveau login");
  });

  it("on a provider's chooser, the account linked to the site says Utilisé pour <site>", async () => {
    const { r, handle } = setup(() =>
      ok({
        origin: "https://accounts.google.com",
        formKind: "login",
        items: [login("g_perso", { title: "Google", subtitle: "alex.perso@example.com" }), login("g_pro", { title: "Google", subtitle: "alex.pro@example.com" })],
        linked: { itemId: "g_pro", site: "atlas-cloud.test" },
      }),
    );
    await handle.ready;
    const rows = [...r.querySelectorAll("[role=option]")].map((x) => text(x));
    expect(rows[0]).toContain("alex.pro@example.com");
    expect(rows[0]).toContain("Utilisé pour atlas-cloud.test");
    expect(rows[1]).not.toContain("Utilisé pour");
  });

  it("menu_ignores_click_within_300ms", async () => {
    const { r, handle, worker, clock } = setup(def);
    await handle.ready;
    button(r, "Atlas Cloud").click();
    clock.advance(299);
    button(r, "Atlas Cloud").click();
    await Promise.resolve();
    expect(worker.types()).toEqual(["menu_init"]);
    clock.advance(1);
    button(r, "Atlas Cloud").click();
    await Promise.resolve();
    expect(worker.sent.at(-1)).toEqual({ type: "menu_pick", token: TOKEN, itemId: "it_01" });
  });

  it("IOSSAF-09: a real tap held back by the delay shows pressed until the delay is over, and runs nothing", async () => {
    const { r, handle, worker, clock } = setup(def);
    await handle.ready;
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      clock.advance(100);
      const row = button(r, "Atlas Cloud");
      row.click();
      expect(row.classList.contains("held")).toBe(true);
      vi.advanceTimersByTime(200);
      expect(row.classList.contains("held")).toBe(false);
      expect(worker.types()).toEqual(["menu_init"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("ignores untrusted clicks by default", async () => {
    const r = root();
    const clock = new Clock();
    const worker = new FakeWorker((m) => (m.type === "menu_init" ? { ok: { origin: SITE, formKind: "login", items: [login("it_01")] } } : ok()));
    const handle = mountMenu(r, { send: worker.send, hash: HASH, now: clock.now, observe: () => undefined });
    await handle.ready;
    clock.advance(1000);
    button(r, "Atlas Cloud").click(); // jsdom click: isTrusted false
    await Promise.resolve();
    expect(worker.types()).toEqual(["menu_init"]);
  });

  it("requires IntersectionObserver v2 visibility when reported, closes when scrolled out", async () => {
    const { r, handle, worker, clock, vis } = setup(def);
    await handle.ready;
    clock.advance(500);
    vis.emit({ intersecting: true, visible: false });
    button(r, "Atlas Cloud").click();
    await Promise.resolve();
    expect(worker.types()).toEqual(["menu_init"]);
    vis.emit({ intersecting: true, visible: true });
    // Revealed: the 300 ms delay starts again.
    button(r, "Atlas Cloud").click();
    await Promise.resolve();
    expect(worker.types()).toEqual(["menu_init"]);
    clock.advance(299);
    button(r, "Atlas Cloud").click();
    await Promise.resolve();
    expect(worker.types()).toEqual(["menu_init"]);
    clock.advance(1);
    button(r, "Atlas Cloud").click();
    await Promise.resolve();
    expect(worker.types()).toEqual(["menu_init", "menu_pick"]);
    vis.emit({ intersecting: false });
    expect(worker.sent.at(-1)).toEqual({ type: "menu_close", token: TOKEN });
  });

  it("entering the viewport again re-arms the delay", async () => {
    const { r, handle, worker, clock, vis } = setup(def);
    await handle.ready;
    clock.advance(500);
    vis.emit({ intersecting: false });
    vis.emit({ intersecting: true });
    button(r, "Atlas Cloud").click();
    await Promise.resolve();
    expect(worker.types().filter((t) => t === "menu_pick")).toEqual([]);
    clock.advance(300);
    button(r, "Atlas Cloud").click();
    await Promise.resolve();
    expect(worker.types()).toContain("menu_pick");
  });

  it("provider entry starts the chain with menu_signin", async () => {
    const { r, handle, worker, clock } = setup(def);
    await handle.ready;
    clock.advance(300);
    button(r, "Avec Google").click();
    await Promise.resolve();
    expect(worker.sent.at(-1)).toEqual({ type: "menu_signin", token: TOKEN, itemId: "it_02", provider: "google" });
  });

  it("the default provider account, and the others unfolded inline", async () => {
    const { r, handle, worker, clock } = setup(def, "login", CHOICES);
    await handle.ready;
    expect(r.querySelectorAll("button.row-sub")).toHaveLength(0);
    clock.advance(300);
    button(r, "Autre compte Google").click();
    const sub = r.querySelector<HTMLButtonElement>('button.row-sub[data-account="g_pro"]')!;
    expect(says(sub)).toBe("alex.pro@example.com | Google · Google pro | Continuer");
    expect(r.querySelector("button.row-fold")!.getAttribute("aria-expanded")).toBe("true");
    clock.advance(300);
    sub.click();
    await Promise.resolve();
    expect(worker.sent.at(-1)).toEqual({ type: "menu_signin", token: TOKEN, itemId: "it_02", provider: "google", accountId: "g_pro" });
    clock.advance(300);
    button(r, "Avec Google").click();
    await Promise.resolve();
    expect(worker.sent.at(-1)).toEqual({ type: "menu_signin", token: TOKEN, itemId: "it_02", provider: "google", accountId: "g_perso" });
  });

  it("keys relayed from the field move the highlight; Return picks it, after the delay only", async () => {
    const keys: string[][] = [["down"], ["down"], ["up"], ["enter"]];
    const pending: ((r: Reply) => void)[] = [];
    const { r, handle, worker, clock } = setup((m) => {
      if (m.type === "menu_keys") {
        const k = keys.shift();
        return k ? ok({ keys: k }) : new Promise<Reply>((res) => void pending.push(res));
      }
      return def();
    });
    await handle.ready;
    // The first three keys arrive at once, before the click delay ran out.
    for (let i = 0; i < 6; i++) await Promise.resolve();
    await new Promise((res) => setTimeout(res, 0));
    const opts = [...r.querySelectorAll("[role=option]")];
    expect(opts[0]!.classList.contains("active")).toBe(true);
    expect(opts[0]!.getAttribute("aria-selected")).toBe("true");
    // Return within 300 ms of the render: ignored, like a click.
    expect(worker.types()).toEqual(["menu_init"]);
    clock.advance(300);
    pending.shift()?.(ok({ keys: ["enter"] }));
    await new Promise((res) => setTimeout(res, 0));
    expect(worker.sent.filter((m) => m.type === "menu_pick")).toEqual([{ type: "menu_pick", token: TOKEN, itemId: "it_01" }]);
    // The focus never moved into the menu.
    expect(document.activeElement).toBe(document.body);
  });

  it("one selection: the pointer and the relayed keys move the same highlight", async () => {
    const keys: string[][] = [["down"]];
    const { r, handle } = setup((m) => {
      if (m.type === "menu_keys") {
        const k = keys.shift();
        return k ? ok({ keys: k }) : new Promise<Reply>(() => undefined);
      }
      return def();
    });
    await handle.ready;
    for (let i = 0; i < 6; i++) await Promise.resolve();
    await new Promise((res) => setTimeout(res, 0));
    const opts = [...r.querySelectorAll<HTMLElement>("[role=option]")];
    const selected = () => opts.filter((o) => o.classList.contains("active") || o.getAttribute("aria-selected") === "true");
    expect(selected()).toEqual([opts[0]]);
    // The pointer over another row takes the selection: never two rows highlighted.
    opts[2]!.dispatchEvent(new MouseEvent("mousemove", { bubbles: true }));
    expect(selected()).toEqual([opts[2]]);
    opts[1]!.dispatchEvent(new MouseEvent("mousemove", { bubbles: true }));
    expect(selected()).toEqual([opts[1]]);
  });

  it("keyboard: arrows move between options, Escape closes", async () => {
    const { r, handle, worker } = setup(def);
    await handle.ready;
    const opts = [...r.querySelectorAll<HTMLButtonElement>("[role=option]")];
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown" }));
    expect(document.activeElement).toBe(opts[0]);
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown" }));
    expect(document.activeElement).toBe(opts[1]);
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown" }));
    expect(document.activeElement).toBe(opts[2]);
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown" }));
    expect(document.activeElement).toBe(opts[0]);
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowUp" }));
    expect(document.activeElement).toBe(opts[2]);
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    expect(worker.sent.at(-1)).toEqual({ type: "menu_close", token: TOKEN });
  });

  it("locked, no unlock asked yet: the button; unlocked at once, the fill resumes (or the menu loads)", async () => {
    let locked = true;
    const { r, handle, worker, clock } = setup((m) => {
      if (m.type === "menu_init") return locked ? { err: "locked" } : def();
      // No native vault (macOS, other browsers): the app button.
      if (m.type === "menu_vault") return { err: "invalid" };
      // No gesture asked for this menu's unlock; later, the worker refuses the resume.
      if (m.type === "menu_resume") return { err: "invalid" };
      if (m.type === "menu_unlock") {
        locked = false;
        return ok({ locked: false });
      }
      return ok();
    });
    await handle.ready;
    await flush();
    expect(text(r)).toContain("OnePass est verrouillé");
    clock.advance(300);
    button(r, "Déverrouiller dans OnePass").click();
    await flush();
    await flush();
    expect(worker.types()).toEqual(["menu_init", "menu_vault", "menu_resume", "menu_unlock", "menu_resume", "menu_init"]);
    expect(text(r)).toContain("Atlas Cloud");
  });

  it("one gesture: the menu of a click that already asked the unlock opens waiting, no button, and resumes by itself", async () => {
    let locked = true;
    const { r, handle, worker, timers } = setup((m) => {
      if (m.type === "menu_init") return locked ? { err: "locked" } : def();
      if (m.type === "menu_vault") return { err: "invalid" };
      // The worker asked the app when the icon was clicked: still locked, then it resumes.
      if (m.type === "menu_resume") return locked ? { err: "locked" } : ok();
      return ok();
    });
    await handle.ready;
    await flush();
    await flush();
    expect(text(r)).toContain("Déverrouille OnePass pour continuer");
    expect(r.querySelector("button")).toBeNull();
    timers.runTimeouts();
    await flush();
    expect(text(r)).toContain("Déverrouille OnePass pour continuer");
    locked = false;
    timers.runTimeouts();
    await flush();
    // The worker closed the menu and filled: nothing more is asked, no click was needed.
    expect(worker.types()).toEqual(["menu_init", "menu_vault", "menu_resume", "menu_resume", "menu_resume"]);
    expect(worker.types()).not.toContain("menu_unlock");
    expect(timers.timeouts.size).toBe(0);
  });

  it("locked: the app comes forward, the menu waits for the unlock and reloads by itself", async () => {
    let locked = true;
    let asked = false;
    const { r, handle, worker, clock, timers } = setup((m) => {
      if (m.type === "menu_init") return locked ? { err: "locked" } : def();
      if (m.type === "menu_vault") return { err: "invalid" };
      if (m.type === "menu_unlock") {
        asked = true;
        return ok({ locked: true });
      }
      // Waiting while locked; then a frame's menu, or too late: the worker refuses, the menu reloads.
      if (m.type === "menu_resume") return asked && locked ? { err: "locked" } : { err: "invalid" };
      return ok();
    });
    await handle.ready;
    await flush();
    clock.advance(300);
    button(r, "Déverrouiller dans OnePass").click();
    await flush();
    expect(text(r)).toContain("Déverrouille OnePass pour continuer");
    timers.runTimeouts();
    await flush();
    expect(text(r)).toContain("Déverrouille OnePass pour continuer");
    locked = false;
    timers.runTimeouts();
    await flush();
    await flush();
    expect(text(r)).toContain("Atlas Cloud");
    expect(worker.types().filter((t) => t === "menu_unlock")).toHaveLength(1);
  });

  it("locked: after 90 s without unlock, the button comes back", async () => {
    let asked = false;
    const { r, handle, worker, clock, timers } = setup((m) => {
      if (m.type === "menu_init") return { err: "locked" };
      if (m.type === "menu_vault") return { err: "invalid" };
      if (m.type === "menu_unlock") {
        asked = true;
        return ok({ locked: true });
      }
      if (m.type === "menu_resume") return asked ? { err: "locked" } : { err: "invalid" };
      return ok();
    });
    await handle.ready;
    await flush();
    clock.advance(300);
    button(r, "Déverrouiller dans OnePass").click();
    await flush();
    expect(UNLOCK_WAIT_TRIES * UNLOCK_POLL_MS).toBe(UNLOCK_WAIT_MS);
    for (let i = 0; i < UNLOCK_WAIT_TRIES - 1; i++) {
      timers.runTimeouts();
      await flush();
    }
    expect(text(r)).toContain("Déverrouille OnePass pour continuer");
    timers.runTimeouts();
    await flush();
    expect(text(r)).toContain("OnePass est verrouillé");
    expect(button(r, "Déverrouiller dans OnePass")).toBeTruthy();
    // The wait is over: nothing polls any more.
    expect(timers.timeouts.size).toBe(0);
    expect(worker.types().filter((t) => t === "menu_resume")).toHaveLength(UNLOCK_WAIT_TRIES + 1);
  });

  it("the app is not running, launched by the gesture: the menu says so, waits, follows it to its unlock, then resumes", async () => {
    let state: "missing" | "locked" | "open" = "missing";
    const { r, handle, worker, timers } = setup((m) => {
      if (m.type === "menu_init") return { err: "host_missing" };
      if (m.type === "menu_resume") return state === "missing" ? { err: "host_missing" } : state === "locked" ? { err: "locked" } : ok();
      return ok();
    });
    await handle.ready;
    await flush();
    expect(text(r)).toContain("Ouverture de OnePass…");
    expect(r.querySelector("button")).toBeNull();
    state = "locked";
    timers.runTimeouts();
    await flush();
    expect(text(r)).toContain("Déverrouille OnePass pour continuer");
    state = "open";
    timers.runTimeouts();
    await flush();
    expect(worker.types()).toEqual(["menu_init", "menu_resume", "menu_resume", "menu_resume"]);
    expect(timers.timeouts.size).toBe(0);
  });

  it("the app is not running and no gesture launched it: Open OnePass launches it, then waits; the button comes back after 90 s", async () => {
    let asked = false;
    const { r, handle, worker, clock, timers } = setup((m) => {
      if (m.type === "menu_init") return { err: "host_missing" };
      if (m.type === "menu_unlock") {
        asked = true;
        return ok({ locked: true });
      }
      if (m.type === "menu_resume") return asked ? { err: "host_missing" } : { err: "invalid" };
      return ok();
    });
    await handle.ready;
    await flush();
    expect(text(r)).toContain("App OnePass introuvable");
    clock.advance(300);
    button(r, "Ouvrir OnePass").click();
    await flush();
    expect(worker.types()).toEqual(["menu_init", "menu_resume", "menu_unlock"]);
    expect(text(r)).toContain("Ouverture de OnePass…");
    for (let i = 0; i < UNLOCK_WAIT_TRIES; i++) {
      timers.runTimeouts();
      await flush();
    }
    expect(text(r)).toContain("App OnePass introuvable");
    expect(button(r, "Ouvrir OnePass")).toBeTruthy();
    expect(timers.timeouts.size).toBe(0);
  });

  it("the app cannot be opened: the button stays, with what to do", async () => {
    const { r, handle, clock } = setup((m) => {
      if (m.type === "menu_resume") return { err: "invalid" };
      return { err: "host_missing" };
    });
    await handle.ready;
    await flush();
    clock.advance(300);
    button(r, "Ouvrir OnePass").click();
    await flush();
    expect(text(r)).toContain("App OnePass introuvable");
    expect(text(r)).toContain("Ouvre l'app OnePass sur cet ordinateur, puis réessaie.");
    expect(button(r, "Ouvrir OnePass")).toBeTruthy();
  });

  it("iOS: the unlock sheet runs Face ID once by itself, then loads the menu", async () => {
    let locked = true;
    const { r, handle, worker } = setup((m) => {
      if (m.type === "menu_init") return locked ? { err: "locked" } : def();
      if (m.type === "menu_vault") return ok({ locked: true, account: "Camille", biometry: "faceID" });
      if (m.type === "menu_unlock_biometric") {
        locked = false;
        return ok({ locked: false, account: "Camille", biometry: "faceID" });
      }
      if (m.type === "menu_resume") return { err: "invalid" };
      return ok();
    });
    await handle.ready;
    await flush();
    await flush();
    expect(worker.types()).toEqual(["menu_init", "menu_vault", "menu_unlock_biometric", "menu_init"]);
    expect(text(r)).toContain("Atlas Cloud");
  });

  it("MS-03 (iOS): the automatic Face ID says no gesture; a tap on Face ID says one (the worker resumes in that call)", async () => {
    let first = true;
    const { r, handle, worker, clock } = setup((m) => {
      if (m.type === "menu_init") return { err: "locked" };
      if (m.type === "menu_vault") return ok({ locked: true, account: "Camille", biometry: "faceID" });
      if (m.type === "menu_unlock_biometric") {
        if (first) {
          first = false;
          return ok({ locked: true, account: "Camille", biometry: "faceID", error: "cancelled" });
        }
        return ok({ locked: false, account: "Camille", biometry: "faceID" });
      }
      return ok();
    });
    await handle.ready;
    for (let i = 0; i < 4; i++) await flush();
    expect(worker.sent.filter((m) => m.type === "menu_unlock_biometric")).toEqual([{ type: "menu_unlock_biometric", token: TOKEN }]);
    clock.advance(300);
    button(r, "Déverrouiller avec Face ID").click();
    for (let i = 0; i < 3; i++) await flush();
    expect(worker.sent.filter((m) => m.type === "menu_unlock_biometric").at(-1)).toEqual({ type: "menu_unlock_biometric", token: TOKEN, gesture: true });
    // One resume per unlock: the menu never asks for a second one after the sheet.
    expect(worker.types()).not.toContain("menu_resume");
  });

  it("MS-03 (iOS): an automatic Face ID that opens the vault never asks to resume", async () => {
    const { handle, worker } = setup((m) => {
      if (m.type === "menu_init") return { err: "locked" };
      if (m.type === "menu_vault") return ok({ locked: true, account: "Camille", biometry: "faceID" });
      if (m.type === "menu_unlock_biometric") return ok({ locked: false, account: "Camille", biometry: "faceID" });
      return ok();
    });
    await handle.ready;
    for (let i = 0; i < 4; i++) await flush();
    expect(worker.types().slice(0, 4)).toEqual(["menu_init", "menu_vault", "menu_unlock_biometric", "menu_init"]);
    expect(worker.sent.find((m) => m.type === "menu_unlock_biometric")).toEqual({ type: "menu_unlock_biometric", token: TOKEN });
    expect(worker.types()).not.toContain("menu_resume");
  });

  it("MS-03 (Mac): Touch ID in the app, then the menu resumes the fill by itself", async () => {
    let locked = true;
    let asked = false;
    const { r, handle, worker, clock, timers } = setup((m) => {
      if (m.type === "menu_init") return locked ? { err: "locked" } : def();
      if (m.type === "menu_vault") return { err: "invalid" };
      if (m.type === "menu_unlock") {
        asked = true;
        return ok({ locked: true });
      }
      if (m.type === "menu_resume") return !asked ? { err: "invalid" } : locked ? { err: "locked" } : ok();
      return ok();
    });
    await handle.ready;
    await flush();
    clock.advance(300);
    button(r, "Déverrouiller dans OnePass").click();
    await flush();
    locked = false;
    timers.runTimeouts();
    await flush();
    await flush();
    // The probe at load, then one check that resumed: the worker fills, the menu asks no more.
    expect(worker.types().filter((t) => t === "menu_resume")).toHaveLength(2);
    expect(worker.types().at(-1)).toBe("menu_resume");
  });

  it("iOS: a cancelled Face ID never runs again by itself; the button and the password stay", async () => {
    const { r, handle, worker, clock } = setup((m) => {
      if (m.type === "menu_init") return { err: "locked" };
      if (m.type === "menu_vault") return ok({ locked: true, account: "Camille", biometry: "faceID" });
      if (m.type === "menu_unlock_biometric") return ok({ locked: true, account: "Camille", biometry: "faceID", error: "cancelled" });
      return ok();
    });
    await handle.ready;
    for (let i = 0; i < 5; i++) await flush();
    expect(worker.types().filter((t) => t === "menu_unlock_biometric")).toHaveLength(1);
    expect(text(r)).toContain("Camille");
    expect(r.querySelector("input[type=password]")).not.toBeNull();
    clock.advance(300);
    button(r, "Déverrouiller avec Face ID").click();
    for (let i = 0; i < 5; i++) await flush();
    expect(worker.types().filter((t) => t === "menu_unlock_biometric")).toHaveLength(2);
  });

  it("iOS: the policy asks the password (no Face ID offered), a wrong one says so, the right one opens", async () => {
    let locked = true;
    const { r, handle, worker, clock } = setup((m) => {
      if (m.type === "menu_init") return locked ? { err: "locked" } : def();
      if (m.type === "menu_vault") return ok({ locked: true, account: "Camille", biometry: "none" });
      if (m.type === "menu_unlock_password") {
        if (m.password !== "bon-mot-de-passe") return ok({ locked: true, account: "Camille", biometry: "none", error: "wrong_password" });
        locked = false;
        return ok({ locked: false, account: "Camille", biometry: "none" });
      }
      if (m.type === "menu_resume") return { err: "invalid" };
      return ok();
    });
    await handle.ready;
    await flush();
    expect(worker.types()).not.toContain("menu_unlock_biometric");
    expect(r.querySelector(".unlock-bio")).toBeNull();
    const submit = (pw: string) => {
      const input = r.querySelector<HTMLInputElement>("input[type=password]")!;
      input.value = pw;
      r.querySelector("form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    };
    clock.advance(300);
    submit("faux");
    await flush();
    expect(text(r)).toContain("Mot de passe incorrect.");
    // The field never keeps the typed password.
    expect(r.querySelector<HTMLInputElement>("input[type=password]")!.value).toBe("");
    submit("bon-mot-de-passe");
    await flush();
    await flush();
    expect(text(r)).toContain("Atlas Cloud");
    expect(worker.types().filter((t) => t === "menu_unlock_password")).toHaveLength(2);
  });

  it("unpaired, host missing and malformed replies", async () => {
    let s = setup(() => ({ err: "unpaired" }));
    await s.handle.ready;
    expect(text(s.r)).toContain("OnePass n'est pas appairé");
    s = setup((m) => (m.type === "menu_resume" ? { err: "invalid" } : { err: "host_missing" }));
    await s.handle.ready;
    await flush();
    expect(text(s.r)).toContain("App OnePass introuvable");
    s = setup(() => ok({ origin: SITE, formKind: "login", items: [{ item_id: 3 }] }));
    await s.handle.ready;
    expect(text(s.r)).toContain("Erreur interne de OnePass.");
    // A raw host message is never shown.
    s = setup(() => ({ err: "<b>raw host text</b>" }));
    await s.handle.ready;
    expect(text(s.r)).toContain("Erreur interne de OnePass.");
    expect(s.r.querySelector("b")).toBeNull();
  });

  it("empty: Aucun login pour <domaine>", async () => {
    const { r, handle } = setup(() => ok({ origin: SITE, formKind: "login", items: [] }));
    await handle.ready;
    expect(text(r)).toContain("Aucun login pour atlas-cloud.test");
  });

  it("a signup that can make a passkey asks password or passkey first", async () => {
    const init = { origin: SITE, formKind: "signup", items: [login("it_01")], signup: { passkey: true } };
    const { r, handle, worker, clock } = setup((m) => (m.type === "menu_init" ? ok(init) : ok()), "signup");
    await handle.ready;
    const opts = [...r.querySelectorAll("[role=option]")];
    expect(opts[0]?.getAttribute("data-signup")).toBe("password");
    expect(opts[1]?.getAttribute("data-signup")).toBe("passkey");
    expect(says(opts[0]!)).toContain("Créer le compte avec un mot de passe fort");
    expect(says(opts[1]!)).toContain("Créer une passkey à la place");
    clock.advance(300);
    (opts[1] as HTMLButtonElement).click();
    await Promise.resolve();
    expect(worker.sent.at(-1)).toEqual({ type: "menu_signup", token: TOKEN, mode: "passkey" });
    clock.advance(300);
    (opts[0] as HTMLButtonElement).click();
    await Promise.resolve();
    expect(worker.sent.at(-1)).toEqual({ type: "menu_signup", token: TOKEN, mode: "password" });
  });

  it("no signup rows without the offer, nor with a malformed one", async () => {
    for (const extra of [{}, { signup: { passkey: "yes" } }]) {
      const init = { origin: SITE, formKind: "signup", items: [login("it_01")], ...extra };
      const { r, handle } = setup((m) => (m.type === "menu_init" ? ok(init) : ok()), "signup");
      await handle.ready;
      expect(r.querySelector("[data-signup]")).toBeNull();
    }
  });

  it("unpaired: Appairer avec OnePass asks the worker to open the popup", async () => {
    const { r, handle, worker, clock } = setup((m) => (m.type === "menu_init" ? { err: "unpaired" } : ok()));
    await handle.ready;
    clock.advance(300);
    button(r, "Appairer avec OnePass").click();
    await Promise.resolve();
    expect(worker.sent.at(-1)).toEqual({ type: "menu_pair", token: TOKEN });
  });

  it("signup form puts Générer un mot de passe above the site's logins", async () => {
    const { r, handle } = setup(def, "signup");
    await handle.ready;
    const rows = [...r.querySelectorAll("[role=option]")].map((x) => x.querySelector(".t1")?.textContent);
    expect(rows[0]).toBe("Générer un mot de passe");
    expect(rows).toContain("Atlas Cloud");
  });

  it("change-password form keeps Générer un mot de passe below the logins", async () => {
    const { r, handle } = setup(def, "change_password");
    await handle.ready;
    const rows = [...r.querySelectorAll("[role=option]")].map((x) => x.querySelector(".t1")?.textContent);
    expect(rows[0]).not.toBe("Générer un mot de passe");
    expect(rows).toContain("Générer un mot de passe");
  });

  it("signup form offers Générer un mot de passe", async () => {
    const { r, handle, worker, clock } = setup(def, "signup");
    await handle.ready;
    clock.advance(300);
    button(r, "Générer un mot de passe").click();
    await Promise.resolve();
    expect(worker.sent.at(-1)).toEqual({ type: "menu_generate", token: TOKEN });
  });

  it("a refused pick shows a French sentence, never markup from data", async () => {
    const { r, handle, clock } = setup((m) =>
      m.type === "menu_init"
        ? ok({ origin: SITE, formKind: "login", items: [login("it_01", { title: "<img src=x onerror=alert(1)>" })] })
        : { err: "origin_mismatch" },
    );
    await handle.ready;
    // The only image is the site's icon, never markup from the data.
    expect(r.querySelector("img:not(.site-img)")).toBeNull();
    expect(text(r)).toContain("<img src=x onerror=alert(1)>");
    clock.advance(300);
    button(r, "<img").click();
    await new Promise((res) => setTimeout(res, 0));
    expect(text(r)).toContain("La page a changé : remplissage annulé.");
  });

  it("an invalid hash never contacts the worker", async () => {
    const r = root();
    const worker = new FakeWorker(() => ok());
    await mountMenu(r, { send: worker.send, hash: "#bad", observe: () => undefined }).ready;
    expect(worker.sent).toEqual([]);
  });
});
