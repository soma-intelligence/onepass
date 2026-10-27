import { describe, expect, it } from "vitest";
import type { UiToBg } from "../../src/shared/messages";
import { mountMenu } from "../../src/ui/menu";
import { Clock, FakeVisibility, FakeWorker, HASH, type Reply, TOKEN, button, login, root, text } from "./helpers";

const SITE = "https://atlas-cloud.test";

function setup(answer: (m: UiToBg) => Reply, formKind = "login") {
  const r = root();
  const clock = new Clock();
  const vis = new FakeVisibility();
  const worker = new FakeWorker((m) => {
    if (m.type === "menu_init") {
      const res = answer(m);
      return "ok" in res && res.ok === "default"
        ? { ok: { origin: SITE, formKind, items: [login("it_01"), login("it_02", { title: "Atlas Perso", has_password: false, methods: [{ provider: "google", account_email: "alex.perso@example.com" }] })] } }
        : res;
    }
    return answer(m);
  });
  const handle = mountMenu(r, { send: worker.send, hash: HASH, now: clock.now, trusted: () => true, observe: vis.observe });
  return { r, clock, vis, worker, handle };
}

const ok = (v: unknown = {}): Reply => ({ ok: v });
const def = () => ok("default");

describe("inline menu", () => {
  it("renders the header, the logins and the provider entry", async () => {
    const { r, handle, worker } = setup(def);
    await handle.ready;
    expect(worker.sent[0]).toEqual({ type: "menu_init", token: TOKEN });
    expect(text(r)).toContain("OnePass · atlas-cloud.test");
    expect(text(r)).toContain("Atlas Cloud");
    expect(text(r)).toContain("alex@atlas.dev");
    expect(text(r)).toContain("Se connecter avec Google (alex.perso@example.com)");
    // A provider-only login has no password row.
    expect(text(r)).not.toContain("Atlas Perso alex@atlas.dev");
    // Two sign-in rows, then "Enregistrer un nouveau login".
    expect(r.querySelectorAll("[role=option]")).toHaveLength(3);
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
    button(r, "Se connecter avec Google").click();
    await Promise.resolve();
    expect(worker.sent.at(-1)).toEqual({ type: "menu_signin", token: TOKEN, itemId: "it_02", provider: "google" });
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

  it("locked state offers to unlock, then reloads", async () => {
    let locked = true;
    const { r, handle, worker, clock } = setup((m) => {
      if (m.type === "menu_init") return locked ? { err: "locked" } : def();
      if (m.type === "menu_unlock") {
        locked = false;
        return ok({ locked: false });
      }
      return ok();
    });
    await handle.ready;
    expect(text(r)).toContain("OnePass est verrouillé");
    clock.advance(300);
    button(r, "Déverrouiller dans OnePass").click();
    await new Promise((res) => setTimeout(res, 0));
    expect(worker.types()).toEqual(["menu_init", "menu_unlock", "menu_init"]);
    expect(text(r)).toContain("Atlas Cloud");
  });

  it("unpaired, host missing and malformed replies", async () => {
    let s = setup(() => ({ err: "unpaired" }));
    await s.handle.ready;
    expect(text(s.r)).toContain("Appairer OnePass depuis la barre d'outils");
    s = setup(() => ({ err: "host_missing" }));
    await s.handle.ready;
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
    expect(r.querySelector("img")).toBeNull();
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
