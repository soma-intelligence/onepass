import { describe, expect, it } from "vitest";
import type { UiToBg } from "../../src/shared/messages";
import type { SaveInit } from "../../src/shared/ui";
import type { Timers } from "../../src/ui/components";
import { mountSave } from "../../src/ui/save";
import { Clock, FakeWorker, HASH, type Reply, TOKEN, button, flush, root, text } from "./helpers";

const SITE = "https://atlas-cloud.test";
const base: SaveInit = {
  origin: SITE,
  site: "atlas-cloud.test",
  kind: "login",
  status: "new",
  title: "Atlas Cloud",
  username: "alex@atlas.dev",
  vaults: [
    { id: "v1", name: "Personnel" },
    { id: "v2", name: "Projet Atlas" },
  ],
};

class Later implements Timers {
  pending: (() => void)[] = [];
  setTimeout(fn: () => void) {
    this.pending.push(fn);
    return 0;
  }
  clearTimeout() {}
  setInterval() {
    return 0;
  }
  clearInterval() {}
}

function setup(init: SaveInit | { err: string }, extra?: (m: UiToBg) => Reply | null) {
  const r = root();
  const clock = new Clock();
  const timers = new Later();
  const worker = new FakeWorker((m) => {
    const x = extra?.(m);
    if (x) return x;
    if (m.type === "save_init") return "err" in init ? init : { ok: init };
    if (m.type === "save_reveal") return { ok: { password: "typed-Secret-1" } };
    if (m.type === "save_generate") return { ok: { password: "Gen-Pass-123" } };
    return { ok: {} };
  });
  const handle = mountSave(r, { send: worker.send, hash: HASH, now: clock.now, trusted: () => true, observe: () => undefined, timers });
  // Each view change restarts the 300 ms click guard: advance before clicks.
  const click = async (label: string) => {
    clock.advance(300);
    button(r, label).click();
    await flush();
  };
  return { r, worker, handle, click, timers, clock };
}

describe("save prompt", () => {
  it("card (new): site, username, vault chip, Enregistrer; password never shown", async () => {
    const { r, handle, worker, click, timers } = setup({ ...base, defaultVault: "v2" });
    await handle.ready;
    expect(worker.sent[0]).toEqual({ type: "save_init", token: TOKEN });
    expect(text(r)).toContain("Enregistrer le login pour atlas-cloud.test ?");
    expect(text(r)).toContain("alex@atlas.dev");
    expect(text(r)).not.toContain("typed-Secret-1");
    // The default vault is the one the worker picked (last used for the site).
    const chip = r.querySelector<HTMLButtonElement>("button.sc-chip")!;
    expect(chip.getAttribute("aria-label")).toBe("Coffre : Projet Atlas");
    // Pick the other vault from the chip.
    await click("Projet Atlas");
    expect([...r.querySelectorAll(".sc-vault")].map((x) => x.textContent)).toEqual(["Personnel", "Projet Atlas"]);
    await click("Personnel");
    expect(r.querySelector("button.sc-chip")!.getAttribute("aria-label")).toBe("Coffre : Personnel");
    await click("Enregistrer");
    expect(worker.sent.at(-1)).toEqual({
      type: "save_decide",
      token: TOKEN,
      decision: "save",
      edits: { title: "Atlas Cloud", username: "alex@atlas.dev", password: "", vaultId: "v1", rule: "domain", tags: [] },
    });
    // One quiet line, then it closes itself.
    expect(text(r)).toContain("Enregistré dans Personnel");
    timers.pending.forEach((f) => f());
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "save_close", token: TOKEN });
    expect(worker.types()).not.toContain("save_decide_later");
  });

  it("the vault name the worker reports wins, and an already saved login says so", async () => {
    let s = setup(base, (m) => (m.type === "save_decide" ? { ok: { outcome: "saved", vault: "Projet Atlas" } } : null));
    await s.handle.ready;
    await s.click("Enregistrer");
    expect(text(s.r)).toContain("Enregistré dans Projet Atlas");
    s = setup({ ...base, locked: true, vaults: [] }, (m) => (m.type === "save_decide" ? { ok: { outcome: "already" } } : null));
    await s.handle.ready;
    expect(text(s.r)).toContain("Verrouillé");
    // Locked: Save is offered (it unlocks first in the worker).
    expect(button(s.r, "Enregistrer").disabled).toBe(false);
    await s.click("Enregistrer");
    expect(text(s.r)).toContain("Déjà dans OnePass");
  });

  it("several OnePass accounts: the chip names the account too", async () => {
    const { r, handle } = setup({
      ...base,
      vaults: [
        { id: "v1", name: "Personnel", account: "Perso" },
        { id: "v2", name: "Équipe", account: "Augura" },
      ],
    });
    await handle.ready;
    expect(r.querySelector("button.sc-chip")!.getAttribute("aria-label")).toBe("Coffre : Perso · Personnel");
  });

  it("card (update): Mettre à jour le mot de passe, the item named, then update", async () => {
    const { r, handle, worker, click } = setup({ ...base, status: "update", update: { itemId: "it_01", title: "Atlas Cloud (multi)" } });
    await handle.ready;
    expect(text(r)).toContain("Mettre à jour le mot de passe pour atlas-cloud.test ?");
    expect(text(r)).toContain("Atlas Cloud (multi) · alex@atlas.dev");
    expect(r.querySelector("button.sc-chip")).toBeNull();
    await click("Mettre à jour");
    expect(worker.sent.filter((m) => m.type === "save_decide").at(-1)).toEqual({ type: "save_decide", token: TOKEN, decision: "update" });
    expect(text(r)).toContain("Mot de passe mis à jour");
  });

  it("update: the menu saves it as a new login instead", async () => {
    const { r, handle, worker, click, clock } = setup({ ...base, status: "update", update: { itemId: "it_01", title: "Atlas Cloud" } });
    await handle.ready;
    clock.advance(300);
    r.querySelector<HTMLButtonElement>("button[aria-label=Options]")!.click();
    await flush();
    await click("Enregistrer comme nouveau login");
    expect(text(r)).toContain("Enregistrer le login pour atlas-cloud.test ?");
    await click("Enregistrer");
    expect((worker.sent.at(-1) as { decision: string }).decision).toBe("save");
  });

  it("menu: Ne jamais proposer pour ce site", async () => {
    const { r, handle, worker, click, clock } = setup(base);
    await handle.ready;
    clock.advance(300);
    r.querySelector<HTMLButtonElement>("button[aria-label=Options]")!.click();
    await flush();
    expect(text(r)).toContain("Modifier avant d'enregistrer");
    await click("Ne jamais proposer pour ce site");
    expect(worker.sent.at(-1)).toEqual({ type: "save_decide", token: TOKEN, decision: "never" });
    expect(text(r)).toContain("OnePass ne proposera plus rien ici");
  });

  it("Pas maintenant dismisses", async () => {
    const { handle, worker, click } = setup(base);
    await handle.ready;
    await click("Pas maintenant");
    expect(worker.sent.at(-1)).toEqual({ type: "save_decide", token: TOKEN, decision: "dismiss" });
  });

  it("left alone 20 s, the card goes and the sign-in waits in the popup; not while hovered", async () => {
    const { r, handle, worker, timers } = setup(base);
    await handle.ready;
    // Hovered: the timer is stopped (its callback does nothing).
    r.querySelector(".save")!.dispatchEvent(new Event("pointerenter"));
    timers.pending.splice(0).forEach((f) => f());
    await flush();
    expect(worker.types()).not.toContain("save_decide");
    r.querySelector(".save")!.dispatchEvent(new Event("pointerleave"));
    timers.pending.splice(0).forEach((f) => f());
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "save_decide", token: TOKEN, decision: "later" });
  });

  it("edit view: fields, reveal on click only, Générer, rule and tags", async () => {
    const { r, handle, worker, click, clock } = setup(base);
    await handle.ready;
    clock.advance(300);
    r.querySelector<HTMLButtonElement>("button[aria-label=Options]")!.click();
    await flush();
    await click("Modifier avant d'enregistrer");
    expect(text(r)).toContain("Enregistrer l'élément");
    expect(text(r)).toContain("nom d'utilisateur");
    expect(text(r)).toContain("site web");
    expect(text(r)).toContain(SITE);
    const rules = [...r.querySelectorAll<HTMLOptionElement>("select[aria-label=Correspondance] option")].map((o) => o.textContent);
    expect(rules).toEqual(["Tout le domaine", "Sous-domaine exact", "URL exacte", "Jamais remplir"]);
    // Masked until "Afficher".
    expect(text(r)).not.toContain("typed-Secret-1");
    expect(worker.types()).not.toContain("save_reveal");
    await click("Afficher");
    expect(worker.sent.at(-1)).toEqual({ type: "save_reveal", token: TOKEN });
    expect(r.querySelector(".pwd-value")!.textContent).toBe("typed-Secret-1");
    await click("Masquer");
    expect(r.querySelector(".pwd-value")!.textContent).not.toBe("typed-Secret-1");
    await click("Générer");
    expect(worker.sent.at(-1)).toEqual({ type: "save_generate", token: TOKEN });
    expect(r.querySelector(".pwd-value")!.textContent).toBe("Gen-Pass-123");
    // Edits.
    const title = r.querySelector<HTMLInputElement>("input[aria-label=Titre]")!;
    title.value = "Atlas Admin";
    title.dispatchEvent(new Event("input"));
    const rule = r.querySelector<HTMLSelectElement>("select[aria-label=Correspondance]")!;
    rule.value = "exact_host";
    rule.dispatchEvent(new Event("change"));
    const tag = r.querySelector<HTMLInputElement>("input[aria-label='Ajouter un tag']")!;
    tag.value = "Travail";
    tag.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    expect(text(r)).toContain("Travail");
    await click("Enregistrer");
    expect(worker.sent.at(-1)).toEqual({
      type: "save_decide",
      token: TOKEN,
      decision: "save",
      edits: { title: "Atlas Admin", username: "alex@atlas.dev", password: "", vaultId: "v1", rule: "exact_host", tags: ["Travail"] },
    });
    expect(text(r)).toContain("Atlas Admin enregistré");
  });

  it("provider link variant", async () => {
    const { r, handle, worker, click } = setup({
      ...base,
      kind: "provider_link",
      username: "",
      vaults: [],
      provider: { id: "google", email: "alex.perso@example.com", title: "Google perso" },
    });
    await handle.ready;
    // One compact prompt: the site, the provider, and the very account item the link points to.
    expect(r.querySelector("h1")!.textContent).toBe("Retenir ce lien ?");
    expect(r.querySelector(".link-card .t1")!.textContent).toBe("atlas-cloud.test ↔ Google");
    expect(r.querySelector(".link-card .line2")!.textContent).toBe("alex.perso@example.com · Google perso");
    expect(r.querySelector(".link-card .way-badge svg.glyph-p_google")).not.toBeNull();
    expect(r.querySelector(".save")!.classList.contains("fit")).toBe(true);
    await click("Enregistrer");
    expect(worker.sent.at(-1)).toEqual({ type: "save_decide", token: TOKEN, decision: "save" });
    expect(text(r)).toContain("Lien enregistré");
  });

  it("no vault: Enregistrer disabled, Aucun coffre disponible in the edit view", async () => {
    const { r, handle, worker, click, clock } = setup({ ...base, vaults: [] });
    await handle.ready;
    expect(button(r, "Enregistrer").disabled).toBe(true);
    await click("Enregistrer");
    expect(worker.types()).not.toContain("save_decide");
    clock.advance(300);
    r.querySelector<HTMLButtonElement>("button[aria-label=Options]")!.click();
    await flush();
    await click("Modifier avant d'enregistrer");
    expect(text(r)).toContain("Aucun coffre disponible");
    expect(button(r, "Enregistrer").disabled).toBe(true);
  });

  it("errors are French sentences", async () => {
    let s = setup({ err: "locked" });
    await s.handle.ready;
    expect(text(s.r)).toContain("OnePass est verrouillé");
    s = setup(base, (m) => (m.type === "save_decide" ? { err: "rate_limited" } : null));
    await s.handle.ready;
    await s.click("Enregistrer");
    expect(text(s.r)).toContain("Trop de demandes. Réessaie dans une minute.");
  });

  it("new login from the menu: edit view at once, site prefilled, identifier and password typed", async () => {
    const { r, handle, worker, click } = setup({ ...base, username: "", view: "edit" });
    await handle.ready;
    expect(text(r)).toContain("Enregistrer l'élément");
    expect(text(r)).toContain(SITE);
    const user = r.querySelector<HTMLInputElement>("input[aria-label=\"nom d'utilisateur\"]")!;
    expect(user.value).toBe("");
    const pwd = r.querySelector<HTMLInputElement>("input[aria-label=\"mot de passe\"]")!;
    expect(pwd.type).toBe("password");
    expect(pwd.value).toBe("");
    // Nothing to reveal: the worker holds no password yet.
    expect(() => button(r, "Afficher")).toThrow();
    // No password yet: nothing can be saved.
    expect(button(r, "Enregistrer").disabled).toBe(true);
    user.value = "alex@atlas.dev";
    user.dispatchEvent(new Event("input"));
    expect(button(r, "Enregistrer").disabled).toBe(true);
    pwd.value = "Typed-Pass-9";
    pwd.dispatchEvent(new Event("input"));
    expect(button(r, "Enregistrer").disabled).toBe(false);
    pwd.value = "";
    pwd.dispatchEvent(new Event("input"));
    expect(button(r, "Enregistrer").disabled).toBe(true);
    pwd.value = "Typed-Pass-9";
    pwd.dispatchEvent(new Event("input"));
    await click("Enregistrer");
    expect(worker.sent.at(-1)).toEqual({
      type: "save_decide",
      token: TOKEN,
      decision: "save",
      edits: { title: "Atlas Cloud", username: "alex@atlas.dev", password: "Typed-Pass-9", vaultId: "v1", rule: "domain", tags: [] },
    });
  });

  it("new login: Générer fills the field and the worker keeps that password; Fermer dismisses", async () => {
    const { r, handle, worker, click } = setup({ ...base, username: "", view: "edit" });
    await handle.ready;
    await click("Générer");
    const pwd = r.querySelector<HTMLInputElement>("input[aria-label=\"mot de passe\"]")!;
    expect(pwd.value).toBe("Gen-Pass-123");
    expect(button(r, "Enregistrer").disabled).toBe(false);
    await click("Enregistrer");
    // The generated one is held by the worker: not sent back.
    expect((worker.sent.at(-1) as { edits: { password: string } }).edits.password).toBe("");
    const s2 = setup({ ...base, username: "", view: "edit" });
    await s2.handle.ready;
    s2.clock.advance(300);
    r.ownerDocument.body.append(s2.r);
    s2.r.querySelector<HTMLButtonElement>("button[aria-label=Fermer]")!.click();
    await flush();
    expect(s2.worker.sent.at(-1)).toEqual({ type: "save_decide", token: TOKEN, decision: "dismiss" });
  });
});
