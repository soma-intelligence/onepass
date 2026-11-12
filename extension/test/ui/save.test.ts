import { describe, expect, it } from "vitest";
import type { UiToBg } from "../../src/shared/messages";
import type { SaveInit } from "../../src/shared/ui";
import type { Timers } from "../../src/ui/components";
import { AUTO_DISMISS_MS, TOAST_MS, mountSave } from "../../src/ui/save";
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

  it("Plus tard folds the card into the pill at once (no decision)", async () => {
    const { r, handle, worker, click } = setup(base);
    await handle.ready;
    await click("Plus tard");
    expect(worker.sent.at(-1)).toEqual({ type: "save_fold", token: TOKEN });
    expect(worker.types()).not.toContain("save_decide");
    expect(r.querySelector(".save-pill")).not.toBeNull();
    expect(text(r)).toContain("1 login à enregistrer");
    expect(r.querySelector(".save-card")).toBeNull();
  });

  it("the card of a card or an address keeps Pas maintenant, which dismisses", async () => {
    const { handle, worker, click } = setup({ ...base, kind: "card", card: { last4: "4242" } });
    await handle.ready;
    await click("Pas maintenant");
    expect(worker.sent.at(-1)).toEqual({ type: "save_decide", token: TOKEN, decision: "dismiss" });
  });

  it("update card folds after AUTO_DISMISS_MS into the pill; not while hovered", async () => {
    const upd: SaveInit = { ...base, status: "update", update: { itemId: "it_01", title: "Atlas Cloud" } };
    const { r, handle, worker, timers } = setup(upd);
    await handle.ready;
    // Hovered: the timer is stopped (its callback does nothing).
    r.querySelector(".save")!.dispatchEvent(new Event("pointerenter"));
    timers.pending.splice(0).forEach((f) => f());
    await flush();
    expect(worker.types()).not.toContain("save_fold");
    r.querySelector(".save")!.dispatchEvent(new Event("pointerleave"));
    timers.pending.splice(0).forEach((f) => f());
    await flush();
    expect(worker.sent.filter((m) => m.type === "save_fold")).toEqual([{ type: "save_fold", token: TOKEN }]);
    expect(worker.types()).not.toContain("save_decide");
    expect(text(r)).toContain("1 login à mettre à jour");
    expect(AUTO_DISMISS_MS).toBe(20_000);
  });

  it("the frame height shrinks when the card folds", async () => {
    const heights = new Map<string, number>([
      ["save-card", 120],
      ["save-pill", 40],
    ]);
    const orig = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollHeight");
    Object.defineProperty(HTMLElement.prototype, "scrollHeight", {
      configurable: true,
      get(this: HTMLElement) {
        for (const [cls, h] of heights) if (this.querySelector(`.${cls}`)) return h;
        return 0;
      },
    });
    try {
      const { handle, worker, click } = setup(base);
      await handle.ready;
      await new Promise((r) => setTimeout(r, 40));
      await click("Plus tard");
      await new Promise((r) => setTimeout(r, 40));
      const resizes = worker.sent.filter((m) => m.type === "save_resize").map((m) => (m as { height: number }).height);
      expect(resizes[0]).toBe(120);
      expect(resizes.at(-1)).toBe(40);
    } finally {
      if (orig) Object.defineProperty(HTMLElement.prototype, "scrollHeight", orig);
      else delete (HTMLElement.prototype as { scrollHeight?: number }).scrollHeight;
    }
  });

  it("the pill's width goes with its height; the card's width is back after unfolding", async () => {
    const orig = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollHeight");
    const origW = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetWidth");
    Object.defineProperty(HTMLElement.prototype, "scrollHeight", {
      configurable: true,
      get(this: HTMLElement) {
        return this.querySelector(".save-pill") ? 40 : this.querySelector(".save-card") ? 120 : 0;
      },
    });
    Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
      configurable: true,
      get(this: HTMLElement) {
        return this.classList.contains("save-pill-wrap") ? 188 : 340;
      },
    });
    try {
      const { handle, worker, click } = setup(base);
      await handle.ready;
      await new Promise((r) => setTimeout(r, 40));
      const sizes = () => worker.sent.filter((m) => m.type === "save_resize") as { height: number; width?: number }[];
      expect(sizes().at(-1)).toMatchObject({ height: 120 });
      expect(sizes().at(-1)!.width).toBeUndefined();
      await click("Plus tard");
      await new Promise((r) => setTimeout(r, 40));
      expect(sizes().at(-1)).toMatchObject({ height: 40, width: 188 });
      await click("1 login à enregistrer");
      await new Promise((r) => setTimeout(r, 40));
      expect(sizes().at(-1)).toMatchObject({ height: 120 });
      expect(sizes().at(-1)!.width).toBeUndefined();
    } finally {
      for (const [k, d] of [["scrollHeight", orig], ["offsetWidth", origW]] as const) {
        if (d) Object.defineProperty(HTMLElement.prototype, k, d);
        else delete (HTMLElement.prototype as unknown as Record<string, unknown>)[k];
      }
    }
  });

  it("the pill's width is sent again when only its width changes (late font)", async () => {
    let w = 188;
    const origW = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetWidth");
    const origH = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollHeight");
    Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
      configurable: true,
      get(this: HTMLElement) {
        return this.classList.contains("save-pill-wrap") ? w : 340;
      },
    });
    Object.defineProperty(HTMLElement.prototype, "scrollHeight", { configurable: true, get: () => 40 });
    try {
      const r = root();
      const clock = new Clock();
      const observers: (() => void)[] = [];
      const worker = new FakeWorker((m) => (m.type === "save_init" ? { ok: base } : { ok: {} }));
      const handle = mountSave(r, {
        send: worker.send,
        hash: HASH,
        now: clock.now,
        trusted: () => true,
        observe: () => undefined,
        timers: new Later(),
        observeSize: (_el, cb) => void observers.push(cb),
      });
      await handle.ready;
      clock.advance(300);
      button(r, "Plus tard").click();
      await flush();
      const widths = () => worker.sent.filter((m) => m.type === "save_resize").map((m) => (m as { width?: number }).width);
      expect(widths().at(-1)).toBe(188);
      await new Promise((x) => setTimeout(x, 30));
      const n = widths().length;
      // Nothing changed: no new message.
      observers.forEach((f) => f());
      await new Promise((x) => setTimeout(x, 30));
      expect(widths()).toHaveLength(n);
      w = 204;
      observers.forEach((f) => f());
      await new Promise((x) => setTimeout(x, 30));
      expect(widths().at(-1)).toBe(204);
      expect(r.querySelector(".save-pill-text")).not.toBeNull();
    } finally {
      for (const [k, d] of [["offsetWidth", origW], ["scrollHeight", origH]] as const) {
        if (d) Object.defineProperty(HTMLElement.prototype, k, d);
        else delete (HTMLElement.prototype as unknown as Record<string, unknown>)[k];
      }
    }
  });

  it("pill click unfolds the card (save_unfold) and the card works again", async () => {
    const upd: SaveInit = { ...base, status: "update", update: { itemId: "it_01", title: "Atlas Cloud" } };
    const { r, handle, worker, click } = setup(upd);
    await handle.ready;
    await click("Plus tard");
    expect(text(r)).toContain("1 login à mettre à jour");
    await click("1 login à mettre à jour");
    expect(worker.sent.at(-1)).toEqual({ type: "save_unfold", token: TOKEN });
    expect(r.querySelector(".save-pill")).toBeNull();
    expect(text(r)).toContain("Mettre à jour le mot de passe pour atlas-cloud.test ?");
    await click("Mettre à jour");
    expect(worker.sent.at(-1)).toMatchObject({ type: "save_decide", decision: "update" });
  });

  it("a frame reloaded on a folded record opens as the pill", async () => {
    const { r, handle } = setup({ ...base, folded: true });
    await handle.ready;
    expect(r.querySelector(".save-pill")).not.toBeNull();
    expect(text(r)).toContain("1 login à enregistrer");
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

  it("saved view: a confirmed signup shows done, nothing to answer, and closes itself", async () => {
    const { r, handle, worker, timers } = setup({ ...base, username: "alex@atlas.dev", view: "saved" });
    await handle.ready;
    expect(text(r)).toContain("Atlas Cloud enregistré");
    expect(text(r)).toContain("alex@atlas.dev");
    expect(() => button(r, "Enregistrer")).toThrow();
    expect(worker.sent.some((m) => (m as { type?: string }).type === "save_decide")).toBe(false);
    timers.pending.forEach((f) => f());
    expect(worker.sent.at(-1)).toEqual({ type: "save_close", token: TOKEN });
  });

  it("MS-04 card: 'Enregistrer cette carte ?', last four digits and expiry, Save sends only the vault", async () => {
    const init: SaveInit = { ...base, kind: "card", username: "", card: { last4: "1111", exp: "04/29", holder: "Alex Martin" }, defaultVault: "v2" };
    const { r, handle, worker, click } = setup(init, (m) => (m.type === "save_decide" ? { ok: { outcome: "saved", vault: "Projet Atlas" } } : null));
    await handle.ready;
    expect(text(r)).toContain("Enregistrer cette carte ?");
    expect(text(r)).toContain("Carte •••• 1111 · exp. 04/29");
    expect(text(r)).toContain("Alex Martin");
    await click("Enregistrer");
    expect(worker.sent.at(-1)).toEqual({
      type: "save_decide",
      token: TOKEN,
      decision: "save",
      edits: { title: "", username: "", password: "", vaultId: "v2", rule: "domain", tags: [] },
    });
    expect(text(r)).toContain("Carte enregistrée");
  });

  it("MS-04 card update and address: their own titles; 'Pas maintenant' dismisses", async () => {
    const up = setup({ ...base, kind: "card", status: "update", username: "", update: { itemId: "card_1", title: "Visa" }, card: { last4: "1111", exp: "05/31" } });
    await up.handle.ready;
    expect(text(up.r)).toContain("Mettre à jour cette carte ?");
    await up.click("Mettre à jour");
    expect(up.worker.sent.at(-1)).toEqual({ type: "save_decide", token: TOKEN, decision: "update" });

    const ad = setup({ ...base, kind: "identity", username: "", identity: { name: "Camille Durand", place: "1 rue de la Paix, 75002, Paris" } });
    await ad.handle.ready;
    expect(text(ad.r)).toContain("Enregistrer cette adresse ?");
    expect(text(ad.r)).toContain("1 rue de la Paix, 75002, Paris");
    await ad.click("Pas maintenant");
    expect(ad.worker.sent.at(-1)).toEqual({ type: "save_decide", token: TOKEN, decision: "dismiss" });
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

describe("save toast (spec 4.1, 4.4)", () => {
  /** Timeouts with their delay, fired by hand. */
  class Delays implements Timers {
    pending = new Map<number, { fn: () => void; ms: number }>();
    private n = 0;
    setTimeout(fn: () => void, ms: number) {
      this.pending.set(++this.n, { fn, ms });
      return this.n;
    }
    clearTimeout(id: unknown) {
      this.pending.delete(id as number);
    }
    setInterval() {
      return 0;
    }
    clearInterval() {}
    /** Fires every timeout of `ms`. */
    fire(ms: number) {
      for (const [id, t] of [...this.pending]) {
        if (t.ms !== ms) continue;
        this.pending.delete(id);
        t.fn();
      }
    }
  }

  const toast: SaveInit = { ...base, view: "toast", undo: true, defaultVault: "v2" };

  function setupToast(init: SaveInit, extra?: (m: UiToBg) => Reply | null) {
    const r = root();
    const clock = new Clock();
    const timers = new Delays();
    const worker = new FakeWorker((m) => {
      const x = extra?.(m);
      if (x) return x;
      if (m.type === "save_init") return { ok: init };
      return { ok: {} };
    });
    const handle = mountSave(r, { send: worker.send, hash: HASH, now: clock.now, trusted: () => true, observe: () => undefined, timers });
    const click = async (label: string) => {
      clock.advance(300);
      button(r, label).click();
      await flush();
    };
    return { r, worker, handle, click, timers };
  }

  it("toast shows site and two actions", async () => {
    const { r, handle } = setupToast(toast);
    await handle.ready;
    expect(TOAST_MS).toBe(8000);
    expect(text(r)).toContain("Login pour atlas-cloud.test enregistré");
    expect(text(r)).toContain("alex@atlas.dev");
    expect(r.querySelector("[role=status]")).not.toBeNull();
    expect(button(r, "Annuler")).toBeTruthy();
    expect(button(r, "Modifier")).toBeTruthy();
    // A generated password confirmed at the submission (spec 4.4): saved, neither Undo nor Edit.
    const s = setupToast({ ...base, view: "toast" });
    await s.handle.ready;
    expect(text(s.r)).toContain("Login pour atlas-cloud.test enregistré");
    expect(() => button(s.r, "Annuler")).toThrow();
    expect(() => button(s.r, "Modifier")).toThrow();
  });

  it("toast stays while hovered and goes after 8000 ms otherwise", async () => {
    const { r, handle, worker, timers } = setupToast(toast);
    await handle.ready;
    r.querySelector(".save")!.dispatchEvent(new Event("pointerenter"));
    timers.fire(TOAST_MS);
    await flush();
    expect(worker.types()).not.toContain("save_close");
    r.querySelector(".save")!.dispatchEvent(new Event("pointerleave"));
    timers.fire(TOAST_MS - 1);
    await flush();
    expect(worker.types()).not.toContain("save_close");
    timers.fire(TOAST_MS);
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "save_close", token: TOKEN });
    // Never "later": the login is saved, nothing waits in the popup.
    expect(worker.sent.some((m) => m.type === "save_decide")).toBe(false);
  });

  it('Undo sends save_undo and shows "Removed"', async () => {
    const { r, handle, worker, click } = setupToast(toast);
    await handle.ready;
    await click("Annuler");
    expect(worker.sent.at(-1)).toEqual({ type: "save_undo", token: TOKEN });
    expect(text(r)).toContain("Supprimé");
    // The bridge refused (too late, edited): said so, nothing crashes.
    const s = setupToast(toast, (m) => (m.type === "save_undo" ? { err: "not_found" } : null));
    await s.handle.ready;
    await s.click("Annuler");
    expect(text(s.r)).toContain("Impossible d'annuler");
  });

  it("Edit opens the edit view with name, identifier, vault", async () => {
    const { r, handle, worker, click } = setupToast(toast, (m) => (m.type === "save_decide" ? { ok: { outcome: "saved", vault: "Projet Atlas" } } : null));
    await handle.ready;
    await click("Modifier");
    expect(worker.sent.at(-1)).toEqual({ type: "save_edit", token: TOKEN });
    const title = r.querySelector<HTMLInputElement>("input.title-input")!;
    expect(title.value).toBe("Atlas Cloud");
    const user = r.querySelector<HTMLInputElement>(`input[aria-label="nom d'utilisateur"]`)!;
    expect(user.value).toBe("alex@atlas.dev");
    const vault = r.querySelector<HTMLSelectElement>('select[aria-label="Coffre"]')!;
    expect(vault.value).toBe("v2");
    expect(button(r, "Ne jamais proposer pour ce site")).toBeTruthy();
    title.value = "Atlas pro";
    title.dispatchEvent(new Event("input"));
    await click("Enregistrer");
    expect(worker.sent.at(-1)).toEqual({
      type: "save_decide",
      token: TOKEN,
      decision: "save",
      edits: { title: "Atlas pro", username: "alex@atlas.dev", password: "", vaultId: "v2", rule: "domain", tags: [] },
    });
  });
});
