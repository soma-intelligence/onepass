import { describe, expect, it } from "vitest";
import type { UiToBg } from "../../src/shared/messages";
import type { Timers } from "../../src/ui/components";
import { GENERATOR_TYPES, mountPopup } from "../../src/ui/popup";
import { FakeWorker, type Reply, button, login, root, text } from "./helpers";

class ManualTimers implements Timers {
  private n = 0;
  readonly timeouts = new Map<number, () => void>();
  readonly intervals = new Map<number, () => void>();
  setTimeout(fn: () => void) {
    this.timeouts.set(++this.n, fn);
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
  runTimeouts() {
    const fns = [...this.timeouts.values()];
    this.timeouts.clear();
    fns.forEach((f) => f());
  }
  tick() {
    [...this.intervals.values()].forEach((f) => f());
  }
}

const STATUS = { locked: false, account: "alex@atlas.dev", vaults: 2 };
const items = [login("it_01", { has_totp: true }), login("id_01", { kind: "identity", title: "Alex Martin", subtitle: "Identité", has_password: false })];

function worker(over: (m: UiToBg) => Reply | null = () => null) {
  return new FakeWorker((m) => {
    const x = over(m);
    if (x) return x;
    switch (m.type) {
      case "popup_status":
        return { ok: STATUS };
      case "popup_suggestions":
        return { ok: { domain: "atlas-cloud.test", items } };
      case "popup_item": {
        const s = items.find((i) => i.item_id === m.itemId)!;
        return { ok: { summary: s, website: "https://atlas-cloud.test" } };
      }
      case "popup_reveal":
        return { ok: { value: "pw-Secret-1" } };
      case "popup_totp":
        return { ok: { code: "703083", remaining: 2 } };
      case "popup_fill":
      case "popup_fill_generated":
        return { ok: { domain: "atlas-cloud.test" } };
      case "popup_search":
        return { ok: { items: [login("it_09", { title: "GitHub (Atlas)" })] } };
      case "popup_generate":
        return { ok: { password: m.kind === "pin" ? "482913" : "abcd7e.XYZ.wxyz4kq", entropy_bits: 90 } };
      case "popup_history":
        return { ok: { entries: [{ password: "old-Pass-1", kind: "random", at: 1 }] } };
      case "popup_pair_start":
        return { ok: { sas: "123 456" } };
      default:
        return { ok: {} };
    }
  });
}

function setup(w = worker()) {
  const r = root();
  const timers = new ManualTimers();
  const copied: string[] = [];
  const handle = mountPopup(r, { send: w.send, timers, copy: async (t) => void copied.push(t) });
  return { r, w, timers, handle, copied };
}

describe("popup", () => {
  it("unpaired: Appairer avec OnePass, then the code and its two buttons", async () => {
    const w = worker((m) => (m.type === "popup_status" ? { err: "unpaired" } : null));
    const { r, handle } = setup(w);
    await handle.ready;
    expect(text(r)).toContain("OnePass n'est pas appairé");
    button(r, "Appairer avec OnePass").click();
    await handle.settled();
    expect(text(r)).toContain("123 456");
    expect(button(r, "Les codes sont identiques")).toBeTruthy();
    expect(button(r, "Annuler")).toBeTruthy();
    button(r, "Annuler").click();
    await handle.settled();
    expect(w.types()).toContain("popup_pair_cancel");
    expect(text(r)).toContain("Appairer avec OnePass");
  });

  it("re-pairing is offered on unpaired even when a record exists, and approval reloads", async () => {
    // The worker holds a record the host no longer knows: it answers `unpaired`.
    let paired = false;
    const w = worker((m) => {
      if (m.type === "popup_status" && !paired) return { err: "unpaired" };
      if (m.type === "popup_pair_approve") {
        paired = true;
        return { ok: {} };
      }
      return null;
    });
    const { r, handle } = setup(w);
    await handle.ready;
    button(r, "Appairer avec OnePass").click();
    await handle.settled();
    button(r, "Les codes sont identiques").click();
    await handle.settled();
    expect(w.types()).toEqual(["popup_status", "popup_pair_start", "popup_pair_approve", "popup_status", "popup_suggestions"]);
    expect(text(r)).toContain("Suggestions pour atlas-cloud.test");
  });

  it("locked: Déverrouiller dans OnePass", async () => {
    let locked = true;
    const w = worker((m) => {
      if (m.type === "popup_status") return { ok: { ...STATUS, locked } };
      if (m.type === "popup_unlock") {
        locked = false;
        return { ok: { locked: false } };
      }
      return null;
    });
    const { r, handle } = setup(w);
    await handle.ready;
    expect(text(r)).toContain("OnePass est verrouillé");
    button(r, "Déverrouiller dans OnePass").click();
    await handle.settled();
    expect(text(r)).toContain("Suggestions pour atlas-cloud.test");
  });

  it("Oublier cet appairage: confirmation, then the unpaired state", async () => {
    let paired = true;
    const w = worker((m) => {
      if (m.type === "popup_status" && !paired) return { err: "unpaired" };
      if (m.type === "popup_forget") {
        paired = false;
        return { ok: {} };
      }
      return null;
    });
    const { r, handle } = setup(w);
    await handle.ready;
    button(r, "Oublier cet appairage").click();
    await handle.settled();
    expect(r.querySelector("h1")?.textContent).toBe("Oublier cet appairage ?");
    expect(text(r)).toContain("Il faudra appairer à nouveau.");
    expect(w.types()).not.toContain("popup_forget");
    button(r, "Annuler").click();
    await handle.settled();
    expect(text(r)).toContain("Suggestions pour atlas-cloud.test");
    button(r, "Oublier cet appairage").click();
    await handle.settled();
    button(r, "Oublier").click();
    await handle.settled();
    expect(w.types().filter((t) => t === "popup_forget")).toHaveLength(1);
    expect(text(r)).toContain("OnePass n'est pas appairé");
    expect(button(r, "Appairer avec OnePass")).toBeTruthy();
  });

  it("Oublier cet appairage is reachable while locked", async () => {
    const w = worker((m) => (m.type === "popup_status" ? { ok: { ...STATUS, locked: true } } : null));
    const { r, handle } = setup(w);
    await handle.ready;
    expect(text(r)).toContain("OnePass est verrouillé");
    button(r, "Oublier cet appairage").click();
    await handle.settled();
    button(r, "Annuler").click();
    await handle.settled();
    expect(text(r)).toContain("OnePass est verrouillé");
    button(r, "Oublier cet appairage").click();
    await handle.settled();
    button(r, "Oublier").click();
    await handle.settled();
    expect(w.types()).toContain("popup_forget");
    expect(text(r)).toContain("Appairer avec OnePass");
  });

  it("host missing: App OnePass introuvable", async () => {
    const { r, handle } = setup(worker((m) => (m.type === "popup_status" ? { err: "host_missing" } : null)));
    await handle.ready;
    expect(text(r)).toContain("App OnePass introuvable");
    expect(button(r, "Réessayer")).toBeTruthy();
  });

  it("suggestions for the domain, verified domain note", async () => {
    const { r, handle } = setup();
    await handle.ready;
    expect(text(r)).toContain("Suggestions pour atlas-cloud.test");
    expect(text(r)).toContain("Domaine vérifié : atlas-cloud.test. Le remplissage ne marche que sur ce site exact.");
    expect(text(r)).toContain("Atlas Cloud");
    expect(text(r)).toContain("alex@atlas.dev");
    expect(r.querySelector("input[type=search]")!.getAttribute("placeholder")).toBe("Rechercher dans OnePass");
  });

  it("detail with masked password, reveal on click, TOTP countdown, Remplir toast", async () => {
    const { r, handle, w, timers } = setup();
    await handle.ready;
    button(r, "Atlas Cloud").click();
    await handle.settled();
    expect(text(r)).toContain("nom d’utilisateur");
    expect(r.querySelector(".pwd-value")!.textContent).toBe("••••••••••••");
    expect(text(r)).not.toContain("pw-Secret-1");
    expect(text(r)).toContain("703 083");
    expect(r.querySelector(".totp-left")!.textContent).toBe("2 s");
    expect(text(r)).toContain("site web");
    expect(text(r)).toContain("https://atlas-cloud.test");
    timers.tick();
    expect(r.querySelector(".totp-left")!.textContent).toBe("1 s");
    timers.tick();
    await handle.settled();
    expect(w.types().filter((t) => t === "popup_totp")).toHaveLength(2);
    button(r, "Afficher").click();
    await handle.settled();
    expect(w.sent.at(-1)).toEqual({ type: "popup_reveal", itemId: "it_01" });
    expect(r.querySelector(".pwd-value")!.textContent).toBe("pw-Secret-1");
    button(r, "Masquer").click();
    await handle.settled();
    expect(r.querySelector(".pwd-value")!.textContent).toBe("••••••••••••");
    button(r, "Remplir").click();
    await handle.settled();
    expect(w.sent.at(-1)).toEqual({ type: "popup_fill", itemId: "it_01" });
    expect(r.querySelector(".toast")!.textContent).toBe("Rempli sur atlas-cloud.test");
    timers.runTimeouts();
    expect(r.querySelector(".toast")).toBeNull();
  });

  it("a refused fill shows a French sentence", async () => {
    const { r, handle } = setup(worker((m) => (m.type === "popup_fill" ? { err: "no_form" } : null)));
    await handle.ready;
    button(r, "Atlas Cloud").click();
    await handle.settled();
    button(r, "Remplir").click();
    await handle.settled();
    expect(r.querySelector(".toast")!.textContent).toBe("Aucun formulaire à remplir sur cette page.");
  });

  it("TOTP refresh does not stack while a request is in flight", async () => {
    let release: (() => void) | null = null;
    let calls = 0;
    const w = worker((m) => {
      if (m.type !== "popup_totp") return null;
      calls++;
      return null;
    });
    const base = w.answer;
    w.answer = (m) => {
      if (m.type === "popup_totp" && calls >= 1) {
        calls++;
        return new Promise((res) => (release = () => res({ ok: { code: "111222", remaining: 30 } })));
      }
      return base(m);
    };
    const { r, handle, timers } = setup(w);
    await handle.ready;
    button(r, "Atlas Cloud").click();
    await handle.settled();
    expect(calls).toBe(1);
    // remaining 2: two ticks reach 0 and start one refresh; more ticks while it hangs add nothing.
    timers.tick();
    timers.tick();
    timers.tick();
    timers.tick();
    await new Promise((res) => setTimeout(res, 0));
    expect(w.types().filter((t) => t === "popup_totp")).toHaveLength(2);
    release!();
    await new Promise((res) => setTimeout(res, 0));
    expect(text(r)).toContain("111 222");
    expect(r.querySelector(".totp-left")!.textContent).toBe("30 s");
  });

  it("search shows only the latest query's result", async () => {
    const releases: Record<string, () => void> = {};
    const w = worker();
    const base = w.answer;
    w.answer = (m) =>
      m.type === "popup_search"
        ? new Promise((res) => {
            releases[m.query] = () => res({ ok: { items: [login(`it_${m.query}`, { title: `Résultat ${m.query}` })] } });
          })
        : base(m);
    const { r, handle, timers } = setup(w);
    await handle.ready;
    const input = r.querySelector<HTMLInputElement>("input[type=search]")!;
    for (const q of ["gi", "git"]) {
      input.value = q;
      input.dispatchEvent(new Event("input"));
      timers.runTimeouts();
    }
    await new Promise((res) => setTimeout(res, 0));
    releases.git!();
    await new Promise((res) => setTimeout(res, 0));
    releases.gi!();
    await new Promise((res) => setTimeout(res, 0));
    expect(text(r)).toContain("Résultat git");
    expect(text(r)).not.toContain("Résultat gi ");
    expect([...r.querySelectorAll(".pp-list .t1")].map((e) => e.textContent)).toEqual(["Résultat git"]);
  });

  it("search", async () => {
    const { r, handle, w, timers } = setup();
    await handle.ready;
    const input = r.querySelector<HTMLInputElement>("input[type=search]")!;
    input.value = "git";
    input.dispatchEvent(new Event("input"));
    timers.runTimeouts();
    await handle.settled();
    expect(w.sent.at(-1)).toEqual({ type: "popup_search", query: "git" });
    expect(text(r)).toContain("Résultats");
    expect(text(r)).toContain("GitHub (Atlas)");
    input.value = "";
    input.dispatchEvent(new Event("input"));
    timers.runTimeouts();
    await handle.settled();
    expect(text(r)).toContain("Suggestions pour atlas-cloud.test");
  });

  it("generator: types, length, copy, fill, history", async () => {
    const { r, handle, w, copied } = setup();
    await handle.ready;
    r.querySelector<HTMLButtonElement>("button[aria-label='Générateur de mot de passe']")!.click();
    await handle.settled();
    expect(w.sent.at(-1)).toEqual({ type: "popup_generate", kind: "smart" });
    expect(text(r)).toContain("Générateur de mot de passe");
    expect(r.querySelector(".gen-out")!.textContent).toBe("abcd7e.XYZ.wxyz4kq");
    const select = r.querySelector<HTMLSelectElement>("select[aria-label='Type de mot de passe']")!;
    expect([...select.options].map((o) => [o.value, o.textContent])).toEqual(GENERATOR_TYPES.map((t) => [t.kind, t.label]));
    expect([...select.options].map((o) => o.textContent)).toEqual(["Intelligent", "Aléatoire", "Mémorisable", "Code PIN"]);
    select.value = "random";
    select.dispatchEvent(new Event("change"));
    await handle.settled();
    expect(w.sent.at(-1)).toEqual({ type: "popup_generate", kind: "random", length: 20, symbols: true });
    const range = r.querySelector<HTMLInputElement>("input[type=range]")!;
    range.value = "32";
    range.dispatchEvent(new Event("change"));
    await handle.settled();
    expect(w.sent.at(-1)).toEqual({ type: "popup_generate", kind: "random", length: 32, symbols: true });
    const sel2 = r.querySelector<HTMLSelectElement>("select[aria-label='Type de mot de passe']")!;
    sel2.value = "pin";
    sel2.dispatchEvent(new Event("change"));
    await handle.settled();
    expect(w.sent.at(-1)).toEqual({ type: "popup_generate", kind: "pin" });
    expect(r.querySelector("input[type=range]")).toBeNull();
    button(r, "Copier").click();
    await handle.settled();
    expect(copied).toEqual(["482913"]);
    button(r, "Remplir").click();
    await handle.settled();
    expect(w.sent.at(-1)).toEqual({ type: "popup_fill_generated", password: "482913" });
    expect(r.querySelector(".toast")!.textContent).toBe("Rempli sur atlas-cloud.test");
    button(r, "Historique du générateur").click();
    await handle.settled();
    expect(w.sent.at(-1)).toEqual({ type: "popup_history" });
    expect(text(r)).toContain("old-Pass-1");
  });

  it("locked during use falls back to the locked view", async () => {
    const { r, handle } = setup(worker((m) => (m.type === "popup_item" ? { err: "locked" } : null)));
    await handle.ready;
    button(r, "Atlas Cloud").click();
    await handle.settled();
    expect(text(r)).toContain("OnePass est verrouillé");
  });

  it("renders data as text only", async () => {
    const w = worker((m) =>
      m.type === "popup_suggestions"
        ? { ok: { domain: "atlas-cloud.test", items: [login("it_x", { title: "<img src=x onerror=alert(1)>" })] } }
        : null,
    );
    const { r, handle } = setup(w);
    await handle.ready;
    expect(r.querySelector("img")).toBeNull();
    expect(text(r)).toContain("<img src=x onerror=alert(1)>");
  });
});
