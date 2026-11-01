import { describe, expect, it } from "vitest";
import type { PasskeyInit, UiToBg } from "../../src/shared/messages";
import { mountPasskey } from "../../src/ui/passkey";
import { Clock, FakeVisibility, FakeWorker, HASH, type Reply, TOKEN, button, flush, root, text } from "./helpers";

const ORIGIN = "https://login.atlas-cloud.test";
const GET_INIT: PasskeyInit = {
  kind: "get",
  origin: ORIGIN,
  rpId: "atlas-cloud.test",
  accounts: [
    { itemId: "i1", credentialId: "q83vEjRWeJA", title: "Atlas Cloud", userName: "alex@atlas.dev", vaultName: "Personnel" },
    { itemId: "i2", credentialId: "AAECAwQFBgc", title: "Atlas Admin", userName: "ops@atlas.dev", vaultName: "Travail" },
  ],
};
const CREATE_INIT: PasskeyInit = {
  kind: "create",
  origin: ORIGIN,
  rpId: "atlas-cloud.test",
  accounts: [],
  userName: "alex@atlas.dev",
  vaults: [
    { id: "v1", name: "Personnel" },
    { id: "v2", name: "Travail" },
  ],
};

function setup(init: PasskeyInit | { err: string }, opts: { trusted?: boolean; answer?: (m: UiToBg) => Reply | null } = {}) {
  const r = root();
  const clock = new Clock();
  const vis = new FakeVisibility();
  const worker = new FakeWorker((m) => {
    const x = opts.answer?.(m);
    if (x) return x;
    if (m.type === "passkey_init") return "err" in init ? init : { ok: init };
    return { ok: {} };
  });
  const handle = mountPasskey(r, {
    send: worker.send,
    hash: HASH,
    now: clock.now,
    trusted: () => opts.trusted !== false,
    observe: vis.observe,
  });
  return { r, worker, handle, clock, vis };
}

describe("passkey choice window", () => {
  it("lists the accounts with name and site, and the two ways out", async () => {
    const { r, handle } = setup(GET_INIT);
    await handle.ready;
    const t = text(r);
    expect(t).toContain("atlas-cloud.test");
    expect(t).toContain("alex@atlas.dev");
    expect(t).toContain("Atlas Cloud");
    expect(t).toContain("ops@atlas.dev");
    expect(button(r, "Autre appareil")).toBeTruthy();
    expect(button(r, "Annuler")).toBeTruthy();
  });

  it("signs in with the picked account after the click guard", async () => {
    const { r, handle, worker, clock } = setup(GET_INIT);
    await handle.ready;
    button(r, "ops@atlas.dev").click();
    await flush();
    expect(worker.types()).toEqual(["passkey_init"]);
    clock.advance(300);
    button(r, "ops@atlas.dev").click();
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "passkey_pick", token: TOKEN, itemId: "i2", credentialId: "AAECAwQFBgc" });
  });

  it("ignores untrusted clicks", async () => {
    const { r, handle, worker, clock } = setup(GET_INIT, { trusted: false });
    await handle.ready;
    clock.advance(1000);
    button(r, "alex@atlas.dev").click();
    button(r, "Annuler").click();
    await flush();
    expect(worker.types()).toEqual(["passkey_init"]);
  });

  it("re-arms the guard when the window becomes visible again", async () => {
    const { r, handle, worker, clock, vis } = setup(GET_INIT);
    await handle.ready;
    clock.advance(1000);
    vis.emit({ intersecting: true, visible: false });
    vis.emit({ intersecting: true, visible: true });
    button(r, "alex@atlas.dev").click();
    await flush();
    expect(worker.types()).toEqual(["passkey_init"]);
  });

  it("Annuler and Autre appareil", async () => {
    const { r, handle, worker, clock } = setup(GET_INIT);
    await handle.ready;
    clock.advance(300);
    button(r, "Autre appareil").click();
    await flush();
    button(r, "Annuler").click();
    await flush();
    expect(worker.types()).toEqual(["passkey_init", "passkey_other", "passkey_cancel"]);
  });

  it("shows the host's refusal and stays", async () => {
    const { r, handle, clock } = setup(GET_INIT, { answer: (m) => (m.type === "passkey_pick" ? { err: "reprompt_required" } : null) });
    await handle.ready;
    clock.advance(300);
    button(r, "alex@atlas.dev").click();
    await flush();
    expect(text(r)).toContain("Confirme dans l'app OnePass");
    expect(button(r, "alex@atlas.dev").disabled).toBe(false);
  });

  it("create: names the account and site, saves in the chosen vault", async () => {
    const { r, handle, worker, clock } = setup(CREATE_INIT);
    await handle.ready;
    expect(text(r)).toContain("alex@atlas.dev");
    expect(text(r)).toContain("atlas-cloud.test");
    const sel = r.querySelector("select") as HTMLSelectElement;
    sel.value = "v2";
    sel.dispatchEvent(new Event("change"));
    clock.advance(300);
    button(r, "Enregistrer").click();
    await flush();
    expect(worker.sent.at(-1)).toEqual({ type: "passkey_save", token: TOKEN, vaultId: "v2" });
  });

  it("an invalid token shows a message, no list", async () => {
    const { r, handle } = setup({ err: "invalid" });
    await handle.ready;
    expect(r.querySelectorAll("button.row")).toHaveLength(0);
    expect(text(r)).toContain("Demande refusée");
  });

  it("renders host strings as text, never markup", async () => {
    const { r, handle } = setup({ ...GET_INIT, accounts: [{ ...GET_INIT.accounts[0]!, userName: "<img src=x onerror=alert(1)>" }] });
    await handle.ready;
    expect(r.querySelector("img")).toBeNull();
    expect(text(r)).toContain("<img src=x");
  });
});
