import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { LANGS, setLang, t, tn } from "../../src/shared/i18n";
import fr from "../../src/shared/l10n/fr.json";
import en from "../../src/shared/l10n/en.json";
import es from "../../src/shared/l10n/es.json";
import itCat from "../../src/shared/l10n/it.json";
import type { SetupCandidate, SetupCardState, UiToBg } from "../../src/shared/messages";
import { errorText } from "../../src/ui/components";
import { SAVED_CLOSE_MS, mountSetup } from "../../src/ui/setup";
import { mountPopup } from "../../src/ui/popup";
import { Clock, FakeWorker, HASH, ManualTimers, type Reply, TOKEN, button, flush, login, root, text } from "./helpers";

const ALEX: SetupCandidate = { itemId: "it_01", title: "Atlas Cloud", username: "alex@atlas.dev", hasTotp: false, associated: false };
const SAM: SetupCandidate = { itemId: "it_02", title: "Atlas (work)", username: "sam@atlas.dev", hasTotp: false, associated: false };
const DOCS: SetupCandidate = { itemId: "it_03", title: "Atlas Docs", username: "alex@atlas.dev", hasTotp: false, associated: true };

const state = (over: Partial<SetupCardState> = {}): SetupCardState => ({
  mode: "confirm",
  issuer: "Atlas",
  account: "alex@atlas.dev",
  candidates: [ALEX],
  selected: "it_01",
  mismatch: false,
  ...over,
});

const KEY = "JBSW Y3DP EHPK 3PXP JBSW Y3DP";

function setup(init: SetupCardState | { err: string }, extra?: (m: UiToBg) => Reply | null) {
  const r = root();
  const clock = new Clock();
  const timers = new ManualTimers();
  const worker = new FakeWorker((m) => {
    const x = extra?.(m);
    if (x) return x;
    if (m.type === "setup_init") return "err" in init ? init : { ok: init };
    if (m.type === "setup_save") return { ok: { status: "saved" } };
    return { ok: {} };
  });
  const handle = mountSetup(r, { send: worker.send, hash: HASH, now: clock.now, trusted: () => true, observe: () => undefined, timers });
  // Each view change restarts the 300 ms click guard: advance before clicks.
  const click = async (label: string) => {
    clock.advance(300);
    button(r, label).click();
    await flush();
    await flush();
  };
  return { r, worker, handle, click, timers, clock };
}

const focused = () => (document.activeElement?.textContent ?? "").trim();
const saves = (w: FakeWorker) => w.sent.filter((m) => m.type === "setup_save");

beforeEach(() => setLang("en"));
afterEach(() => setLang("fr"));

describe("setup card", () => {
  it("focuses Add with one matching item", async () => {
    const { r, handle, worker, click } = setup(state());
    await handle.ready;
    expect(worker.sent[0]).toEqual({ type: "setup_init", token: TOKEN });
    expect(text(r)).toContain("Add the 2FA code to Atlas Cloud?");
    expect(text(r)).toContain("Atlas, alex@atlas.dev");
    // One item: no list.
    expect(r.querySelector('[role="listbox"]')).toBeNull();
    expect(focused()).toBe("Add");
    await click("Add");
    expect(saves(worker)).toEqual([{ type: "setup_save", token: TOKEN, itemId: "it_01" }]);
    expect(text(r)).toContain("Saved. Press the site's button to confirm.");
  });

  it("focuses Cancel when the account differs", async () => {
    const { r, handle, worker, click } = setup(state({ account: "pat@atlas.dev", mismatch: true }));
    await handle.ready;
    expect(text(r)).toContain("The code is for pat@atlas.dev. This login is alex@atlas.dev.");
    expect(focused()).toBe("Cancel");
    await click("Cancel");
    expect(worker.sent.at(-1)).toEqual({ type: "setup_close", token: TOKEN });
    expect(saves(worker)).toEqual([]);
  });

  it("asks to replace with Cancel focused, and sends replace only on the Replace click", async () => {
    let n = 0;
    const { r, handle, worker, click } = setup(state({ candidates: [{ ...ALEX, hasTotp: true }] }), (m) =>
      m.type === "setup_save" ? { ok: { status: n++ === 0 ? "exists" : "replaced" } } : null,
    );
    await handle.ready;
    await click("Add");
    expect(text(r)).toContain("Atlas Cloud already has a 2FA code. Replace it?");
    expect(text(r)).toContain("The old code stays on the login.");
    expect(focused()).toBe("Cancel");
    expect(saves(worker)).toEqual([{ type: "setup_save", token: TOKEN, itemId: "it_01" }]);
    await click("Replace");
    expect(saves(worker).at(-1)).toEqual({ type: "setup_save", token: TOKEN, itemId: "it_01", replace: true });
    expect(text(r)).toContain("Saved. Press the site's button to confirm.");
  });

  it("shows the list with several items and New login last", async () => {
    const { r, handle, worker, click } = setup(state({ candidates: [ALEX, SAM, DOCS] }));
    await handle.ready;
    const options = [...r.querySelectorAll('[role="option"]')];
    expect(options.map((o) => o.querySelector(".t1")?.textContent)).toEqual(["Atlas Cloud", "Atlas (work)", "Atlas Docs", "New login"]);
    expect(options[0]!.getAttribute("aria-selected")).toBe("true");
    // Another item: the mismatch is computed again for it, Cancel then leads.
    await click("Atlas (work)");
    expect(text(r)).toContain("The code is for alex@atlas.dev. This login is sam@atlas.dev.");
    expect(focused()).toBe("Cancel");
    // New login: an editable username, prefilled with the QR account; Add waits for one.
    await click("New login");
    const field = r.querySelector<HTMLInputElement>("input.sc-identifier")!;
    expect(field.value).toBe("alex@atlas.dev");
    field.value = "  ";
    field.dispatchEvent(new Event("input"));
    expect(button(r, "Add").disabled).toBe(true);
    field.value = "alex.2fa@atlas.dev";
    field.dispatchEvent(new Event("input"));
    expect(button(r, "Add").disabled).toBe(false);
    await click("Add");
    expect(saves(worker)).toEqual([{ type: "setup_save", token: TOKEN, itemId: null, username: "alex.2fa@atlas.dev" }]);
  });

  it("shows the paste field in paste mode and refuses a non-base32 key", async () => {
    const { r, handle, worker, click } = setup(state({ mode: "paste", issuer: "atlas-cloud.test", account: "", selected: "it_01" }), (m) =>
      m.type === "setup_paste" ? { ok: state({ issuer: "atlas-cloud.test", account: "alex@atlas.dev" }) } : null,
    );
    await handle.ready;
    expect(text(r)).toContain("No QR code found. Paste the setup key.");
    const field = r.querySelector<HTMLInputElement>("input.sc-key")!;
    expect(field.getAttribute("autocomplete")).toBe("off");
    expect(button(r, "Add").disabled).toBe(true);
    field.value = "not a key 1890!";
    field.dispatchEvent(new Event("input"));
    expect(button(r, "Add").disabled).toBe(true);
    field.value = KEY;
    field.dispatchEvent(new Event("input"));
    expect(button(r, "Add").disabled).toBe(false);
    await click("Add");
    expect(worker.sent.filter((m) => m.type === "setup_paste")).toEqual([{ type: "setup_paste", token: TOKEN, key: KEY }]);
    // The key is gone from the page; the confirmation follows.
    expect(r.querySelector("input.sc-key")).toBeNull();
    expect(text(r)).toContain("Add the 2FA code to Atlas Cloud?");
    expect(saves(worker)).toEqual([]);
  });

  it("shows the code and its countdown when the answer carries one", async () => {
    const { r, handle, click, timers } = setup(state(), (m) => (m.type === "setup_save" ? { ok: { status: "saved", code: "123456", remaining: 20 } } : null));
    await handle.ready;
    await click("Add");
    expect(text(r)).toContain("Your code");
    expect(r.querySelector(".sc-code")?.textContent).toBe("123456");
    expect(r.querySelector(".sc-count")?.textContent).toBe("20");
    timers.tick();
    expect(r.querySelector(".sc-count")?.textContent).toBe("19");
  });

  it("shows Unlock on locked and retries on click", async () => {
    let n = 0;
    const { r, handle, worker, click } = setup(state(), (m) => (m.type === "setup_save" ? { ok: { status: n++ === 0 ? "locked" : "saved" } } : null));
    await handle.ready;
    await click("Add");
    expect(button(r, "Unlock Kelid")).toBeTruthy();
    await click("Unlock Kelid");
    expect(saves(worker)).toEqual([
      { type: "setup_save", token: TOKEN, itemId: "it_01" },
      { type: "setup_save", token: TOKEN, itemId: "it_01" },
    ]);
    expect(text(r)).toContain("Saved. Press the site's button to confirm.");
  });

  it("keeps replace through an unlock: Replace, locked, Unlock sends replace again", async () => {
    const answers = ["exists", "locked", "replaced"];
    const { r, handle, worker, click } = setup(state({ candidates: [{ ...ALEX, hasTotp: true }] }), (m) =>
      m.type === "setup_save" ? { ok: { status: answers.shift() ?? "saved" } } : null,
    );
    await handle.ready;
    await click("Add");
    await click("Replace");
    expect(button(r, "Unlock Kelid")).toBeTruthy();
    await click("Unlock Kelid");
    expect(saves(worker)).toEqual([
      { type: "setup_save", token: TOKEN, itemId: "it_01" },
      { type: "setup_save", token: TOKEN, itemId: "it_01", replace: true },
      { type: "setup_save", token: TOKEN, itemId: "it_01", replace: true },
    ]);
    expect(text(r)).toContain("Saved. Press the site's button to confirm.");
  });

  it("keeps replace through an unlock when the bridge error is locked", async () => {
    let n = 0;
    const { r, handle, worker, click } = setup(state({ candidates: [{ ...ALEX, hasTotp: true }] }), (m) => {
      if (m.type !== "setup_save") return null;
      n++;
      if (n === 1) return { ok: { status: "exists" } };
      if (n === 2) return { err: "locked" };
      return { ok: { status: "replaced" } };
    });
    await handle.ready;
    await click("Add");
    await click("Replace");
    await click("Unlock Kelid");
    expect(saves(worker).slice(1)).toEqual([
      { type: "setup_save", token: TOKEN, itemId: "it_01", replace: true },
      { type: "setup_save", token: TOKEN, itemId: "it_01", replace: true },
    ]);
    expect(text(r)).toContain("Saved. Press the site's button to confirm.");
  });

  it("focuses the first login when several are listed and none is selected", async () => {
    const { r, handle } = setup(state({ candidates: [ALEX, SAM], selected: null, account: "" }));
    await handle.ready;
    expect(button(r, "Add").disabled).toBe(true);
    const first = r.querySelector('[role="option"]');
    expect(first?.querySelector(".t1")?.textContent).toBe("Atlas Cloud");
    expect(document.activeElement).toBe(first);
  });

  it("shows Unlock when the vault locked before the card opened, and asks again on click", async () => {
    let locked = true;
    const { r, handle, worker, click } = setup(state(), (m) => (m.type === "setup_init" && locked ? { err: "locked" } : null));
    await handle.ready;
    expect(button(r, "Unlock Kelid")).toBeTruthy();
    locked = false;
    await click("Unlock Kelid");
    expect(worker.sent.filter((m) => m.type === "setup_init")).toHaveLength(2);
    expect(text(r)).toContain("Add the 2FA code to Atlas Cloud?");
  });

  it("closes on Escape and SAVED_CLOSE_MS after Saved", async () => {
    const a = setup(state());
    await a.handle.ready;
    a.clock.advance(300);
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    await flush();
    expect(a.worker.sent.at(-1)).toEqual({ type: "setup_close", token: TOKEN });

    const b = setup(state());
    await b.handle.ready;
    await b.click("Add");
    expect(SAVED_CLOSE_MS).toBe(8000);
    expect(b.worker.sent.at(-1)?.type).toBe("setup_save");
    b.timers.runTimeouts();
    await flush();
    expect(b.worker.sent.at(-1)).toEqual({ type: "setup_close", token: TOKEN });
  });

  it("asks to save the recovery codes on the login", async () => {
    const { r, handle, worker, click } = setup(state({ mode: "codes", issuer: "atlas-cloud.test", account: "", codeCount: 10 }), (m) =>
      m.type === "setup_codes_save" ? { ok: { status: "saved" } } : null,
    );
    await handle.ready;
    expect(text(r)).toContain("Save 10 recovery codes on Atlas Cloud?");
    await click("Save");
    expect(worker.sent.filter((m) => m.type === "setup_codes_save")).toEqual([{ type: "setup_codes_save", token: TOKEN }]);
  });

  it("says why a write was refused, from the worker's reason", async () => {
    const cases: [string, string][] = [
      ["origin_mismatch", errorText("origin_mismatch")],
      ["reprompt_required", errorText("reprompt_required")],
      ["rate_limited", errorText("rate_limited")],
      ["invalid", errorText("invalid")],
    ];
    for (const [reason, sentence] of cases) {
      const { r, handle, click } = setup(state(), (m) => (m.type === "setup_save" ? { ok: { status: "refused", reason } } : null));
      await handle.ready;
      await click("Add");
      expect(text(r)).toContain(sentence);
    }
    // The codes card too.
    const codes = setup(state({ mode: "codes", codeCount: 6 }), (m) =>
      m.type === "setup_codes_save" ? { ok: { status: "refused", reason: "reprompt_required" } } : null,
    );
    await codes.handle.ready;
    await codes.click("Save");
    expect(text(codes.r)).toContain(errorText("reprompt_required"));
  });

  it("fails closed on a refusal reason it does not know", async () => {
    for (const reply of [{ status: "refused", reason: "page_said_so" }, { status: "refused" }, { status: "saved", reason: "invalid" }]) {
      const { r, handle, click } = setup(state(), (m) => (m.type === "setup_save" ? { ok: reply } : null));
      await handle.ready;
      await click("Add");
      expect(text(r)).toContain(errorText("internal"));
      expect(text(r)).not.toContain("page_said_so");
    }
  });

  it("renders page text as text only", async () => {
    const evil = '<img src=x onerror="window.__pwned=1">';
    const { r, handle } = setup(state({ issuer: evil, account: evil, candidates: [{ ...ALEX, title: evil }, { ...SAM, username: evil }] }));
    await handle.ready;
    expect(r.querySelector("img")).toBeNull();
    expect(document.querySelector("img")).toBeNull();
    expect(text(r)).toContain(evil);
    expect((window as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("renders every setup.* key in the four languages", async () => {
    const catalogs = { fr, en, es, it: itCat } as Record<string, Record<string, unknown>>;
    const keys = Object.keys(en).filter((k) => k.startsWith("setup.") || k.startsWith("popup.scanQr"));
    expect(keys).toEqual(expect.arrayContaining(["setup.title", "setup.codesTitle", "setup.recoveryLabel", "setup.previousCode", "popup.scanQr"]));
    for (const l of LANGS) {
      for (const k of keys) {
        const v = catalogs[l]![k];
        expect(v, `${l} ${k}`).toBeDefined();
        expect(JSON.stringify(v), `${l} ${k}`).not.toContain(String.fromCharCode(0x2014));
      }
      setLang(l);
      const { r, handle } = setup(state({ candidates: [ALEX, SAM] }));
      await handle.ready;
      expect(text(r)).toContain(t("setup.title", { item: "Atlas Cloud" }));
      expect(text(r)).toContain(t("setup.newLogin"));
      expect(text(r)).toContain(t("setup.cancel"));
      expect(text(r)).toContain(t("setup.add"));
      expect(tn("setup.codesTitle", 2, { item: "X" })).toContain("2");
    }
  });
});

describe("popup scan button", () => {
  function popup(answer: Reply) {
    const w = new FakeWorker((m) => {
      switch (m.type) {
        case "popup_status":
          return { ok: { locked: false, account: "alex@atlas.dev", vaults: 1 } };
        case "popup_suggestions":
          return { ok: { domain: "atlas-cloud.test", items: [login("it_01")] } };
        case "popup_scan_qr":
          return answer;
        default:
          return { ok: {} };
      }
    });
    const r = root();
    let closed = 0;
    const handle = mountPopup(r, { send: w.send, timers: new ManualTimers(), close: () => void closed++ });
    return { r, w, handle, closed: () => closed };
  }

  it("closes the popup once the card shows", async () => {
    const p = popup({ ok: { status: "card" } });
    await p.handle.ready;
    button(p.r, "Scan 2FA QR code").click();
    await p.handle.settled();
    expect(p.w.sent.filter((m) => m.type === "popup_scan_qr")).toHaveLength(1);
    expect(p.closed()).toBe(1);
  });

  it("closes the popup when nothing was read: the paste card is in the page", async () => {
    const p = popup({ ok: { status: "none" } });
    await p.handle.ready;
    button(p.r, "Scan 2FA QR code").click();
    await p.handle.settled();
    expect(p.closed()).toBe(1);
  });

  it("is not offered while the vault is locked", async () => {
    const w = new FakeWorker((m) => (m.type === "popup_status" ? { ok: { locked: true, account: "alex@atlas.dev", vaults: 1 } } : { ok: { locked: true } }));
    const r = root();
    const handle = mountPopup(r, { send: w.send, timers: new ManualTimers() });
    await handle.ready;
    expect(text(r)).not.toContain("Scan 2FA QR code");
  });
});
