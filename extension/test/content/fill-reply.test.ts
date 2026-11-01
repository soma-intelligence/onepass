// The fill reply waits for the region a country change reloads (bounded),
// and lists the roles actually written (spec 2026-10-31, section 3.3).
import { afterEach, describe, expect, it } from "vitest";
import type { FormInfo, PageAnalysis } from "../../src/shared/messages";
import { REPLY_MAX_MS } from "../../src/content/index";
import { EXT_ID, setPage, start, type Started } from "./harness";

const ORIGIN = "https://atlas-cloud.test";
let s: Started | null = null;
afterEach(() => s?.cs.stop());

function formOf(st: Started): FormInfo {
  const all = st.ext.ofType("page_analysis");
  const f = (all[all.length - 1]!.analysis as PageAnalysis).forms[0];
  if (!f) throw new Error("no form");
  return f;
}

/** Delivers a fill and resolves with the reply, sync or async. */
function fillReply(st: Started, formRef: string, values: Record<string, string>): Promise<unknown> {
  return new Promise<unknown>((resolve) => {
    for (const l of st.ext.listeners) l({ type: "fill", origin: ORIGIN, formRef, values }, { id: EXT_ID }, resolve);
  });
}

const sel = (id: string) => document.getElementById(id) as HTMLSelectElement;

describe("fill reply", () => {
  it("waits for the region a country change reloads, and lists it", async () => {
    setPage(`<form id="f">
      <label for="a1">Address</label><input id="a1" autocomplete="address-line1">
      <label for="c">Country</label><select id="c" autocomplete="country"><option value="US">United States</option><option value="FR">France</option></select>
      <label for="s">State</label><select id="s" autocomplete="address-level1"><option value="">-</option><option value="CA">California</option></select>
      <button type="submit">Save</button></form>`);
    sel("c").addEventListener("change", () => {
      setTimeout(() => (sel("s").innerHTML = `<option value="">-</option><option value="69">69 - Rhône</option>`), 80);
    });
    s = start();
    const reply = (await fillReply(s, formOf(s).ref, { address_line1: "4 rue des Tilleuls", country: "FR", region: "Rhone" })) as { ok: boolean; filled: string[] };
    expect(sel("s").value).toBe("69");
    expect(reply.ok).toBe(true);
    expect([...reply.filled].sort()).toEqual(["address_line1", "country", "region"]);
  });

  it("answers within the bound when the list never comes", async () => {
    setPage(`<form id="f">
      <label for="a1">Address</label><input id="a1" autocomplete="address-line1">
      <label for="c">Country</label><select id="c" autocomplete="country"><option value="US">United States</option><option value="FR">France</option></select>
      <label for="s">State</label><select id="s" autocomplete="address-level1"><option value="">-</option><option value="CA">California</option></select>
      <button type="submit">Save</button></form>`);
    s = start();
    const t0 = Date.now();
    const reply = (await fillReply(s, formOf(s).ref, { address_line1: "1 rue Neuve", country: "FR", region: "Rhone" })) as { ok: boolean; filled: string[] };
    expect(Date.now() - t0).toBeLessThan(REPLY_MAX_MS + 500);
    expect(reply).toEqual({ ok: true, filled: ["address_line1", "country"] });
  }, 10_000);

  it("answers at once when nothing waits", async () => {
    setPage(`<form id="f"><input id="u" autocomplete="username"><input type="password" autocomplete="current-password"><button>Go</button></form>`);
    s = start();
    let out: unknown;
    for (const l of s.ext.listeners) l({ type: "fill", origin: ORIGIN, formRef: formOf(s).ref, values: { username: "alex" } }, { id: EXT_ID }, (x) => (out = x));
    expect(out).toEqual({ ok: true, filled: ["username"] });
  });
});
