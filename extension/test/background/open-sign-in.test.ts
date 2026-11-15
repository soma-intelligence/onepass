// @vitest-environment node
// Open and sign in (open-sign-in.ts): the service worker asks the host for the pending sign-in only
// on a top https sign-in page, once per document, and starts the chain on the item it gets.
import { describe, expect, it, vi } from "vitest";
import { OpenSignIn, type OpenSignInDeps } from "../../src/background/open-sign-in";
import type { FormInfo, PageAnalysis } from "../../src/shared/messages";
import { loadVector } from "../bridge/vectors";

interface SignInVector {
  item_id: string;
  request: { id: number; op: string; origin: string; top_origin: string };
  reply_some: { id: number; ok: { item_id: string | null } };
  reply_none: { id: number; ok: { item_id: string | null } };
}

const V = loadVector<SignInVector>("sign_in");
const ORIGIN = V.request.origin;
const ITEM = V.item_id;

const signInForm: FormInfo = {
  ref: "f1",
  kind: "login",
  fields: [{ ref: "e1", role: "email" }],
} as unknown as FormInfo;

function analysis(forms: FormInfo[] = [signInForm]): PageAnalysis {
  return { url: `${ORIGIN}/signin`, forms, captcha: false, push: false, providerButtons: [], accountChooser: [] };
}

function deps(over: Partial<OpenSignInDeps> & { pending?: string | null; locked?: boolean } = {}) {
  let pending: string | null = over.pending === undefined ? ITEM : over.pending;
  const calls: Record<string, unknown>[] = [];
  const request = vi.fn(async (req: Record<string, unknown>) => {
    calls.push(req);
    if (req.op === "take_sign_in") {
      const out = { item_id: pending };
      pending = null;
      return out;
    }
    if (req.op === "status") return { locked: over.locked ?? false, account: "", vaults: 1 };
    throw new Error(`unexpected ${String(req.op)}`);
  });
  const start = vi.fn(async () => undefined);
  const d: OpenSignInDeps = {
    session: { request } as unknown as OpenSignInDeps["session"],
    chain: { start },
    chainRunning: over.chainRunning ?? (async () => false),
    frames: over.frames ?? { frameOrigin: async () => ORIGIN },
    unlock: over.unlock ?? (async () => true),
  };
  return { d, calls, start, request };
}

const top = { tabId: 4, frameId: 0, origin: ORIGIN, documentId: "doc-1" };

describe("OpenSignIn", () => {
  it("takes the pending item on a top sign-in page and starts the chain", async () => {
    const { d, calls, start } = deps();
    expect(await new OpenSignIn(d).onAnalysis(analysis(), top)).toBe(ITEM);
    // The request is the vector's, without the id the client assigns.
    const { id: _id, ...want } = V.request;
    expect(calls[0]).toEqual(want);
    expect(start).toHaveBeenCalledWith(4, ITEM);
  });

  it("asks once per document", async () => {
    const { d, calls } = deps({ pending: null });
    const o = new OpenSignIn(d);
    await o.onAnalysis(analysis(), top);
    await o.onAnalysis(analysis(), top);
    expect(calls.filter((c) => c.op === "take_sign_in")).toHaveLength(1);
    await o.onAnalysis(analysis(), { ...top, documentId: "doc-2" });
    expect(calls.filter((c) => c.op === "take_sign_in")).toHaveLength(2);
  });

  it("nothing pending: no chain", async () => {
    const { d, start } = deps({ pending: null });
    expect(await new OpenSignIn(d).onAnalysis(analysis(), top)).toBeNull();
    expect(start).not.toHaveBeenCalled();
  });

  it("never asks from a frame, an http page or a page without a sign-in form", async () => {
    const { d, request } = deps();
    const o = new OpenSignIn(d);
    expect(await o.onAnalysis(analysis(), { ...top, frameId: 3 })).toBeNull();
    expect(await o.onAnalysis(analysis(), { ...top, origin: "http://www.atlas-cloud.test", documentId: "h" })).toBeNull();
    expect(await o.onAnalysis(analysis([]), { ...top, documentId: "empty" })).toBeNull();
    expect(request).not.toHaveBeenCalled();
  });

  it("the tab's top document moved: nothing asked", async () => {
    const { d, request } = deps({ frames: { frameOrigin: async () => "https://evil.test" } });
    expect(await new OpenSignIn(d).onAnalysis(analysis(), top)).toBeNull();
    expect(request).not.toHaveBeenCalled();
  });

  it("a running chain is left alone", async () => {
    const { d, request } = deps({ chainRunning: async () => true });
    expect(await new OpenSignIn(d).onAnalysis(analysis(), top)).toBeNull();
    expect(request).not.toHaveBeenCalled();
  });

  it("locked: unlocks first, and stops when the unlock fails", async () => {
    const ok = deps({ locked: true });
    expect(await new OpenSignIn(ok.d).onAnalysis(analysis(), top)).toBe(ITEM);
    const unlock = vi.fn(async () => false);
    const no = deps({ locked: true, unlock });
    expect(await new OpenSignIn(no.d).onAnalysis(analysis(), top)).toBeNull();
    expect(unlock).toHaveBeenCalledOnce();
    expect(no.start).not.toHaveBeenCalled();
  });

  it("an older host answering invalid is nothing", async () => {
    const { d, start, request } = deps();
    request.mockImplementationOnce(async () => {
      throw new Error("invalid");
    });
    expect(await new OpenSignIn(d).onAnalysis(analysis(), top)).toBeNull();
    expect(start).not.toHaveBeenCalled();
  });

  it("the vector replies have the shape the client types", () => {
    expect(V.reply_some.ok.item_id).toBe(ITEM);
    expect(V.reply_none.ok.item_id).toBeNull();
  });
});
