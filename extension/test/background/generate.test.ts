import { afterEach, describe, expect, it, vi } from "vitest";
import type { GenerationReport } from "../../src/bridge/client";
import type { FillTarget } from "../../src/background/fill";
import { FormGenerator, PATTERN_CHECK_MS, parsePasswordContextReply } from "../../src/background/generate";
import { patternMatches } from "../../src/content/password-context";
import { GENERATOR_PROFILE_KEY } from "../../src/shared/ui";
import { FakeExt } from "./fake-ext";

const SITE = "https://atlas-cloud.test";
const target: FillTarget = { tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1", formRef: "f1" };

const report = (over: Partial<GenerationReport> = {}): GenerationReport => ({
  length: 20,
  lower: true,
  upper: true,
  digit: true,
  special: true,
  sources: ["attributes"],
  dropped: [],
  fallback: false,
  readable_fell_back: false,
  weak_by_site: false,
  entropy_bits: 110,
  ...over,
});

/**
 * A content script replying `reply` to `password_context` and checking candidates against
 * `pattern` (as the page's tab does), and a host answering `passwords` by `narrow`.
 */
function setup(reply: unknown, passwords: string[], pattern: string | null = null) {
  const ext = new FakeExt();
  ext.tabReply = (_tab, m) => {
    const msg = m as { type?: string; candidate?: string };
    if (msg.type === "password_context") return reply;
    if (msg.type === "pattern_check") return { ok: true, matches: patternMatches(pattern, msg.candidate ?? "") };
    return undefined;
  };
  const requests: Record<string, unknown>[] = [];
  const session = {
    request: async (r: Record<string, unknown>) => {
      requests.push(r);
      const narrow = ((r.recipe as { narrow?: number }).narrow ?? 0) as number;
      return { password: passwords[narrow] as string, entropy_bits: 90, report: report() };
    },
  };
  const gen = new FormGenerator({ tabs: ext.tabs, session: session as never, area: ext.local });
  return { ext, requests, gen };
}

const CONTEXT = { rules: ["minlength: 8;"], max_length: 20 };

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("generateForForm", () => {
  it("asks the pinned document, then the host with the context and origin", async () => {
    const { ext, requests, gen } = setup({ ok: true, context: CONTEXT, has_pattern: false }, ["Abc-def!12"]);
    const r = await gen.generateForForm(target, "menu");
    expect(r?.password).toBe("Abc-def!12");
    expect(r?.report).toEqual(report());
    expect(ext.sentToTabs).toEqual([
      { tabId: 7, message: { type: "password_context", origin: SITE, formRef: "f1" }, options: { documentId: "doc-1" } },
    ]);
    expect(requests).toEqual([{ op: "generate", ctx: "menu", origin: SITE, recipe: { kind: "smart", profile: "strong", context: CONTEXT } }]);
  });

  it("retries_without_symbols_on_pattern_miss", async () => {
    const { ext, requests, gen } = setup({ ok: true, context: CONTEXT, has_pattern: true }, ["Abc-def!12", "Abcdef1234", "abcdef1234"], "[A-Za-z0-9]+");
    const r = await gen.generateForForm(target, "menu");
    expect(r?.password).toBe("Abcdef1234");
    expect(requests.map((x) => (x.recipe as { narrow?: number }).narrow)).toEqual([undefined, 1]);
    // Each candidate went to the pinned document, which answered for its own pattern.
    expect(ext.sentToTabs.slice(1)).toEqual([
      { tabId: 7, message: { type: "pattern_check", origin: SITE, formRef: "f1", candidate: "Abc-def!12" }, options: { documentId: "doc-1" } },
      { tabId: 7, message: { type: "pattern_check", origin: SITE, formRef: "f1", candidate: "Abcdef1234" }, options: { documentId: "doc-1" } },
    ]);
  });

  it("gives_up_after_three", async () => {
    const { requests, gen } = setup({ ok: true, context: CONTEXT, has_pattern: true }, ["Abc-def!12", "Abcdef1234", "abcdef1234"], "[0-9]{6}");
    expect(await gen.generateForForm(target, "menu")).toBeNull();
    expect(requests.map((x) => (x.recipe as { narrow?: number }).narrow)).toEqual([undefined, 1, 2]);
  });

  it("invalid_pattern_ignored", async () => {
    // The tab cannot compile it: it accepts.
    const { requests, gen } = setup({ ok: true, context: CONTEXT, has_pattern: true }, ["Abc-def!12"], "(");
    expect((await gen.generateForForm(target, "menu"))?.password).toBe("Abc-def!12");
    expect(requests).toHaveLength(1);
  });

  it("no pattern: no check sent", async () => {
    const { ext, gen } = setup({ ok: true, context: CONTEXT, has_pattern: false }, ["Abc-def!12"], "[0-9]{6}");
    expect((await gen.generateForForm(target, "menu"))?.password).toBe("Abc-def!12");
    expect(ext.sentToTabs.map((x) => (x.message as { type: string }).type)).toEqual(["password_context"]);
  });

  it("a tab that never answers the check: the first candidate after the timeout", async () => {
    vi.useFakeTimers();
    const { ext, requests, gen } = setup({ ok: true, context: CONTEXT, has_pattern: true }, ["Abc-def!12", "Abcdef1234"]);
    // A page whose pattern hangs its own tab: the worker waits for nothing more.
    ext.tabReply = (_t, m) =>
      (m as { type?: string }).type === "password_context" ? { ok: true, context: CONTEXT, has_pattern: true } : new Promise(() => undefined);
    const ctor = vi.spyOn(globalThis, "RegExp");
    const p = gen.generateForForm(target, "menu");
    await vi.advanceTimersByTimeAsync(PATTERN_CHECK_MS - 1);
    let done = false;
    void p.then(() => (done = true));
    await Promise.resolve();
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect((await p)?.password).toBe("Abc-def!12");
    expect(requests).toHaveLength(1);
    // The worker compiled no page pattern.
    expect(ctor).not.toHaveBeenCalled();
  });

  it("a tab that is gone or answers nonsense counts as a match", async () => {
    for (const answer of [() => Promise.reject(new Error("closed")), () => ({ ok: false }), () => undefined, () => ({ ok: true })]) {
      const { ext, requests, gen } = setup({ ok: true, context: CONTEXT, has_pattern: true }, ["Abc-def!12"]);
      ext.tabReply = (_t, m) => ((m as { type?: string }).type === "password_context" ? { ok: true, context: CONTEXT, has_pattern: true } : answer());
      expect((await gen.generateForForm(target, "menu"))?.password).toBe("Abc-def!12");
      expect(requests).toHaveLength(1);
    }
  });

  it("profile_from_storage", async () => {
    const { ext, requests, gen } = setup({ ok: true, context: CONTEXT, has_pattern: false }, ["pw"]);
    const profileOf = () => {
      const recipe = requests.at(-1)?.recipe as Record<string, unknown>;
      const { context: _c, ...rest } = recipe;
      return rest;
    };
    await gen.generateForForm(target, "menu");
    expect(profileOf()).toEqual({ kind: "smart", profile: "strong" });
    await ext.local.set({ [GENERATOR_PROFILE_KEY]: "readable" });
    await gen.generateForForm(target, "menu");
    expect(profileOf()).toEqual({ kind: "smart", profile: "readable" });
    await ext.local.set({ [GENERATOR_PROFILE_KEY]: { kind: "custom", length: 30, symbols: false } });
    await gen.generateForForm(target, "menu");
    expect(profileOf()).toEqual({ kind: "smart", profile: "custom", length: 30, symbols: false });
    // Anything else stored: Strong.
    for (const bad of ["fort", { kind: "custom", length: 4, symbols: true }, { kind: "custom", length: 20 }, 3]) {
      await ext.local.set({ [GENERATOR_PROFILE_KEY]: bad });
      await gen.generateForForm(target, "menu");
      expect(profileOf()).toEqual({ kind: "smart", profile: "strong" });
    }
  });

  it("a frame that does not answer: the host without context", async () => {
    const { ext, requests, gen } = setup(undefined, ["pw"]);
    ext.tabReply = () => {
      throw new Error("no receiving end");
    };
    expect((await gen.generateForForm(target, "menu"))?.password).toBe("pw");
    expect(requests).toEqual([{ op: "generate", ctx: "menu", origin: SITE, recipe: { kind: "smart", profile: "strong" } }]);
  });

  it("without a form: the profile, the origin, no context", async () => {
    const { ext, requests, gen } = setup(undefined, ["pw"]);
    await ext.local.set({ [GENERATOR_PROFILE_KEY]: "readable" });
    expect((await gen.generate("save_prompt", SITE)).password).toBe("pw");
    expect(ext.sentToTabs).toEqual([]);
    expect(requests).toEqual([{ op: "generate", ctx: "save_prompt", origin: SITE, recipe: { kind: "smart", profile: "readable" } }]);
  });
});

describe("parsePasswordContextReply", () => {
  it("bounds what the content script replied", () => {
    const rules = ["a".repeat(1025), "€".repeat(342), ...Array.from({ length: 10 }, (_, i) => `r${i};`), 5];
    const r = parsePasswordContextReply({
      ok: true,
      context: { rules, min_length: 0, max_length: 1.5, hint_text: "h".repeat(700), extra: "x" },
      // A pattern the content script would never send: dropped, never kept by the worker.
      pattern: "(.*)*!",
      has_pattern: "yes",
    });
    expect(r).toEqual({ context: { rules: ["r0;", "r1;", "r2;", "r3;", "r4;", "r5;", "r6;", "r7;"], hint_text: "h".repeat(600) }, hasPattern: false });
    expect(parsePasswordContextReply({ ok: false })).toBeNull();
    expect(parsePasswordContextReply("x")).toBeNull();
    expect(parsePasswordContextReply({ ok: true, context: { rules: [], min_length: 8, max_length: 64 }, has_pattern: true })).toEqual({
      context: { rules: [], min_length: 8, max_length: 64 },
      hasPattern: true,
    });
  });
});
