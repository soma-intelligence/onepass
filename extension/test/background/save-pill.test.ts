// The save card folds into a pill (spec 4.2): the record outlives the card for PILL_TTL_MS,
// survives navigation inside the site, and goes when the tab leaves its registrable domain.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PILL_TTL_MS, SAVE_TTL_MS, SavePrompts } from "../../src/background/save";
import { FakeExt } from "./fake-ext";

const SITE = "https://atlas-cloud.test";
const TAB = 7;
const UI = { page: "save.html", tabId: TAB };

function setup() {
  const ext = new FakeExt();
  const requests: { op: string }[] = [];
  const prompts = new SavePrompts({
    ext: ext as never,
    session: {
      request: (async (r: { op: string }) => {
        requests.push(r);
        if (r.op === "vaults") return { vaults: [{ id: "v1", name: "Perso", color: null }] };
        if (r.op === "save_login") return { item_id: "it_new" };
        return {};
      }) as never,
    },
    generator: { generate: async () => ({ password: "unused" }) } as never,
    neverSave: { has: async () => false, add: async () => undefined, list: async () => [], remove: async () => undefined } as never,
  });
  prompts.tokens.install(ext);
  ext.setFrame(TAB, 0, `${SITE}/home`, "doc-2");
  const open = async (status: "new" | "update" = "update") =>
    prompts.open({
      tabId: TAB,
      origin: SITE,
      documentId: "doc-2",
      kind: "login",
      status,
      username: "alex@atlas.dev",
      password: "Atlas-Pass-1",
      ...(status === "update" ? { update: { itemId: "it_01", title: "Atlas Cloud" } } : {}),
    });
  const sent = (type: string) => ext.sentToTabs.filter((s) => (s.message as { type: string }).type === type);
  return { ext, prompts, open, sent, requests };
}

describe("save pill", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("folded: the record lives PILL_TTL_MS, not SAVE_TTL_MS", async () => {
    expect(PILL_TTL_MS).toBe(600_000);
    const { prompts, open } = setup();
    const token = await open();
    await prompts.fold(token, UI);
    await vi.advanceTimersByTimeAsync(SAVE_TTL_MS + 1000);
    expect((await prompts.init(token, UI)).folded).toBe(true);
    await vi.advanceTimersByTimeAsync(PILL_TTL_MS - SAVE_TTL_MS - 2000);
    await expect(prompts.init(token, UI)).resolves.toMatchObject({ status: "update" });
  });

  it("an unfolded card still expires after SAVE_TTL_MS", async () => {
    const { prompts, open } = setup();
    const token = await open();
    await vi.advanceTimersByTimeAsync(SAVE_TTL_MS + 1000);
    await expect(prompts.init(token, UI)).rejects.toMatchObject({ code: "invalid" });
  });

  it("pill goes after PILL_TTL_MS: record gone, frame removed", async () => {
    const { prompts, open, sent } = setup();
    const token = await open();
    await prompts.fold(token, UI);
    await vi.advanceTimersByTimeAsync(PILL_TTL_MS + 1000);
    await expect(prompts.init(token, UI)).rejects.toMatchObject({ code: "invalid" });
    expect(sent("remove_frame")).toHaveLength(1);
  });

  it("unfold gives the card its own SAVE_TTL_MS again and clears the folded flag", async () => {
    const { prompts, open } = setup();
    const token = await open();
    await prompts.fold(token, UI);
    await vi.advanceTimersByTimeAsync(300_000);
    await prompts.unfold(token, UI);
    expect((await prompts.init(token, UI)).folded).toBeUndefined();
    await vi.advanceTimersByTimeAsync(SAVE_TTL_MS + 1000);
    await expect(prompts.init(token, UI)).rejects.toMatchObject({ code: "invalid" });
  });

  it("pill goes when the tab leaves the registrable domain", async () => {
    const { ext, prompts, open } = setup();
    const token = await open();
    await prompts.fold(token, UI);
    ext.navigate(TAB, 0, "https://elsewhere.test/", "doc-9");
    ext.complete(TAB, 0);
    await vi.advanceTimersByTimeAsync(10);
    await expect(prompts.init(token, UI)).rejects.toMatchObject({ code: "invalid" });
  });

  it("pill stays across a navigation inside the site and is shown again once the page loaded", async () => {
    const { ext, prompts, open, sent } = setup();
    const token = await open();
    await prompts.fold(token, UI);
    const before = sent("show_frame").length;
    ext.navigate(TAB, 0, "https://app.atlas-cloud.test/dash", "doc-3");
    await vi.advanceTimersByTimeAsync(10);
    // Not before the new document finished loading.
    expect(sent("show_frame")).toHaveLength(before);
    ext.complete(TAB, 0);
    await vi.advanceTimersByTimeAsync(10);
    const shown = sent("show_frame");
    expect(shown).toHaveLength(before + 1);
    expect((shown.at(-1)!.message as { url: string }).url).toContain(`#${token}`);
    expect(shown.at(-1)!.options).toEqual({ frameId: 0 });
    expect((await prompts.init(token, UI)).folded).toBe(true);
  });

  it("an unfolded card still goes on any navigation", async () => {
    const { ext, prompts, open } = setup();
    const token = await open();
    ext.navigate(TAB, 0, `${SITE}/other`, "doc-3");
    await vi.advanceTimersByTimeAsync(10);
    await expect(prompts.init(token, UI)).rejects.toMatchObject({ code: "invalid" });
  });

  it("folding keeps the sign-in in the popup list like the old auto-dismiss; pill expiry leaves it there", async () => {
    const { prompts, open } = setup();
    const token = await open();
    expect(await prompts.pendingList()).toEqual([]);
    await prompts.fold(token, UI);
    const listed = await prompts.pendingList();
    expect(listed).toEqual([expect.objectContaining({ site: "atlas-cloud.test", username: "alex@atlas.dev", status: "update" })]);
    // The pill goes after PILL_TTL_MS (same 10 minutes as the popup entry's own lifetime): only the pill.
    await vi.advanceTimersByTimeAsync(PILL_TTL_MS - 1000);
    await expect(prompts.init(token, UI)).resolves.toMatchObject({ folded: true });
    expect(await prompts.pendingList()).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(2000);
    await expect(prompts.init(token, UI)).rejects.toMatchObject({ code: "invalid" });
    // PENDING_SAVE_TTL_MS is the same 10 minutes: the entry ends by its own timer, not the pill's.
  });

  it("leaving the site removes the pill only; the popup entry stays", async () => {
    const { ext, prompts, open } = setup();
    const token = await open();
    await prompts.fold(token, UI);
    ext.navigate(TAB, 0, "https://elsewhere.test/", "doc-9");
    await vi.advanceTimersByTimeAsync(10);
    await expect(prompts.init(token, UI)).rejects.toMatchObject({ code: "invalid" });
    expect(await prompts.pendingList()).toHaveLength(1);
  });

  it("answering the unfolded card removes its popup entry", async () => {
    const { prompts, open } = setup();
    const token = await open();
    await prompts.fold(token, UI);
    await prompts.unfold(token, UI);
    expect(await prompts.pendingList()).toHaveLength(1);
    await prompts.decide(token, UI, "dismiss");
    expect(await prompts.pendingList()).toEqual([]);
  });

  it("saved from the popup: the pill and its record go, a later unfold or decide saves nothing", async () => {
    const { prompts, open, sent, requests } = setup();
    const token = await open("new");
    await prompts.fold(token, UI);
    const [w] = await prompts.pendingList();
    await prompts.decidePending(w!.id, "save");
    expect(requests.filter((r) => r.op === "save_login")).toHaveLength(1);
    expect(sent("remove_frame")).toHaveLength(1);
    await expect(prompts.init(token, UI)).rejects.toMatchObject({ code: "invalid" });
    await expect(prompts.unfold(token, UI)).rejects.toMatchObject({ code: "invalid" });
    const edits = { title: "Atlas Cloud", username: "alex@atlas.dev", password: "", vaultId: "v1", rule: "domain" as const, tags: [] };
    await expect(prompts.decide(token, UI, "save", edits)).rejects.toMatchObject({ code: "invalid" });
    expect(requests.filter((r) => r.op === "save_login")).toHaveLength(1);
  });

  it("never and dismiss from the popup also take the pill", async () => {
    for (const d of ["never", "dismiss"] as const) {
      const { prompts, open, sent } = setup();
      const token = await open("new");
      await prompts.fold(token, UI);
      const [w] = await prompts.pendingList();
      await prompts.decidePending(w!.id, d);
      expect(sent("remove_frame")).toHaveLength(1);
      await expect(prompts.unfold(token, UI)).rejects.toMatchObject({ code: "invalid" });
    }
  });

  it("a dropped record cannot fold", async () => {
    const { prompts, open } = setup();
    const token = await open("new");
    await prompts.decide(token, UI, "dismiss");
    await expect(prompts.fold(token, UI)).rejects.toMatchObject({ code: "invalid" });
  });
});
