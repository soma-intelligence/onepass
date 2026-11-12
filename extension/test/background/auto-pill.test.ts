// The sign-in pill that appears by itself (auto-pill.ts): when it shows, which face, and never
// anything filled, submitted or started by its appearance.
import { describe, expect, it } from "vitest";
import { AUTO_PILL_SHOWN_KEY, AutoPill, type AutoFace, type AutoPillDeps, type AutoVault } from "../../src/background/auto-pill";
import type { CsContext } from "../../src/background/frames";
import { AUTO_PILL_KEY, AUTO_PILL_NEVER_KEY, readAutoPill } from "../../src/shared/auto-pill";
import { FakeArea } from "./fake-ext";

const SITE = "https://atlas-cloud.test";

interface Page {
  url: string;
  doc: string;
  login: string[];
  signup: string[];
  prefilled: boolean;
  vault: AutoVault;
  logins: number;
  busy: boolean;
  incognito: boolean;
  /** The analysis is of another document than the top frame's. */
  staleDoc?: string;
  /** Runs while the vault answers (the tab may move meanwhile). */
  onVault?: () => void;
}

function setup(over: Partial<Page> = {}, session?: FakeArea) {
  const local = new FakeArea();
  const page: Page = { url: `${SITE}/login`, doc: "doc-1", login: ["f1"], signup: [], prefilled: false, vault: "open", logins: 1, busy: false, incognito: false, ...over };
  const opened: { cs: CsContext; face: AutoFace }[] = [];
  const asked: string[] = [];
  let failOpen = false;
  const deps: AutoPillDeps = {
    local,
    ...(session ? { session } : {}),
    topFrame: async () => ({ url: page.url, documentId: page.doc }),
    incognito: async () => page.incognito,
    busy: async () => page.busy,
    page: async () => ({ origin: new URL(page.url).origin, documentId: page.staleDoc ?? page.doc, login: page.login, signup: page.signup }),
    prefilled: async (_cs, refs) => {
      asked.push(`prefilled:${refs.join(",")}`);
      return page.prefilled;
    },
    vault: async () => {
      page.onVault?.();
      return page.vault;
    },
    logins: async () => page.logins,
    open: async (cs, face) => {
      if (failOpen) throw new Error("gone");
      opened.push({ cs, face });
    },
  };
  const pill = new AutoPill(deps);
  /** The worker restarted: a new instance on the same storage. */
  const restart = () => new AutoPill(deps);
  return {
    pill,
    restart,
    page,
    local,
    opened,
    asked,
    failOpen: (v: boolean) => {
      failOpen = v;
    },
  };
}

describe("auto sign-in pill: appearance", () => {
  it("case 1: a login form, the vault open, a login saved for the site: the sign-in pill", async () => {
    const t = setup();
    await t.pill.onReady(7);
    expect(t.opened).toEqual([{ cs: { tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1" }, face: "signin" }]);
    // Only the recognised form is asked about (a value in it keeps the pill away), again right before it shows.
    expect(t.asked).toEqual(["prefilled:f1", "prefilled:f1"]);
  });

  it("case 2: a login form and a locked vault: the generic card", async () => {
    const t = setup({ vault: "locked" });
    await t.pill.onReady(7);
    expect(t.opened.map((x) => x.face)).toEqual(["generic"]);
  });

  it("case 3: a signup form (new-password fields), the vault open: the create pill", async () => {
    const t = setup({ login: [], signup: ["f2"] });
    await t.pill.onReady(7);
    expect(t.opened.map((x) => x.face)).toEqual(["signup"]);
    expect(t.asked).toEqual(["prefilled:f2", "prefilled:f2"]);
  });

  it("a login form with nothing saved for the site: nothing", async () => {
    const t = setup({ logins: 0 });
    await t.pill.onReady(7);
    expect(t.opened).toEqual([]);
  });

  it("a signup form on a locked vault, or no app at all: nothing", async () => {
    for (const over of [{ login: [], signup: ["f2"], vault: "locked" as const }, { vault: "missing" as const }, { login: [], signup: ["f2"], vault: "missing" as const }]) {
      const t = setup(over);
      await t.pill.onReady(7);
      expect(t.opened).toEqual([]);
    }
  });

  it("a page without a recognised form: nothing", async () => {
    const t = setup({ login: [], signup: [] });
    await t.pill.onReady(7);
    expect(t.opened).toEqual([]);
  });

  it("an analysis of another document than the top frame's: nothing", async () => {
    const t = setup({ staleDoc: "doc-0" });
    await t.pill.onReady(7);
    expect(t.opened).toEqual([]);
  });

  it("waits for the page to be ready: a top analysis before it shows nothing, one after it does", async () => {
    const t = setup();
    await t.pill.onAnalysis(7, 0);
    expect(t.opened).toEqual([]);
    await t.pill.onReady(7);
    expect(t.opened).toHaveLength(1);
  });

  it("a form that shows up after the load (a page analysis of the top frame) brings the pill then", async () => {
    const t = setup({ login: [] });
    await t.pill.onReady(7);
    expect(t.opened).toEqual([]);
    t.page.login = ["f1"];
    await t.pill.onAnalysis(7, 0);
    expect(t.opened).toHaveLength(1);
  });

  it("an analysis of a child frame never brings it", async () => {
    const t = setup({ login: [] });
    await t.pill.onReady(7);
    t.page.login = ["f1"];
    await t.pill.onAnalysis(7, 3);
    expect(t.opened).toEqual([]);
  });
});

describe("auto sign-in pill: never shown when", () => {
  it("the tab moved to another site while the vault answered (no document id: Firefox, Safari)", async () => {
    const t = setup({ doc: undefined as unknown as string });
    t.page.onVault = () => {
      t.page.url = "https://foreign.test/";
    };
    await t.pill.onReady(7);
    expect(t.opened).toEqual([]);
  });

  it("the user typed in the form while the vault answered (the value is looked at again right before it shows)", async () => {
    const t = setup();
    t.page.onVault = () => {
      t.page.prefilled = true;
    };
    await t.pill.onReady(7);
    expect(t.opened).toEqual([]);
    expect(t.asked).toEqual(["prefilled:f1", "prefilled:f1"]);
  });

  it("the top document changed while the vault answered", async () => {
    const t = setup();
    t.page.onVault = () => {
      t.page.doc = "doc-2";
    };
    await t.pill.onReady(7);
    expect(t.opened).toEqual([]);
  });

  it("a chain runs in the tab, or another of our surfaces is there", async () => {
    const t = setup({ busy: true });
    await t.pill.onReady(7);
    expect(t.opened).toEqual([]);
  });

  it("a field of the form already holds a value", async () => {
    const t = setup({ prefilled: true });
    await t.pill.onReady(7);
    expect(t.opened).toEqual([]);
  });

  it("the window is private", async () => {
    const t = setup({ incognito: true });
    await t.pill.onReady(7);
    expect(t.opened).toEqual([]);
  });

  it("the top page is not https, or not a page", async () => {
    for (const url of ["http://atlas-cloud.test/login", "chrome-extension://abc/x.html", "about:blank"]) {
      const t = setup({ url });
      await t.pill.onReady(7);
      expect(t.opened).toEqual([]);
    }
  });

  it("the setting is off", async () => {
    const t = setup();
    await t.local.set({ [AUTO_PILL_KEY]: false });
    await t.pill.onReady(7);
    expect(t.opened).toEqual([]);
  });

  it("the site is in the never-list (its registrable domain, any host of it)", async () => {
    const t = setup({ url: "https://login.atlas-cloud.test/" });
    await t.pill.never("https://www.atlas-cloud.test");
    expect(await readAutoPill(t.local)).toEqual({ enabled: true, never: ["atlas-cloud.test"] });
    await t.pill.onReady(7);
    expect(t.opened).toEqual([]);
  });
});

describe("auto sign-in pill: once per site per tab", () => {
  it("a second page ready on the same site in the same tab shows nothing (a reload included)", async () => {
    const t = setup();
    await t.pill.onReady(7);
    t.pill.onCommitted(7);
    t.page.doc = "doc-2";
    await t.pill.onReady(7);
    t.page.url = `${SITE}/other`;
    t.pill.onCommitted(7);
    await t.pill.onReady(7);
    expect(t.opened).toHaveLength(1);
  });

  it("another site in the same tab, or the same site in another tab, may show it", async () => {
    const t = setup();
    await t.pill.onReady(7);
    await t.pill.onReady(8);
    t.pill.onCommitted(7);
    t.page.url = "https://other-site.test/login";
    await t.pill.onReady(7);
    expect(t.opened.map((x) => `${x.cs.tabId}:${x.cs.origin}`)).toEqual([`7:${SITE}`, `8:${SITE}`, "7:https://other-site.test"]);
  });

  it("a closed tab forgets its sites", async () => {
    const t = setup();
    await t.pill.onReady(7);
    t.pill.onTabRemoved(7);
    await t.pill.onReady(7);
    expect(t.opened).toHaveLength(2);
  });

  it("a pill that could not be shown (the page went away) does not count", async () => {
    const t = setup();
    t.failOpen(true);
    await t.pill.onReady(7);
    t.failOpen(false);
    await t.pill.onReady(7);
    expect(t.opened).toHaveLength(1);
  });

  it("two triggers at once show one pill", async () => {
    const t = setup();
    await Promise.all([t.pill.onReady(7), t.pill.onAnalysis(7, 0), t.pill.onAnalysis(7, 0)]);
    expect(t.opened).toHaveLength(1);
  });
});

describe("auto sign-in pill: once per site per tab, across a restart of the worker (storage.session)", () => {
  it("a worker stopped and started again still knows the site showed in this tab", async () => {
    const session = new FakeArea();
    const t = setup({}, session);
    await t.pill.onReady(7);
    const again = t.restart();
    await again.onReady(7);
    expect(t.opened).toHaveLength(1);
    expect(session.data.get(AUTO_PILL_SHOWN_KEY)).toEqual(["7|atlas-cloud.test"]);
  });

  it("a closed tab is forgotten in storage.session too", async () => {
    const session = new FakeArea();
    const t = setup({}, session);
    await t.pill.onReady(7);
    await t.pill.onReady(8);
    await t.pill.onTabRemoved(7);
    expect(session.data.get(AUTO_PILL_SHOWN_KEY)).toEqual(["8|atlas-cloud.test"]);
    await t.restart().onReady(7);
    expect(t.opened).toHaveLength(3);
  });

  it("a tab replaced by another (prerender, instant pages) carries what it showed", async () => {
    const session = new FakeArea();
    const t = setup({}, session);
    await t.pill.onReady(7);
    await t.pill.onReplaced(9, 7);
    expect(session.data.get(AUTO_PILL_SHOWN_KEY)).toEqual(["9|atlas-cloud.test"]);
    await t.restart().onReady(9);
    await t.pill.onReady(9);
    expect(t.opened).toHaveLength(1);
  });

  it("without storage.session, worker memory", async () => {
    const t = setup();
    await t.pill.onReady(7);
    await t.pill.onReplaced(9, 7);
    await t.pill.onReady(9);
    expect(t.opened).toHaveLength(1);
  });
});

describe("auto sign-in pill: settings", () => {
  it("defaults on with an empty never-list; a malformed store reads as the defaults", async () => {
    const local = new FakeArea();
    expect(await readAutoPill(local)).toEqual({ enabled: true, never: [] });
    await local.set({ [AUTO_PILL_KEY]: "no", [AUTO_PILL_NEVER_KEY]: [3, "", "ok.test", null] });
    expect(await readAutoPill(local)).toEqual({ enabled: true, never: ["ok.test"] });
  });

  it("never() keeps each site once", async () => {
    const t = setup();
    await t.pill.never(SITE);
    await t.pill.never(`${SITE}/login`);
    expect((await readAutoPill(t.local)).never).toEqual(["atlas-cloud.test"]);
  });
});
