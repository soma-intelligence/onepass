import { describe, expect, it } from "vitest";
import { AutofillHistory, MAX_SHOWN, PROFILE_KEY, browserKind } from "../../src/background/history";
import type { BridgeLike } from "../../src/background/session";
import { FakeArea } from "./fake-ext";

type Req = Record<string, unknown> & { op: string };

/** A session whose client records what it is asked; `refuse` ops fail. */
function fakeSession(refuse: Set<string> = new Set()) {
  const sent: Req[] = [];
  let client = makeClient();
  function makeClient(): BridgeLike {
    return {
      isOpen: true,
      open: async () => undefined,
      pair: async () => {
        throw new Error("no");
      },
      request: (async (req: Req) => {
        sent.push(req);
        if (refuse.has(req.op)) throw new Error("invalid");
        return {};
      }) as BridgeLike["request"],
      close: () => undefined,
    };
  }
  return {
    sent,
    reconnect: () => {
      client = makeClient();
    },
    session: {
      getClient: async () => client,
      request: (async (req: Req) => client.request(req as never)) as never,
    },
  };
}

const ORIGIN = "https://example.com";

function make(refuse?: Set<string>) {
  const s = fakeSession(refuse);
  const area = new FakeArea();
  let n = 0;
  const h = new AutofillHistory({ session: s.session, area, browser: "chrome", newId: () => `profile-id-${++n}` });
  return { h, s, area };
}

describe("browserKind", () => {
  const ua = (s: string) => ({ userAgent: s });
  it("tells the browsers apart", () => {
    expect(browserKind(ua("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15"))).toBe("safari");
    expect(browserKind(ua("Mozilla/5.0 AppleWebKit/537.36 Chrome/130.0 Safari/537.36"))).toBe("chrome");
    expect(browserKind(ua("Mozilla/5.0 Chrome/130.0 Safari/537.36 Edg/130.0"))).toBe("edge");
    expect(browserKind(ua("Mozilla/5.0 Chrome/130.0 Safari/537.36 OPR/115.0"))).toBe("opera");
    expect(browserKind(ua("Mozilla/5.0 Gecko/20100101 Firefox/133.0"))).toBe("firefox");
    expect(browserKind({ userAgent: "Mozilla/5.0 Chrome/130.0 Safari/537.36", brave: {} })).toBe("brave");
    expect(browserKind({ userAgent: "Mozilla/5.0 Chrome/130.0 Safari/537.36", brands: [{ brand: "Arc" }] })).toBe("arc");
    expect(browserKind(ua("curl/8"))).toBe("unknown");
  });
});

describe("AutofillHistory", () => {
  it("draws the profile id once and keeps it in this profile's storage", async () => {
    const { h, area } = make();
    expect(await h.profileId()).toBe("profile-id-1");
    expect(await area.get(PROFILE_KEY)).toEqual({ [PROFILE_KEY]: "profile-id-1" });
    // A new worker reads it back.
    const again = new AutofillHistory({ session: fakeSession().session, area, browser: "chrome", newId: () => "other-id-x" });
    expect(await again.profileId()).toBe("profile-id-1");
  });

  it("says client_info once per client, again after a reconnect", async () => {
    const { h, s } = make();
    await h.ensureClient();
    await h.ensureClient();
    expect(s.sent).toEqual([{ op: "client_info", browser: "chrome", profile_id: "profile-id-1" }]);
    s.reconnect();
    await h.ensureClient();
    expect(s.sent.filter((r) => r.op === "client_info")).toHaveLength(2);
  });

  it("reports a pick with its rank and the first offer passed over", async () => {
    const { h, s } = make();
    await h.shown("menu:1:0", "menu", ORIGIN, ["a", "b", "c"]);
    await h.picked("menu:1:0", "b");
    // The list is closed by the pick: a later close is no dismissal.
    await h.dismissed("menu:1:0");
    const notes = s.sent.filter((r) => r.op === "note_autofill");
    expect(notes).toEqual([
      { op: "note_autofill", ctx: "menu", origin: ORIGIN, action: "shown", shown: ["a", "b", "c"] },
      { op: "note_autofill", ctx: "menu", origin: ORIGIN, action: "picked", item_id: "b", rank: 1 },
      { op: "note_autofill", ctx: "menu", origin: ORIGIN, action: "picked_other", item_id: "a", rank: 0 },
    ]);
    // Never a value: ids, the origin, ranks.
    expect(JSON.stringify(s.sent)).not.toMatch(/password|username/);
  });

  it("a first pick is no passed-over offer; a close without a pick is a dismissal", async () => {
    const { h, s } = make();
    await h.shown("popup", "popup", ORIGIN, ["a", "b"]);
    await h.picked("popup", "a");
    await h.shown("menu:2:0", "menu", ORIGIN, ["a", "b"]);
    await h.dismissed("menu:2:0");
    const actions = s.sent.filter((r) => r.op === "note_autofill").map((r) => [r.action, r.item_id]);
    expect(actions).toEqual([
      ["shown", undefined],
      ["picked", "a"],
      ["shown", undefined],
      ["dismissed", "a"],
    ]);
  });

  it("caps the shown list, skips http pages and empty lists", async () => {
    const { h, s } = make();
    const ids = Array.from({ length: 12 }, (_, i) => `i${i}`);
    await h.shown("k", "menu", ORIGIN, ids);
    expect((s.sent.find((r) => r.action === "shown")?.shown as string[]).length).toBe(MAX_SHOWN);
    await h.shown("k2", "menu", ORIGIN, []);
    await h.shown("k3", "menu", "http://example.com", ["a"]);
    await h.picked("k3", "a");
    expect(s.sent.filter((r) => r.op === "note_autofill")).toHaveLength(1);
    // A pick on a surface never shown says nothing.
    await h.picked("never", "a");
    expect(s.sent.filter((r) => r.op === "note_autofill")).toHaveLength(1);
  });

  it("an older app refusing both ops never breaks a caller", async () => {
    const { h, s } = make(new Set(["client_info", "note_autofill"]));
    await expect(h.ensureClient()).resolves.toBeUndefined();
    await expect(h.shown("k", "menu", ORIGIN, ["a"])).resolves.toBeUndefined();
    await expect(h.picked("k", "a")).resolves.toBeUndefined();
    // Asked once per client only.
    expect(s.sent.filter((r) => r.op === "client_info")).toHaveLength(1);
  });
});
