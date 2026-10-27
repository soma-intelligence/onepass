import { describe, expect, it } from "vitest";
import { contentSender, extensionSender } from "../../src/background/frames";
import { MENU_TTL_MS, MenuTokens } from "../../src/background/menu";
import { csSender, FakeExt, uiSender } from "./fake-ext";

const SITE = "https://atlas-cloud.test";
const FIELD = { formRef: "f1", fieldRef: "e1", formKind: "login" as const };

function setup(clock = { t: 1_000 }) {
  const ext = new FakeExt();
  const menus = new MenuTokens(ext.session, () => clock.t);
  menus.install(ext);
  const cs = (url = `${SITE}/login`, tabId = 7, frameId = 0) =>
    contentSender(ext.runtime, csSender(url, tabId, frameId, { documentId: "doc-1" }))!;
  const ui = (tabId?: number) => extensionSender(ext.runtime, uiSender("menu.html", tabId))!;
  return { ext, menus, cs, ui, clock };
}

describe("menu tokens", () => {
  it("menu_token_bound_to_tab", async () => {
    const { menus, cs, ui } = setup();
    const token = await menus.register(cs(), FIELD);
    expect(token).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const rec = await menus.resolve(token, ui(7));
    expect(rec).toMatchObject({ tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1", ...FIELD });
    // Another tab, or the popup (no tab), cannot use it.
    expect(await menus.resolve(token, ui(8))).toBeNull();
    expect(await menus.resolve(token, ui())).toBeNull();
    expect(await menus.resolve("not a token", ui(7))).toBeNull();
  });

  it("survives a service worker restart through storage.session", async () => {
    const { ext, menus, cs, ui } = setup();
    const token = await menus.register(cs(), FIELD);
    expect([...ext.session.data.keys()]).toEqual([`menu:${token}`]);
    const fresh = new MenuTokens(ext.session, () => 1_000);
    expect(await fresh.resolve(token, ui(7))).toMatchObject({ origin: SITE });
  });

  it("expires after 10 minutes", async () => {
    const { menus, cs, ui, clock, ext } = setup();
    const token = await menus.register(cs(), FIELD);
    clock.t += MENU_TTL_MS + 1;
    expect(await menus.resolve(token, ui(7))).toBeNull();
    expect(ext.session.data.size).toBe(0);
  });

  it("dies on navigation of its frame, and on top navigation", async () => {
    const { ext, menus, cs, ui } = setup();
    const top = await menus.register(cs(), FIELD);
    const sub = await menus.register(cs(`${SITE}/frame`, 7, 3), FIELD);
    const other = await menus.register(cs(`${SITE}/x`, 9, 0), FIELD);
    ext.navigate(7, 3, `${SITE}/elsewhere`);
    await new Promise((r) => setTimeout(r, 0));
    expect(await menus.resolve(sub, ui(7))).toBeNull();
    expect(await menus.resolve(top, ui(7))).not.toBeNull();
    const sub2 = await menus.register(cs(`${SITE}/frame`, 7, 3), FIELD);
    ext.navigate(7, 0, "https://evil.test/");
    await new Promise((r) => setTimeout(r, 0));
    expect(await menus.resolve(top, ui(7))).toBeNull();
    expect(await menus.resolve(sub2, ui(7))).toBeNull();
    expect(await menus.resolve(other, ui(9))).not.toBeNull();
  });

  it("dies with its tab, and is replaced by a new menu in the same frame", async () => {
    const { ext, menus, cs, ui } = setup();
    const a = await menus.register(cs(), FIELD);
    const b = await menus.register(cs(), FIELD);
    expect(await menus.resolve(a, ui(7))).toBeNull();
    expect(await menus.resolve(b, ui(7))).not.toBeNull();
    ext.onRemoved.emit(7);
    await new Promise((r) => setTimeout(r, 0));
    expect(await menus.resolve(b, ui(7))).toBeNull();
    expect(ext.session.data.size).toBe(0);
  });
});
