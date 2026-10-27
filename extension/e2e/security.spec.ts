// Security tests of spec 11.4 against hostile pages, end to end.
//
// S13 (client without pairing, wrong `PK`, replayed or modified frame) is a
// protocol property covered below the browser: Rust in
// core/onepass-bridge/tests and core/onepass-native-host/tests/host.rs
// (session refused or closed), TypeScript in test/bridge/session.test.ts,
// test/bridge/client.test.ts and test/bridge/host-interop.test.ts
// ("an unknown pairing is refused by the host").
//
// S14, S15 and parts of S5 and S9 need to talk to the service worker as a
// compromised content script would (a forged message with the browser's
// real sender, or a forged sender): they run on the `--e2e` build, whose
// worker exposes its router, session and filler (src/background/e2e-entry.ts).
// Everything else runs on the regular build.
import type { Frame, Page, Worker } from "@playwright/test";
import { type Ext, expect, paired } from "./fixtures";
import { FX } from "./server";

const ATLAS = "https://atlas-cloud.test";

/** Values of the fictional vault that must never reach a page. */
const SECRETS = [
  FX.atlas.password,
  FX.ops.password,
  FX.atlas.totpSecret,
  FX.googlePerso.password,
  FX.googlePro.password,
  "Adm1n-Pass-0002",
  "Old-Pass-0003",
  "Hidden-Pass-0004",
  "Repr-Pass-0007",
  "4242 4242 4242 4242",
  "4242424242424242",
  "abandon abandon",
];

/** What the menu and the overlay show on atlas-cloud.test: never readable by the page. */
const SHOWN = [FX.atlas.email, FX.ops.email, "Atlas Cloud (multi)", ...SECRETS];

async function emptyFields(page: Page | Frame, ...selectors: string[]): Promise<void> {
  for (const s of selectors) await expect(page.locator(s)).toHaveValue("");
}

// ---- service worker handle (e2e build) ----

type Reply = { reply: unknown } | { dropped: true } | { timeout: true };

interface ForgedSender {
  /** Our extension id unless set. */
  id?: string;
  url: string;
  origin?: string;
  tabId?: number;
  frameId?: number;
  documentId?: string;
}

/** Calls the worker's router with a forged sender, as the browser would. */
async function routeAs(w: Worker, message: unknown, sender: ForgedSender): Promise<Reply> {
  return w.evaluate(
    async ({ message, sender }) => {
      type Router = (m: unknown, s: unknown, r: (x: unknown) => void) => unknown;
      const h = (globalThis as { __onepassE2E?: { router: Router } }).__onepassE2E;
      if (!h) throw new Error("not an e2e build");
      const s: Record<string, unknown> = { id: sender.id ?? chrome.runtime.id, url: sender.url };
      if (sender.origin !== undefined) s.origin = sender.origin;
      if (sender.tabId !== undefined) s.tab = { id: sender.tabId };
      if (sender.frameId !== undefined) s.frameId = sender.frameId;
      if (sender.documentId !== undefined) s.documentId = sender.documentId;
      return new Promise<Reply>((resolve) => {
        const kept = h.router(message, s, (r: unknown) => resolve({ reply: r }));
        if (kept !== true) resolve({ dropped: true });
        setTimeout(() => resolve({ timeout: true }), 10_000);
      });
    },
    { message, sender },
  );
}

/** A request straight to the host over the worker's session: `{ok}` or `{err: code}`. */
async function hostRequest(w: Worker, req: Record<string, unknown>): Promise<{ ok?: unknown; err?: string }> {
  return w.evaluate(async (req) => {
    const h = (globalThis as { __onepassE2E?: { session: { request(r: unknown): Promise<unknown> } } }).__onepassE2E;
    if (!h) throw new Error("not an e2e build");
    try {
      return { ok: await h.session.request(req) };
    } catch (e) {
      return { err: (e as { code?: string }).code ?? String(e) };
    }
  }, req);
}

async function itemId(w: Worker, origin: string, title: string): Promise<string> {
  const r = await hostRequest(w, { op: "list_for_origin", ctx: "menu", origin });
  const items = (r.ok as { items: { item_id: string; title: string }[] }).items;
  const it = items.find((x) => x.title === title);
  if (!it) throw new Error(`no item ${title} for ${origin}`);
  return it.item_id;
}

/** The tab showing `pattern` (`null`: the only web tab, for an HTTP page whose URL the extension cannot see). */
async function tabOf(w: Worker, pattern: string | null): Promise<{ tabId: number; documentId?: string }> {
  return w.evaluate(async (pattern) => {
    const tabs = pattern === null ? (await chrome.tabs.query({})).filter((t) => !t.url?.startsWith("chrome-extension://")) : await chrome.tabs.query({ url: pattern });
    const tab = tabs[0];
    if (pattern === null) {
      if (tabs.length !== 1 || tab?.id === undefined) throw new Error("expected one web tab");
      return { tabId: tab.id };
    }
    if (tab?.id === undefined) throw new Error(`no tab for ${pattern}`);
    const f = await chrome.webNavigation.getFrame({ tabId: tab.id, frameId: 0 });
    const out: { tabId: number; documentId?: string } = { tabId: tab.id };
    const doc = (f as { documentId?: string } | null)?.documentId;
    if (doc) out.documentId = doc;
    return out;
  }, pattern);
}

/** Runs `expression` in the content script's isolated world of the page's top frame (CDP). */
async function inContentScript(ext: Ext, page: Page, expression: string): Promise<unknown> {
  const cdp = await ext.context.newCDPSession(page);
  const contexts: { id: number; name: string; auxData?: { type?: string; frameId?: string; isDefault?: boolean } }[] = [];
  cdp.on("Runtime.executionContextCreated", (e) => contexts.push(e.context));
  await cdp.send("Runtime.enable");
  const { frameTree } = await cdp.send("Page.getFrameTree");
  let world: (typeof contexts)[number] | undefined;
  await expect
    .poll(() => {
      world = contexts.find((c) => c.auxData?.type === "isolated" && c.auxData.frameId === frameTree.frame.id && c.name === "OnePass");
      return world !== undefined;
    })
    .toBe(true);
  const r = await cdp.send("Runtime.evaluate", { expression, contextId: world?.id, awaitPromise: true, returnByValue: true });
  await cdp.detach();
  return r.result.value;
}

// ---- tests ----

paired("S1_page_cannot_read_menu_or_overlay", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/login`);
  const overlay = await ext.extFrame(page, "overlay");
  await expect(overlay.getByText(FX.atlas.email)).toBeVisible();
  const menu = await ext.openMenu(page, "#email");
  // What the page looks for really is on screen, in our frames.
  await expect(menu.getByText(FX.ops.email)).toBeVisible();
  const r = await page.evaluate((needles) => {
    const texts: string[] = [document.documentElement.outerHTML, document.body.innerText];
    const walk = (root: Document | ShadowRoot) => {
      for (const el of Array.from(root.querySelectorAll("*"))) {
        if (el.shadowRoot) {
          texts.push(el.shadowRoot.innerHTML);
          walk(el.shadowRoot);
        }
      }
    };
    walk(document);
    const frames: string[] = [];
    for (let i = 0; i < window.frames.length; i++) {
      try {
        texts.push(window.frames[i]?.document.documentElement.outerHTML ?? "");
        frames.push("readable");
      } catch {
        frames.push("blocked");
      }
    }
    for (const f of Array.from(document.querySelectorAll("iframe"))) {
      try {
        const d = f.contentDocument;
        if (d) texts.push(d.documentElement.outerHTML);
      } catch {
        // Cross-origin.
      }
    }
    const host = document.querySelector("onepass-root");
    const all = texts.join("\n");
    return {
      found: needles.filter((n) => all.includes(n)),
      hostPresent: host !== null,
      shadowRoot: host === null ? "absent" : host.shadowRoot === null ? "closed" : "open",
      iframesInDocument: document.querySelectorAll("iframe").length,
      readableFrames: frames.filter((x) => x === "readable").length,
    };
  }, SHOWN);
  expect(r.found).toEqual([]);
  expect(r.hostPresent).toBe(true);
  expect(r.shadowRoot).toBe("closed");
  expect(r.iframesInDocument).toBe(0);
  expect(r.readableFrames).toBe(0);
});

paired("S2_synthetic_click_on_icon_is_ignored", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/login`);
  await expect(page.locator("onepass-root")).toHaveCount(1);
  await ext.settle(1000);
  await page.evaluate(() => {
    const field = document.getElementById("email") as HTMLInputElement;
    const r = field.getBoundingClientRect();
    // Where the icon sits: the right edge of the field.
    const x = r.right - 16;
    const y = r.top + r.height / 2;
    const targets = [document.elementFromPoint(x, y), document.querySelector("onepass-root"), field];
    for (const t of targets) {
      if (!t) continue;
      for (const type of ["pointerdown", "mousedown", "pointerup", "mouseup", "click"]) {
        t.dispatchEvent(new MouseEvent(type, { bubbles: true, composed: true, cancelable: true, clientX: x, clientY: y }));
      }
      (t as HTMLElement).click?.();
    }
    field.focus();
    field.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true, composed: true }));
  });
  await ext.settle(1500);
  expect(ext.findExtFrame(page, "menu")).toBeUndefined();
  // A real keystroke does open it: the page above really was a candidate.
  await ext.openMenu(page, "#email");
  await emptyFields(page, "#email", "#password");
});

paired("S3_postmessage_to_menu_is_ignored", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/login`);
  const menu = await ext.openMenu(page, "#email");
  await expect(menu.locator("button.row").first()).toBeVisible();
  // What a page would need to drive the menu: its token and a real item id
  // (both handed to the page here, which it could never learn by itself).
  const token = new URL(menu.url()).hash.slice(1);
  const rec = (await ext.sessionStorage())[`menu:${token}`] as { offered?: Record<string, string> };
  const itemIds = Object.entries(rec.offered ?? {})
    .filter(([, kind]) => kind === "login")
    .map(([id]) => id);
  expect(itemIds.length).toBeGreaterThan(0);
  await ext.settle();
  const r = await page.evaluate(
    ({ token, itemIds }) => {
      // The menu frame is in a closed shadow root: not among the page's frames.
      const framesSeen = window.frames.length;
      const payloads: unknown[] = [];
      for (const itemId of itemIds) {
        payloads.push(
          { type: "menu_pick", token, itemId },
          { type: "fill", token, itemId, values: { username: "x", current_password: "y" } },
          { token, itemId },
          `menu_pick:${token}:${itemId}`,
        );
      }
      const host = document.querySelector("onepass-root");
      for (const p of payloads) {
        window.postMessage(p, "*");
        window.top?.postMessage(p, "*");
        host?.dispatchEvent(new MessageEvent("message", { data: p, origin: location.origin, bubbles: true, composed: true }));
      }
      // Also the keys a menu would act on, synthesized.
      for (const key of ["ArrowDown", "Enter"]) document.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true }));
      return { framesSeen, hostFound: host !== null };
    },
    { token, itemIds },
  );
  expect(r).toEqual({ framesSeen: 0, hostFound: true });
  await ext.settle(1500);
  await emptyFields(page, "#email", "#password");
  expect(ext.findExtFrame(page, "menu")).toBeDefined();
  // No value was asked of the host.
  expect(ext.audit()).not.toContain("fill_login");
});

for (const lookalike of ["https://atlass-cloud.test", "https://atlas-cloud.test.evil.test"]) {
  paired(`S4_lookalike_${new URL(lookalike).hostname}_gets_nothing`, async ({ ext }) => {
    const { page } = ext;
    await page.goto(`${lookalike}/login`);
    const menu = await ext.openMenu(page, "#email");
    await expect(menu.getByText(`Aucun login pour ${new URL(lookalike).hostname}`)).toBeVisible();
    await expect(menu.locator(".t2")).toHaveCount(0);
    await ext.settle(1500);
    expect(ext.findExtFrame(page, "overlay")).toBeUndefined();
    await emptyFields(page, "#email", "#password");
    expect(ext.server.captured).toEqual([]);
  });
}

paired("S6_no_fill_in_cross_site_iframe", async ({ ext }) => {
  const { page } = ext;
  await page.goto("https://evil.test/frame");
  let victim: Frame | null = null;
  await expect.poll(() => (victim = page.frame({ url: /^https:\/\/atlas-cloud\.test\/login/ })) !== null).toBe(true);
  const frame = victim as unknown as Frame;
  await expect(frame.locator("#email")).toBeVisible();
  const menu = await ext.openMenu(page, "#email", frame);
  await ext.pickRow(menu, "Atlas Cloud");
  await expect(menu.locator(".error-line")).toHaveText("Cadre d'un autre site : remplissage refusé.");
  await ext.settle(1000);
  await emptyFields(frame, "#email", "#password");
});

paired("S7_invisible_form_stays_empty", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/invisible`);
  const menu = await ext.openMenu(page, "#email");
  await ext.pickRow(menu, "Atlas Cloud");
  await expect(page.locator("#email")).toHaveValue(FX.atlas.email);
  await expect(page.locator("#password")).toHaveValue(FX.atlas.password);
  await emptyFields(page, "#decoy-email", "#decoy-password", "#ghost-email", "#ghost-password");
  // Decoys inside the very form that gets filled.
  await emptyFields(page, "#hidden-password", "#transparent-password", "#offscreen-password", "#tiny-password", "#clipped-password", "#clipped-first");
});

paired("S8_nothing_filled_on_load", async ({ ext }) => {
  const { page } = ext;
  for (const path of ["/login", "/multistep", "/checkout", "/profile"]) {
    await page.goto(`${ATLAS}${path}`);
    await expect(page.locator("onepass-root")).toHaveCount(1);
    await ext.settle(2500);
    const values = await page.evaluate(() =>
      Array.from(document.querySelectorAll("input")).map((i) => (i.type === "checkbox" ? "" : i.value)),
    );
    expect(values.every((v) => v === "")).toBe(true);
  }
  // The overlay offers a sign-in on /login and /multistep, but never acts by itself.
  expect(await ext.chainState()).toBeNull();
});

paired("S10_chain_redirected_to_other_domain_stops", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/lookalike-login`);
  await ext.overlayStart(page, "Atlas Cloud");
  await expect(page).toHaveURL("https://atlas-cloud.test.evil.test/login", { timeout: 30_000 });
  await expect.poll(async () => await ext.chainState(), { timeout: 20_000 }).toMatchObject({
    status: "handoff",
    reason: "domain",
    host: "atlas-cloud.test.evil.test",
  });
  await ext.settle(2000);
  await emptyFields(page, "#email", "#password");
  expect(ext.server.captured).toEqual([]);
});

paired("S11_fake_provider_domain_is_not_google", async ({ ext }) => {
  const { page } = ext;
  // Same site, but its "Continuer avec Google" leads to accounts.google.com.evil.test.
  await page.goto("https://docs.atlas-cloud.test/login-fake-provider");
  await ext.overlayStart(page, "Atlas Docs via Google");
  await expect(page).toHaveURL(/^https:\/\/accounts\.google\.com\.evil\.test\/o\/oauth2\/auth/, { timeout: 30_000 });
  await expect.poll(async () => await ext.chainState(), { timeout: 20_000 }).toMatchObject({
    status: "handoff",
    reason: "domain",
    host: "accounts.google.com.evil.test",
  });
  // No account was picked in the fake chooser.
  await ext.settle(2000);
  await expect(page).toHaveURL(/\/o\/oauth2\/auth/);
  // On its identifier page, OnePass offers no Google account at all.
  await page.goto("https://accounts.google.com.evil.test/signin/identifier");
  const menu = await ext.openMenu(page, "#identifier-email");
  await expect(menu.getByText("Aucun login pour accounts.google.com.evil.test")).toBeVisible();
  await expect(menu.getByText(/Utilisé pour/)).toHaveCount(0);
  await emptyFields(page, "#identifier-email");
  expect(ext.server.captured).toEqual([]);
  expect(ext.server.providerSignIns).toEqual([]);
});

paired("S12_captcha_during_chain_stops", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/captcha-step`);
  await ext.overlayStart(page, "Atlas Cloud");
  // Identifier step done, then a CAPTCHA on the password step.
  await expect(page).toHaveURL(`${ATLAS}/captcha-step/password`, { timeout: 30_000 });
  await expect.poll(async () => await ext.chainState(), { timeout: 20_000 }).toMatchObject({ status: "handoff", reason: "captcha" });
  const overlay = await ext.extFrame(page, "overlay");
  await expect(overlay.locator(".ov-status")).toHaveText("CAPTCHA détecté, à toi de jouer");
  await ext.settle(1000);
  await emptyFields(page, "#password");
  await expect(page.locator("#robot")).not.toBeChecked();
});

paired("S16_menu_summaries_hold_no_secret", async ({ ext }) => {
  const { page } = ext;
  const seen: string[] = [];
  for (const [path, field] of [
    ["/login", "#email"],
    ["/checkout", "#cc-number"],
    ["/profile", "#given-name"],
  ] as const) {
    await page.goto(`${ATLAS}${path}`);
    const menu = await ext.openMenu(page, field);
    await expect(menu.locator("button.row").first()).toBeVisible();
    // The very reply the menu renders from.
    const init = await menu.evaluate(async () =>
      JSON.stringify(await chrome.runtime.sendMessage({ type: "menu_init", token: location.hash.slice(1) })),
    );
    seen.push(init);
  }
  const all = seen.join("\n");
  expect(all).toContain(FX.atlas.email);
  expect(all).toContain("Carte Atlas");
  for (const s of SECRETS) expect(all).not.toContain(s);
  expect(all).not.toMatch(/"(password|totp|cvv|number|recovery_phrase)"/);
});

paired("S17_fixed_extension_url_not_reachable", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/login`);
  const results = await page.evaluate(async (id) => {
    const out: Record<string, string> = {};
    for (const path of ["menu.html", "menu.js", "overlay.html", "save.html", "popup.html", "manifest.json"]) {
      try {
        const r = await fetch(`chrome-extension://${id}/${path}`);
        out[path] = `status ${r.status}`;
      } catch {
        out[path] = "blocked";
      }
    }
    return out;
  }, ext.id);
  for (const v of Object.values(results)) expect(v).toBe("blocked");
  // Nor can the page frame it to probe for the extension.
  await page.evaluate((id) => {
    const f = document.createElement("iframe");
    f.src = `chrome-extension://${id}/menu.html#AAAAAAAAAAAAAAAAAAAAAA`;
    document.body.appendChild(f);
  }, ext.id);
  await ext.settle(1500);
  const probe = page.frames().find((f) => f.parentFrame() === page.mainFrame() && !f.url().startsWith("chrome-extension://"));
  expect(probe?.url()).toMatch(/^chrome-error:/);
  expect(page.frames().filter((f) => new URL(f.url()).pathname === "/menu.html")).toHaveLength(0);
});

paired.describe("with the worker handle (e2e build)", () => {
  paired.use({ build: "e2e" });

  paired("S5_http_page_gets_nothing", async ({ ext }) => {
    const { page } = ext;
    await page.goto("http://atlas-cloud.test/login");
    await expect(page.locator("#email")).toBeVisible();
    await ext.settle(2000);
    // The content script does not run on HTTP: no icon, no menu, no overlay.
    await expect(page.locator("onepass-root")).toHaveCount(0);
    await page.locator("#email").focus();
    await page.keyboard.press("ArrowDown");
    await ext.settle(1000);
    expect(ext.findExtFrame(page, "menu")).toBeUndefined();
    await emptyFields(page, "#email", "#password");
    const w = await ext.worker();
    // The worker refuses a menu for an HTTP frame...
    const { tabId } = await tabOf(w, null);
    const menu = await routeAs(
      w,
      { type: "open_menu", fieldRef: "f1", formRef: "f2", formKind: "login" },
      { url: "http://atlas-cloud.test/login", origin: "http://atlas-cloud.test", tabId, frameId: 0 },
    );
    expect(menu).toEqual({ reply: { err: "insecure_origin" } });
    // ...and the host refuses the origin itself.
    const id = await itemId(w, ATLAS, "Atlas Cloud");
    expect(await hostRequest(w, { op: "list_for_origin", ctx: "menu", origin: "http://atlas-cloud.test" })).toEqual({
      err: "insecure_origin",
    });
    expect(
      await hostRequest(w, { op: "fill_login", ctx: "menu", item_id: id, origin: "http://atlas-cloud.test", fields: ["password"] }),
    ).toEqual({ err: "insecure_origin" });
  });

  paired("S9_navigation_between_request_and_fill_is_refused", async ({ ext }) => {
    const { page } = ext;
    await page.goto(`${ATLAS}/login`);
    const menu = await ext.openMenu(page, "#email");
    await expect(menu.locator("button.row").first()).toBeVisible();
    const token = new URL(menu.url()).hash.slice(1);
    const w = await ext.worker();
    const before = await tabOf(w, `${ATLAS}/*`);
    const id = await itemId(w, ATLAS, "Atlas Cloud");

    // The frame navigates (same origin, new document) before the pick lands.
    await page.goto(`${ATLAS}/login?next=1`);
    await expect(page.locator("onepass-root")).toHaveCount(1);
    const after = await tabOf(w, `${ATLAS}/*`);
    expect(after.documentId).not.toBe(before.documentId);

    // The old menu's pick: its token died with the document.
    const pick = await routeAs(w, { type: "menu_pick", token, itemId: id }, {
      url: `chrome-extension://${ext.id}/menu.html#${token}`,
      tabId: before.tabId,
      frameId: 0,
    });
    expect(pick).toEqual({ reply: { err: "invalid" } });

    // A fill bound to the old document, as if it was already in flight.
    const fill = await w.evaluate(
      async ({ tabId, documentId, id, origin }) => {
        const h = (globalThis as { __onepassE2E?: { filler: { fillLogin(t: unknown, i: string, f: string[]): Promise<void> } } }).__onepassE2E;
        try {
          await h?.filler.fillLogin({ tabId, frameId: 0, origin, documentId, formRef: "x" }, id, ["username", "password"]);
          return "filled";
        } catch (e) {
          return (e as { code?: string }).code ?? String(e);
        }
      },
      { tabId: before.tabId, documentId: before.documentId, id, origin: ATLAS },
    );
    expect(fill).toBe("origin_mismatch");
    await ext.settle(1000);
    await emptyFields(page, "#email", "#password");
    // No value was even asked of the host.
    expect(ext.audit()).not.toContain("fill_login");
  });

  paired("S14_compromised_content_script_cannot_get_other_site_item", async ({ ext }) => {
    const { page } = ext;
    await page.goto("https://atlass-cloud.test/login");
    await expect(page.locator("onepass-root")).toHaveCount(1);
    const w = await ext.worker();
    const { tabId, documentId } = await tabOf(w, "https://atlass-cloud.test/*");
    const atlasId = await itemId(w, ATLAS, "Atlas Cloud");

    // A compromised content script writes the victim's origin into its message:
    // the worker binds the token to the origin the browser reports (sender).
    const sender: ForgedSender = {
      url: "https://atlass-cloud.test/login",
      origin: "https://atlass-cloud.test",
      tabId,
      frameId: 0,
      ...(documentId ? { documentId } : {}),
    };
    const opened = await routeAs(
      w,
      { type: "open_menu", fieldRef: "f1", formRef: "f2", formKind: "login", origin: ATLAS, url: `${ATLAS}/login` },
      sender,
    );
    const url = ((opened as { reply: { ok: { url: string } } }).reply.ok ?? {}).url;
    const token = new URL(url).hash.slice(1);
    const rec = (await ext.sessionStorage())[`menu:${token}`] as { origin: string };
    expect(rec.origin).toBe("https://atlass-cloud.test");

    // Its menu lists nothing of atlas-cloud.test, and a pick of an atlas item is refused.
    const menuSender: ForgedSender = { url: `chrome-extension://${ext.id}/menu.html#${token}`, tabId, frameId: 0 };
    const init = await routeAs(w, { type: "menu_init", token }, menuSender);
    expect((init as { reply: { ok: { items: unknown[] } } }).reply.ok.items).toEqual([]);
    expect(await routeAs(w, { type: "menu_pick", token, itemId: atlasId }, menuSender)).toEqual({ reply: { err: "invalid" } });

    // The same request from the real content script world of that page.
    const real = await inContentScript(
      ext,
      page,
      `chrome.runtime.sendMessage({ type: "open_menu", fieldRef: "f1", formRef: "f2", formKind: "login", origin: "${ATLAS}" })`,
    );
    const realToken = new URL((real as { ok: { url: string } }).ok.url).hash.slice(1);
    expect(((await ext.sessionStorage())[`menu:${realToken}`] as { origin: string }).origin).toBe("https://atlass-cloud.test");

    // And the host redoes the match: origin_mismatch.
    expect(
      await hostRequest(w, { op: "fill_login", ctx: "menu", item_id: atlasId, origin: "https://atlass-cloud.test", fields: ["password"] }),
    ).toEqual({ err: "origin_mismatch" });
    await emptyFields(page, "#email", "#password");
  });

  paired("S15_reveal_and_search_refused_outside_popup", async ({ ext }) => {
    const { page } = ext;
    await page.goto(`${ATLAS}/login`);
    await expect(page.locator("onepass-root")).toHaveCount(1);
    const w = await ext.worker();
    const id = await itemId(w, ATLAS, "Atlas Cloud");
    const { tabId } = await tabOf(w, `${ATLAS}/*`);

    // From the real content script world: popup messages get no answer.
    const asCs = async (msg: string) =>
      inContentScript(
        ext,
        page,
        `chrome.runtime.sendMessage(${msg}).then((r) => ({ reply: r === undefined ? null : r }), (e) => ({ error: String(e) }))`,
      );
    for (const msg of [`{ type: "popup_reveal", itemId: "${id}" }`, `{ type: "popup_search", query: "Atlas" }`]) {
      const r = JSON.stringify(await asCs(msg));
      expect(r).not.toContain(FX.atlas.password);
      expect(r).not.toContain(FX.atlas.email);
      expect(r).not.toContain('"ok"');
    }
    // A forged content script sender: dropped without a reply.
    const sender: ForgedSender = { url: `${ATLAS}/login`, origin: ATLAS, tabId, frameId: 0 };
    expect(await routeAs(w, { type: "popup_reveal", itemId: id }, sender)).toEqual({ dropped: true });
    expect(await routeAs(w, { type: "popup_search", query: "Atlas" }, sender)).toEqual({ dropped: true });
    // The host refuses both outside the popup context.
    expect(await hostRequest(w, { op: "reveal", ctx: "menu", item_id: id, field: "password" })).toEqual({ err: "not_allowed" });
    expect(await hostRequest(w, { op: "search", ctx: "menu", query: "Atlas" })).toEqual({ err: "not_allowed" });
  });
});
