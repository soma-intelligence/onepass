// Two-factor setup from a QR code, end to end (plan 2026-11-13, wave 0-1, Task 10): the
// popup's "Scan 2FA QR code" button, the scan of the Atlas pages (/2fa/*), the card in the
// page, the save through the real native host and the fixture vault, the code filled (never
// submitted) and the recovery codes the site then shows.
//
// Capture cases: headless Chromium never grants `activeTab` and no permission is added for
// the tests, so `chrome.tabs.captureVisibleTab` is stubbed in the worker with a real
// screenshot of the tab (setup-helpers.ts `stubCapture`). The decode of that capture, the card
// and the save are real. The real grant is checked by hand.
import { expect, paired } from "./fixtures";
import { FX } from "./server";
import {
  ATLAS,
  L,
  cardClick,
  clickScan,
  findSetupFrame,
  focusedText,
  hasField,
  itemId,
  recordWrites,
  setupCodes,
  setupFrame,
  siteHits,
  stubCapture,
  writes,
} from "./setup-helpers";

paired.use({ uiLang: "en" });

const OPS = "Atlas Cloud (multi)";

paired("img: scan, Add, the code field holds 6 digits, the form is not submitted", async ({ ext }) => {
  const { page, server } = ext;
  await page.goto(`${ATLAS}/2fa/img`);
  await expect(page.locator("onepass-root")).toHaveCount(1);
  await clickScan(ext, page);
  const card = await setupFrame(page);
  await expect(card.getByText(L.title(OPS))).toBeVisible();
  await expect(card.getByText(`Atlas Cloud, ${FX.ops.email}`)).toBeVisible();
  expect(await focusedText(card)).toBe(L.add);
  await cardClick(ext, card, L.add);
  await expect(card.getByText(L.saved)).toBeVisible();
  await expect(page.locator("#code")).toHaveValue(/^\d{6}$/);
  expect(setupCodes()).toContain(await page.locator("#code").inputValue());
  // Filled, never sent: same page, no POST.
  await ext.settle(1000);
  expect(new URL(page.url()).pathname).toBe("/2fa/img");
  expect(siteHits(server).filter((h) => h.method === "POST")).toEqual([]);
});

for (const kind of ["canvas", "svg", "background"] as const) {
  paired(`canvas, inline svg and CSS background are each decoded from the page (${kind})`, async ({ ext }) => {
    const { page } = ext;
    await page.goto(`${ATLAS}/2fa/${kind}`);
    await expect(page.locator("onepass-root")).toHaveCount(1);
    if (kind === "canvas") await expect(page.locator("#qr")).toHaveAttribute("data-drawn", "1");
    await clickScan(ext, page);
    const card = await setupFrame(page);
    // Read from the page itself: no capture (none is granted headless, none is stubbed here).
    await expect(card.getByText(L.title(OPS))).toBeVisible();
    await cardClick(ext, card, L.add);
    await expect(card.getByText(L.saved)).toBeVisible();
    await expect(page.locator("#code")).toHaveValue(/^\d{6}$/);
  });
}

for (const kind of ["frame", "tainted"] as const) {
  paired(
    `cross-origin frame and tainted canvas are decoded from the capture (${kind}; capture stubbed, activeTab not grantable headless)`,
    async ({ ext }) => {
      const { page } = ext;
      await page.goto(`${ATLAS}/2fa/${kind}`);
      await expect(page.locator("onepass-root")).toHaveCount(1);
      if (kind === "frame") await expect(page.frameLocator("#qr").locator("img")).toBeVisible();
      else await expect(page.locator("#qr")).toHaveAttribute("data-drawn", "1");
      await stubCapture(ext, page);
      await clickScan(ext, page);
      const card = await setupFrame(page);
      await expect(card.getByText(L.title(OPS))).toBeVisible();
      await cardClick(ext, card, L.add);
      await expect(card.getByText(L.saved)).toBeVisible();
      await expect(page.locator("#code")).toHaveValue(/^\d{6}$/);
    },
  );
}

paired("without a capture, a QR the page cannot read leaves the paste card", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/2fa/frame`);
  await expect(page.frameLocator("#qr").locator("img")).toBeVisible();
  // No stub: the capture is refused headless (no activeTab), as when the grant is missing.
  const popup = await clickScan(ext, page);
  const card = await setupFrame(page);
  await expect(card.getByText(L.paste)).toBeVisible();
  if (!popup.isClosed()) await expect(popup.getByText(L.none)).toBeVisible();
});

paired(
  "a capture at deviceScaleFactor 3 is decoded (capture stubbed, activeTab not grantable headless)",
  async ({ ext }) => {
    const { page } = ext;
    const cdp = await ext.context.newCDPSession(page);
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 860, deviceScaleFactor: 3, mobile: false });
    await page.goto(`${ATLAS}/2fa/hidpi`);
    await expect(page.locator("onepass-root")).toHaveCount(1);
    await expect(page.locator("#qr-host")).toHaveAttribute("data-drawn", "1");
    expect(await page.evaluate(() => devicePixelRatio)).toBe(3);
    const shot = await stubCapture(ext, page, cdp);
    // Over 10 megapixels, as a Retina capture of a large window.
    expect(shot.width * shot.height).toBeGreaterThan(9_000_000);
    await clickScan(ext, page);
    const card = await setupFrame(page);
    await expect(card.getByText(L.title(OPS))).toBeVisible();
    await cardClick(ext, card, L.add);
    await expect(card.getByText(L.saved)).toBeVisible();
    await expect(page.locator("#code")).toHaveValue(/^\d{6}$/);
    await cdp.detach();
  },
);

paired.describe("with the worker handle (e2e build)", () => {
  paired.use({ build: "e2e" });

  paired("after the user's own click on Verify, the recovery codes card appears and saves 10 codes", async ({ ext }) => {
    const { page } = ext;
    const w = await ext.worker();
    await recordWrites(w);
    const ops = await itemId(w, OPS);
    expect(await hasField(w, ops, "recovery_codes")).toBe(false);
    await page.goto(`${ATLAS}/2fa/img`);
    await expect(page.locator("onepass-root")).toHaveCount(1);
    await clickScan(ext, page);
    const card = await setupFrame(page);
    await cardClick(ext, card, L.add);
    await expect(card.getByText(L.saved)).toBeVisible();
    await expect(page.locator("#code")).toHaveValue(/^\d{6}$/);
    // The user presses the site's button: the site checks the code and shows its codes.
    await page.locator("#submit").click();
    await expect(page.locator("#codes li")).toHaveCount(10);
    const codes = await setupFrame(page);
    await expect(codes.getByText(L.codesTitle(10, OPS))).toBeVisible();
    expect(await focusedText(codes)).toBe(L.save);
    await cardClick(ext, codes, L.save);
    await expect.poll(() => findSetupFrame(page) === undefined).toBe(true);
    expect(await writes(w)).toEqual([
      { op: "save_totp", status: "saved" },
      { op: "save_recovery_codes", status: "ok", count: 10 },
    ]);
    expect(await hasField(w, ops, "recovery_codes")).toBe(true);
  });

  paired("a login that already has another code asks to replace, Cancel focused; Replace keeps previous_otp_1", async ({ ext }) => {
    const { page } = ext;
    const w = await ext.worker();
    await recordWrites(w);
    const atlas = await itemId(w, "Atlas Cloud");
    expect(await hasField(w, atlas, "previous_otp_1")).toBe(false);
    await page.goto(`${ATLAS}/2fa/img?for=alex`);
    await expect(page.locator("onepass-root")).toHaveCount(1);
    await clickScan(ext, page);
    const card = await setupFrame(page);
    await expect(card.getByText(L.title("Atlas Cloud"))).toBeVisible();
    await cardClick(ext, card, L.add);
    await expect(card.getByText(L.replaceTitle("Atlas Cloud"))).toBeVisible();
    expect(await focusedText(card)).toBe(L.cancel);
    // Nothing written yet: the old code is still the one.
    expect(await hasField(w, atlas, "previous_otp_1")).toBe(false);
    await cardClick(ext, card, L.replace);
    await expect(card.getByText(L.saved)).toBeVisible();
    expect(setupCodes()).toContain(await page.locator("#code").inputValue());
    expect(await writes(w)).toEqual([
      { op: "save_totp", status: "exists" },
      { op: "save_totp", status: "replaced" },
    ]);
    expect(await hasField(w, atlas, "previous_otp_1")).toBe(true);
    expect(await hasField(w, atlas, "previous_otp_2")).toBe(false);
  });

  paired("the same secret scanned twice writes nothing and fills the code", async ({ ext }) => {
    const { page } = ext;
    const w = await ext.worker();
    await recordWrites(w);
    const ops = await itemId(w, OPS);
    await page.goto(`${ATLAS}/2fa/img`);
    await expect(page.locator("onepass-root")).toHaveCount(1);
    await clickScan(ext, page);
    let card = await setupFrame(page);
    await cardClick(ext, card, L.add);
    await expect(card.getByText(L.saved)).toBeVisible();
    await cardClick(ext, card, "Close");
    await expect.poll(() => findSetupFrame(page) === undefined).toBe(true);
    await page.locator("#code").fill("");
    // Scanned again: the login already holds this very seed.
    await clickScan(ext, page);
    card = await setupFrame(page);
    await cardClick(ext, card, L.add);
    await expect(card.getByText(L.saved)).toBeVisible();
    await expect(page.locator("#code")).toHaveValue(/^\d{6}$/);
    expect(setupCodes()).toContain(await page.locator("#code").inputValue());
    expect(await writes(w)).toEqual([
      { op: "save_totp", status: "saved" },
      { op: "save_totp", status: "same" },
    ]);
    expect(await hasField(w, ops, "previous_otp_1")).toBe(false);
  });
});

paired("no QR: the paste card saves a pasted key", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/2fa/manual`);
  await expect(page.locator("onepass-root")).toHaveCount(1);
  const key = (await page.locator("#key").textContent()) ?? "";
  const popup = await clickScan(ext, page);
  const card = await setupFrame(page);
  await expect(card.getByText(L.paste)).toBeVisible();
  if (!popup.isClosed()) await expect(popup.getByText(L.none)).toBeVisible();
  const field = card.locator("input.sc-key");
  await expect(field).toBeFocused();
  await field.fill(key);
  await cardClick(ext, card, L.add);
  // The key left the field for the worker; the card now asks which login gets it.
  await expect(card.getByRole("listbox")).toBeVisible();
  await ext.settle();
  await card.getByRole("option", { name: new RegExp(OPS.replace(/[()]/g, "\\$&")) }).click();
  await cardClick(ext, card, L.add);
  await expect(card.getByText(L.saved)).toBeVisible();
  await expect(page.locator("#code")).toHaveValue(/^\d{6}$/);
  expect(setupCodes()).toContain(await page.locator("#code").inputValue());
});

paired("decoy QR for another account: mismatch line, Cancel focused", async ({ ext }) => {
  const { page, server } = ext;
  await page.goto(`${ATLAS}/2fa/decoy`);
  await expect(page.locator("onepass-root")).toHaveCount(1);
  await clickScan(ext, page);
  const card = await setupFrame(page);
  await expect(card.getByText(/^The code is for pat@atlas\.dev\. This login is /)).toBeVisible();
  expect(await focusedText(card)).toBe(L.cancel);
  await cardClick(ext, card, L.cancel);
  await expect.poll(() => findSetupFrame(page) === undefined).toBe(true);
  await expect(page.locator("#code")).toHaveValue("");
  expect(siteHits(server).filter((h) => h.method === "POST")).toEqual([]);
});
