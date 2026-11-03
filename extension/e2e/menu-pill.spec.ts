// The founder's report of 2026-11-03 (accounts.google.com, macOS in dark
// mode), one test per bug, on the local pages with fictional data:
// - "Remplir" filled one page only (the identifier, or just the password):
//   on a sign-in form it now runs the sign-in to its end, code included;
// - the pill's other accounts were unreachable (their chevron sat, hidden,
//   under the close button in the pill's corner);
// - a page that declares a light scheme turned the menu light on a dark Mac,
//   and painted an opaque white backdrop under the dark pill (the white line).
import type { Page } from "@playwright/test";
import { expect, paired } from "./fixtures";
import { readPng } from "./png";
import { FX } from "./server";

const ATLAS = "https://atlas-cloud.test";

paired("menu_fill_runs_a_multistep_signin_to_the_end", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/multistep`);
  const menu = await ext.openMenu(page, "#email");
  await ext.pickRow(menu, "Atlas Cloud");
  // Identifier, then password, then the TOTP code: one pick.
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText(FX.atlas.email);
});

paired("menu_fill_on_the_password_step_finishes_with_the_code", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/multistep`);
  await page.locator("#email").fill(FX.atlas.email);
  await page.locator("#next").click();
  await expect(page).toHaveURL(`${ATLAS}/multistep/password`);
  const menu = await ext.openMenu(page, "#password");
  await ext.pickRow(menu, "Atlas Cloud");
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
});

paired("menu_fill_on_google_identifier_goes_through_the_password_page", async ({ ext }) => {
  const { page } = ext;
  await page.goto("https://accounts.google.com/signin/identifier");
  const menu = await ext.openMenu(page, "#identifier-email");
  await ext.pickRow(menu, "Google perso");
  // The identifier page, then the password page: Google accepted the account.
  await expect.poll(() => ext.server.providerSignIns, { timeout: 30_000 }).toEqual([FX.googlePerso.email]);
});

paired("pill_other_accounts_are_reachable", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/login`);
  const overlay = await ext.extFrame(page, "overlay");
  const more = overlay.locator(".ov-more");
  await expect(more).toHaveCount(1);
  await ext.settle();
  // Shown without hovering, and not under the close button.
  const look = await more.evaluate((el) => {
    const close = el.closest(".ov-shell")?.querySelector(".ov-close");
    const a = el.getBoundingClientRect();
    const b = close?.getBoundingClientRect();
    const over = b ? !(a.right <= b.left || b.right <= a.left || a.bottom <= b.top || b.bottom <= a.top) : false;
    return { opacity: getComputedStyle(el).opacity, over, width: a.width };
  });
  expect(look).toEqual({ opacity: "1", over: false, width: 30 });
  await more.click();
  await ext.overlayStart(page, "Atlas Cloud (multi)");
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText(FX.ops.email);
});

/** Atlas pages, dark, that declare only a light scheme (as some sign-in pages do). */
async function lightDeclaredDarkPage(page: Page) {
  await page.addInitScript(() => {
    if (location.hostname !== "atlas-cloud.test") return;
    const add = () => {
      if (!document.head) return false;
      const meta = document.createElement("meta");
      meta.name = "color-scheme";
      meta.content = "light";
      const style = document.createElement("style");
      style.textContent = "html, body { background: #202124 !important; color: #e8eaed; }";
      document.head.prepend(meta, style);
      return true;
    };
    if (!add()) new MutationObserver((_, o) => add() && o.disconnect()).observe(document, { childList: true, subtree: true });
  });
}

paired.describe("dark system", () => {
  paired.use({ scheme: "dark" });

  paired("menu_follows_a_dark_system_on_a_page_declaring_light", async ({ ext }) => {
    const { page } = ext;
    await lightDeclaredDarkPage(page);
    await page.goto(`${ATLAS}/checkout`);
    expect(await page.evaluate(() => matchMedia("(prefers-color-scheme: dark)").matches), "system in dark mode").toBe(true);
    const menu = await ext.openMenu(page, "#cc-number");
    await menu.locator(".menu").waitFor();
    expect(await menu.evaluate(() => matchMedia("(prefers-color-scheme: dark)").matches)).toBe(true);
    const bg = await menu.evaluate(() => getComputedStyle(document.body).backgroundColor);
    // The inset list's grouped background, dark.
    expect(bg).toBe("rgb(28, 28, 30)");
  });

  paired("pill_has_no_light_backdrop_on_a_page_declaring_light", async ({ ext }) => {
    const { page } = ext;
    await lightDeclaredDarkPage(page);
    await page.goto(`${ATLAS}/login`);
    const overlay = await ext.extFrame(page, "overlay");
    await ext.settle(1500);
    // The frame sits in a closed shadow root: its owner element, through the protocol.
    const box = (await (await overlay.frameElement()).boundingBox())!;
    const shot = readPng(await page.screenshot({ clip: box }));
    // The transparent frame around the capsule shows the dark page (#202124), and the
    // capsule is dark: its edge left of the icon, the corners and along the bottom of the frame.
    const samples = [
      shot.at(16, 36),
      shot.at(2, 2),
      shot.at(shot.width - 2, 2),
      ...[0.3, 0.5, 0.7].map((f) => shot.at(Math.floor(shot.width * f), shot.height - 2)),
    ];
    for (const [r, g, b] of samples) expect(Math.max(r, g, b), `frame pixel ${r},${g},${b}`).toBeLessThanOrEqual(60);
  });
});
