// Smart fill end to end (Task 10): a trusted click on a field's OnePass icon
// plans the page through the real native host (fixture vault) and runs the
// plan. The icon lives in a closed shadow root: it is clicked where it is
// drawn, with the mouse (a trusted click, as a user's).
import type { Page } from "@playwright/test";
import { type Ext, expect, paired } from "./fixtures";
import { FX } from "./server";

const ATLAS = "https://atlas-cloud.test";
/** content/icon.ts: a 20 px icon, 6 px inside the field's right edge. */
const ICON_CENTER_FROM_RIGHT = 6 + 10;

/** Clicks the OnePass icon of `selector` (a trusted mouse click on its drawn position). */
async function clickIcon(ext: Ext, page: Page, selector: string): Promise<void> {
  await expect(page.locator("onepass-root")).toHaveCount(1);
  const field = page.locator(selector);
  await expect(field).toBeVisible();
  // The analysis runs after the load (and a mutation burst): its icon follows.
  await ext.settle(600);
  const box = await field.boundingBox();
  if (!box) throw new Error(`no box for ${selector}`);
  await page.mouse.click(box.x + box.width - ICON_CENTER_FROM_RIGHT, box.y + box.height / 2);
}

/** Lines of the host's audit journal for `op` (no value in them). */
function audited(ext: Ext, op: string): Record<string, unknown>[] {
  return ext
    .audit()
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .filter((e) => e.op === op);
}

/** Counts the page's submit events (a plan must not send these forms). */
async function countSubmits(page: Page): Promise<() => Promise<number>> {
  await page.evaluate(() => {
    (window as unknown as { __submits: number }).__submits = 0;
    document.addEventListener("submit", () => void ((window as unknown as { __submits: number }).__submits += 1), true);
  });
  return () => page.evaluate(() => (window as unknown as { __submits: number }).__submits);
}

paired("smart_fill_two_step_sign_in_in_one_click", async ({ ext }) => {
  const { page } = ext;
  // The site knows this account (a first sign-in noted it), then signs out.
  await page.goto(`${ATLAS}/multistep`);
  await ext.overlayStart(page, "Atlas Cloud");
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect.poll(async () => (await ext.chainState())?.status, { timeout: 20_000 }).toBe("done");
  await expect.poll(() => audited(ext, "note_fill").length, { timeout: 10_000 }).toBe(1);
  await page.goto(`${ATLAS}/logout`);

  // One click on the identifier's icon: identifier, password and code, to the signed-in page.
  await page.goto(`${ATLAS}/multistep`);
  await clickIcon(ext, page, "#email");
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText(FX.atlas.email);
  await expect.poll(async () => (await ext.chainState())?.status, { timeout: 20_000 }).toBe("done");
  const plans = audited(ext, "plan_fill");
  expect(plans.at(-1)).toMatchObject({ intent: "login", action: "open_chain", confidence: "high" });
  // No menu was needed.
  expect(ext.findExtFrame(page, "menu")).toBeUndefined();
});

paired("smart_fill_checkout_fills_card_identity_email_never_pays", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/checkout-full`);
  const submits = await countSubmits(page);
  await clickIcon(ext, page, "#cc-number");
  await expect(page.locator("#cc-number")).toHaveValue(/4242\s?4242\s?4242\s?4242/, { timeout: 15_000 });
  await expect(page.locator("#cc-name")).toHaveValue(FX.card.holder);
  await expect(page.locator("#given-name")).toHaveValue(FX.identity.given);
  await expect(page.locator("#family-name")).toHaveValue(FX.identity.family);
  await expect(page.locator("#email")).toHaveValue(FX.identity.email);
  await ext.settle(1500);
  expect(await submits()).toBe(0);
  expect(page.url()).toBe(`${ATLAS}/checkout-full`);
  expect(ext.server.captured.filter((c) => c.path === "/checkout-full")).toEqual([]);
  expect(audited(ext, "plan_fill").at(-1)).toMatchObject({ intent: "checkout", action: "fill" });
});

paired("smart_fill_signup_generates_password_never_submits_then_offers_save", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/signup`);
  const submits = await countSubmits(page);
  await clickIcon(ext, page, "#new-password");
  await expect(page.locator("#new-password")).not.toHaveValue("", { timeout: 15_000 });
  const pw = await page.locator("#new-password").inputValue();
  await expect(page.locator("#confirm-password")).toHaveValue(pw);
  // The identifier field (autocomplete=username) gets the identity's e-mail.
  await expect(page.locator("#email")).toHaveValue(FX.identity.email);
  await ext.settle(1500);
  expect(await submits()).toBe(0);
  expect(page.url()).toBe(`${ATLAS}/signup`);
  expect(audited(ext, "plan_fill").at(-1)).toMatchObject({ intent: "signup", action: "fill" });
  // That address already has an account here: the user types another one and sends the form.
  await page.locator("#email").fill("new.user@atlas.dev");
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 15_000 });
  const save = await ext.extFrame(page, "save");
  await expect(save.locator("body")).toContainText("Enregistrer le login", { timeout: 15_000 });
  await expect(save.locator("body")).toContainText("new.user@atlas.dev");
});

paired("smart_fill_two_accounts_menu_then_remembered", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/multistep`);
  // Two accounts on the site and no memory: the menu, best first.
  await clickIcon(ext, page, "#email");
  const menu = await ext.extFrame(page, "menu");
  await menu.waitForLoadState("domcontentloaded");
  expect(audited(ext, "plan_fill").at(-1)).toMatchObject({ action: "show_menu" });
  await ext.pickRow(menu, "Atlas Cloud", FX.atlas.email);
  await expect(page.locator("#email")).toHaveValue(FX.atlas.email);
  // The user sends the identifier: the page moves on, the pick is noted.
  await page.locator("#next").click();
  await expect(page).toHaveURL(`${ATLAS}/multistep/password`);
  await expect.poll(() => audited(ext, "note_fill").length, { timeout: 10_000 }).toBe(1);
  // One click on the password page: the remembered account, the chain to the end (done).
  await clickIcon(ext, page, "#password");
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect.poll(async () => (await ext.chainState())?.status, { timeout: 20_000 }).toBe("done");
  await page.goto(`${ATLAS}/logout`);

  // Next time: the same account, no menu.
  await page.goto(`${ATLAS}/multistep`);
  await clickIcon(ext, page, "#email");
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText(FX.atlas.email);
  expect(audited(ext, "plan_fill").at(-1)).toMatchObject({ action: "open_chain", confidence: "high" });
  expect(ext.findExtFrame(page, "menu")).toBeUndefined();
});
