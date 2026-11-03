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

paired("smart_fill_signup_generates_password_never_submits_then_saves_it", async ({ ext }) => {
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
  // The generated password was saved as a pending Login before the submit
  // (save-before-submit): the submission confirms that item, with the
  // submitted address, and asks nothing.
  const saved = audited(ext, "save_login");
  expect(saved).toHaveLength(1);
  await expect.poll(() => audited(ext, "confirm_pending").length, { timeout: 15_000 }).toBe(1);
  expect(audited(ext, "confirm_pending")[0]?.item_id).toBe(saved[0]?.item_id);
  await ext.settle(1500);
  expect(page.frames().some((f) => f.url().startsWith("chrome-extension://") && f.url().includes("/save.html"))).toBe(false);
});

paired("smart_fill_two_accounts_menu_then_remembered", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/multistep`);
  // Two accounts on the site and no memory: the menu, best first.
  await clickIcon(ext, page, "#email");
  const menu = await ext.extFrame(page, "menu");
  await menu.waitForLoadState("domcontentloaded");
  expect(audited(ext, "plan_fill").at(-1)).toMatchObject({ action: "show_menu" });
  // The pick signs in to the end (identifier, password, code), and the chain notes it at its end.
  await ext.pickRow(menu, "Atlas Cloud", FX.atlas.email);
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect.poll(async () => (await ext.chainState())?.status, { timeout: 20_000 }).toBe("done");
  await expect.poll(() => audited(ext, "note_fill").length, { timeout: 10_000 }).toBe(1);
  await page.goto(`${ATLAS}/logout`);

  // Next time: the same account, no menu.
  await page.goto(`${ATLAS}/multistep`);
  await clickIcon(ext, page, "#email");
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText(FX.atlas.email);
  expect(audited(ext, "plan_fill").at(-1)).toMatchObject({ action: "open_chain", confidence: "high" });
  expect(ext.findExtFrame(page, "menu")).toBeUndefined();
});

// One-click signup (2026-11-02): a form that can make a passkey asks first.

/** The menu's signup row (`password` or `passkey`), clicked past its click guard. */
async function pickSignup(ext: Ext, page: Page, mode: "password" | "passkey"): Promise<void> {
  const menu = await ext.extFrame(page, "menu");
  const row = menu.locator(`button.row[data-signup="${mode}"]`);
  await expect(row).toHaveCount(1);
  await ext.settle();
  for (let attempt = 0; attempt < 6; attempt++) {
    if (menu.isDetached()) return;
    await row.click({ timeout: 5_000 }).catch(() => undefined);
    const closed = await row
      .waitFor({ state: "detached", timeout: 1_000 })
      .then(() => true)
      .catch(() => menu.isDetached());
    if (closed) return;
    await ext.settle();
  }
}

paired("smart_fill_signup_with_passkey_asks_then_fills_with_a_password", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/signup-passkey`);
  const submits = await countSubmits(page);
  await clickIcon(ext, page, "#new-password");
  // Asked first: nothing written before the choice.
  const menu = await ext.extFrame(page, "menu");
  await expect(menu.locator('button.row[data-signup="passkey"]')).toHaveCount(1);
  await expect(page.locator("#new-password")).toHaveValue("");
  expect(audited(ext, "plan_fill").at(-1)).toMatchObject({ intent: "signup", action: "fill" });
  await pickSignup(ext, page, "password");
  await expect(page.locator("#new-password")).not.toHaveValue("", { timeout: 15_000 });
  const pw = await page.locator("#new-password").inputValue();
  await expect(page.locator("#confirm-password")).toHaveValue(pw);
  await expect(page.locator("#email")).toHaveValue(FX.identity.email);
  await expect(page.locator("#given-name")).toHaveValue(FX.identity.given);
  await ext.settle(1500);
  expect(await submits()).toBe(0);
  await expect(page.locator("#result")).not.toHaveAttribute("data-status", /.+/);
  expect(page.url()).toBe(`${ATLAS}/signup-passkey`);
});

paired("smart_fill_signup_passkey_choice_opens_the_onepass_window", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/signup-passkey`);
  const submits = await countSubmits(page);
  await clickIcon(ext, page, "#email");
  const opened = ext.context.waitForEvent("page", { predicate: (p) => /\/passkey\.html#[A-Za-z0-9_-]{22}$/.test(p.url()), timeout: 20_000 });
  await pickSignup(ext, page, "passkey");
  // The identity, then the site's own passkey button: OnePass's window asks.
  const win = await opened;
  await expect(win.getByRole("heading", { name: "Enregistrer une passkey" })).toBeVisible();
  await expect(win.getByText(FX.identity.email)).toBeVisible();
  await expect(page.locator("#email")).toHaveValue(FX.identity.email);
  // No password made, nothing created before the user's click in the window.
  await expect(page.locator("#new-password")).toHaveValue("");
  expect(ext.audit()).not.toContain("passkey_create");
  await ext.settle();
  await win.getByRole("button", { name: "Enregistrer", exact: true }).click();
  await expect(page.locator("#result")).toHaveAttribute("data-status", "Créée", { timeout: 15_000 });
  expect(ext.audit()).toContain("passkey_create");
  expect(await submits()).toBe(0);
});
