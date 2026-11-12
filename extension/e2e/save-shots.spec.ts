// Visual check of the save card on the real extension and host (not part of
// the suite): a new login, a password update, the vault chip opened, and the
// card stacked under another password manager's notification, in dark and
// light, French and English. Runs only with ONEPASS_E2E_SHOTS=<dir>:
//
//   ONEPASS_E2E_SHOTS=/tmp npx playwright test -c e2e/playwright.config.ts save-shots
//
// Test data only (the fixture vault and the local fictional sites).
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { type Ext, expect, paired } from "./fixtures";
import { FX } from "./server";

const OUT = process.env.ONEPASS_E2E_SHOTS;
const ATLAS = "https://atlas-cloud.test";

paired.skip(!OUT, "set ONEPASS_E2E_SHOTS to a directory");

async function signIn(page: Page, path: string, email: string, password: string): Promise<void> {
  await page.goto(`${ATLAS}${path}`);
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(password);
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText(/Connecté/);
}

async function signUp(page: Page, email: string, password: string): Promise<void> {
  await page.goto(`${ATLAS}/signup`);
  await page.locator("#email").fill(email);
  await page.locator("#new-password").fill(password);
  await page.locator("#confirm-password").fill(password);
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText(/Connecté/);
}

async function card(ext: Ext, page: Page, title: RegExp) {
  const save = await ext.extFrame(page, "save");
  await expect(save.getByText(title)).toBeVisible();
  // Past the reveal and the click guard.
  await ext.settle(700);
  return save;
}

function shots(lang: "fr" | "en") {
  const T =
    lang === "fr"
      ? { save: /^Login pour .* enregistré/, update: /^Mettre à jour le mot de passe pour/ }
      : { save: /^Login for .* saved/, update: /^Update password for/ };
  for (const scheme of ["dark", "light"] as const) {
    paired(`save_card_shots_${lang}_${scheme}`, async ({ ext }) => {
      const out = OUT ?? "";
      const { page } = ext;
      const name = (n: string) => join(out, `real-${n}-${scheme}${lang === "fr" ? "" : "-en"}.png`);
      await page.emulateMedia({ colorScheme: scheme });
      await page.setViewportSize({ width: 1100, height: 640 });

      // A login the vault does not know: OnePass saves it and says so in a toast.
      await signUp(page, `alex.${scheme}.${lang}@atlas.dev`, "Nouv-Pass-0043");
      let save = await card(ext, page, T.save);
      await page.screenshot({ path: name("save-new") });

      // A known login with a new password: the update card.
      await page.goto(`${ATLAS}/change-password`);
      await page.locator("#current-password").fill(FX.ops.password);
      await page.locator("#new-password").fill("Neuf-Pass-0077");
      await page.locator("#confirm-password").fill("Neuf-Pass-0077");
      await page.locator("#submit").click();
      await expect(page.locator("#status")).toHaveText("Mot de passe modifié");
      save = await card(ext, page, T.update);
      await page.screenshot({ path: name("save-update") });
      await save.getByRole("button", { name: lang === "fr" ? "Plus tard" : "Later" }).click();

      // Another password manager's notification in the same corner.
      await page.goto(`${ATLAS}/logout`);
      await signIn(page, "/login-other-manager", "alex.new@atlas.dev", "Nouv-Pass-0042");
      // Whatever the save frame shows (toast or card) sits beside the other manager.
      await ext.extFrame(page, "save");
      await ext.settle(1200);
      await page.screenshot({ path: name("beside-other-manager") });
    });
  }
}

shots("fr");
paired.describe("english", () => {
  paired.use({ uiLang: "en" });
  shots("en");
});

// ---- Fill UI pictures (glyph, ghost, preview menu, length panel, toast, update
// card, pill): each in a light and a dark browser theme, on a light and a dark
// page. The browser theme is the fixture's `scheme` (Chromium --force-dark-mode,
// which the extension frames follow); the page tone is a style the shot injects
// on the fixture page, so the frames are seen on both grounds.

const TONES = {
  light: "html, body { background: #ffffff !important; color: #1d1d1f !important; } label, h1, .brand { color: #1d1d1f !important; }",
  dark: "html, body { background: #17171a !important; color: #f2f2f4 !important; } label, h1, .brand { color: #f2f2f4 !important; }",
} as const;

async function tone(page: Page, which: keyof typeof TONES): Promise<void> {
  await page.addStyleTag({ content: TONES[which] });
}

for (const scheme of ["light", "dark"] as const) {
  paired.describe(`fill_ui_${scheme}`, () => {
    paired.use({ scheme });
    paired(`fill_ui_shots_${scheme}`, async ({ ext }) => {
      paired.setTimeout(420_000);
      const out = OUT ?? "";
      const { page } = ext;
      // Tall enough for the preview menu with its length panel and a longer login list.
      await page.setViewportSize({ width: 1000, height: 900 });
      const file = (n: string, ground: string) => join(out, `fill-${n}-browser-${scheme}-page-${ground}.png`);
      const ghostFrame = () => page.frames().find((f) => f.url().startsWith("chrome-extension://") && new URL(f.url()).pathname === "/ghost.html");

      // The update card needs the login's current password: it changes each round.
      let opsPassword: string = FX.ops.password;
      // Every document the page loads (also after a form post) gets the tone.
      let current: keyof typeof TONES = "light";
      page.on("domcontentloaded", () => void tone(page, current).catch(() => undefined));
      for (const ground of ["light", "dark"] as const) {
        current = ground;
        // Glyph at rest and with focus, on a login the vault knows.
        await page.goto(`${ATLAS}/logout`);
        await page.goto(`${ATLAS}/login`);
        await tone(page, ground);
        await expect(page.locator("onepass-root")).toHaveCount(1);
        await ext.settle(900);
        await page.screenshot({ path: file("glyph-rest", ground) });
        await page.locator("#email").click();
        await ext.settle(700);
        await page.screenshot({ path: file("glyph-focus", ground) });

        // Ghost with its pill, then the preview menu, then the length panel.
        await page.goto(`${ATLAS}/signup`);
        await tone(page, ground);
        await expect(page.locator("onepass-root")).toHaveCount(1);
        await page.locator("#new-password").click();
        await expect.poll(() => ghostFrame() !== undefined, { timeout: 15_000, message: "ghost frame" }).toBe(true);
        await ext.settle(900);
        await page.screenshot({ path: file("ghost-pill", ground) });
        await page.keyboard.press("ArrowDown");
        const menu = await ext.extFrame(page, "menu");
        await menu.locator(".length-toggle").waitFor({ timeout: 10_000 });
        await ext.settle(700);
        await page.screenshot({ path: file("preview-menu", ground) });
        await menu.locator(".length-toggle").click();
        await expect(menu.locator("#length-panel")).toBeVisible();
        await ext.settle(500);
        await page.screenshot({ path: file("length-panel", ground) });
        await page.keyboard.press("Escape");

        // The toast of a login saved by itself.
        await page.goto(`${ATLAS}/logout`);
        await signInTone(ext, page, ground, `alex.${scheme}${ground}@atlas.dev`);
        await ext.settle(900);
        await page.screenshot({ path: file("toast", ground) });

        // The update card, then the pill it folds into.
        await page.goto(`${ATLAS}/change-password`);
        await tone(page, ground);
        const next = `Neuf-Pass-${scheme}${ground}-77`;
        await page.locator("#current-password").fill(opsPassword);
        await page.locator("#new-password").fill(next);
        await page.locator("#confirm-password").fill(next);
        opsPassword = next;
        await page.locator("#submit").click();
        await expect(page.locator("#status")).toHaveText("Mot de passe modifié");
        const save = await card(ext, page, /^Mettre à jour le mot de passe pour/);
        await page.screenshot({ path: file("update-card", ground) });
        await save.getByRole("button", { name: "Plus tard" }).click();
        await ext.settle(900);
        await page.screenshot({ path: file("pill", ground) });
        // Close the pill so the next round starts clean.
        await (await ext.extFrame(page, "save")).locator(".save-pill button").last().click();
        await ext.settle(500);
      }
    });
  });
}

async function signInTone(ext: Ext, page: Page, ground: keyof typeof TONES, email: string): Promise<void> {
  await page.goto(`${ATLAS}/signup`);
  await tone(page, ground);
  await page.locator("#email").fill(email);
  await page.locator("#new-password").fill("Nouv-Pass-0043");
  await page.locator("#confirm-password").fill("Nouv-Pass-0043");
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText(/Connecté/);
  const save = await ext.extFrame(page, "save");
  await expect(save.locator(".save-toast")).toBeVisible({ timeout: 15_000 });
}
