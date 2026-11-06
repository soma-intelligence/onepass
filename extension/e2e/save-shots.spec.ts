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
      ? { save: /^Enregistrer le login pour/, update: /^Mettre à jour le mot de passe pour/, chip: /^Coffre : / }
      : { save: /^Save login for/, update: /^Update password for/, chip: /^Vault: / };
  for (const scheme of ["dark", "light"] as const) {
    paired(`save_card_shots_${lang}_${scheme}`, async ({ ext }) => {
      const out = OUT ?? "";
      const { page } = ext;
      const name = (n: string) => join(out, `real-${n}-${scheme}${lang === "fr" ? "" : "-en"}.png`);
      await page.emulateMedia({ colorScheme: scheme });
      await page.setViewportSize({ width: 1100, height: 640 });

      // A login the vault does not know.
      await signIn(page, "/login", "alex.new@atlas.dev", "Nouv-Pass-0042");
      let save = await card(ext, page, T.save);
      await page.screenshot({ path: name("save-new") });
      const chip = save.getByRole("button", { name: T.chip });
      if ((await chip.count()) > 0) {
        await chip.click();
        await ext.settle(500);
        await page.screenshot({ path: name("save-vaults") });
        await chip.click();
        await ext.settle(400);
      }
      await save.getByRole("button", { name: lang === "fr" ? "Pas maintenant" : "Not now" }).click();

      // A known login with a new password: the update card.
      await page.goto(`${ATLAS}/change-password`);
      await page.locator("#current-password").fill(FX.ops.password);
      await page.locator("#new-password").fill("Neuf-Pass-0077");
      await page.locator("#confirm-password").fill("Neuf-Pass-0077");
      await page.locator("#submit").click();
      await expect(page.locator("#status")).toHaveText("Mot de passe modifié");
      save = await card(ext, page, T.update);
      await page.screenshot({ path: name("save-update") });
      await save.getByRole("button", { name: lang === "fr" ? "Pas maintenant" : "Not now" }).click();

      // Another password manager's notification in the same corner.
      await page.goto(`${ATLAS}/logout`);
      await signIn(page, "/login-other-manager", "alex.new@atlas.dev", "Nouv-Pass-0042");
      await card(ext, page, T.save);
      await page.screenshot({ path: name("beside-other-manager") });
    });
  }
}

shots("fr");
paired.describe("english", () => {
  paired.use({ uiLang: "en" });
  shots("en");
});
