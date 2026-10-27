// Visual check on the real extension and host (not part of the suite): the
// popup, the in-field icon and the inline menu anchored to its field, the
// save prompt, in dark and light. Runs only with ONEPASS_E2E_SHOTS=<dir>:
//
//   ONEPASS_E2E_SHOTS=/tmp npx playwright test -c e2e/playwright.config.ts shots
import { join } from "node:path";
import { expect, paired } from "./fixtures";

const OUT = process.env.ONEPASS_E2E_SHOTS;
const ATLAS = "https://atlas-cloud.test";

paired.skip(!OUT, "set ONEPASS_E2E_SHOTS to a directory");

for (const scheme of ["dark", "light"] as const) {
  paired(`shots_${scheme}`, async ({ ext }) => {
    const out = OUT ?? "";
    const { page } = ext;
    await page.emulateMedia({ colorScheme: scheme });

    // Inline menu under the email field of the login page.
    await page.setViewportSize({ width: 900, height: 620 });
    await page.goto(`${ATLAS}/login`);
    const menu = await ext.openMenu(page, "#email");
    await expect(menu.locator(".menu-head")).toContainText("atlas-cloud.test");
    await ext.settle();
    await page.screenshot({ path: join(out, `onepass-ext-inline-menu-${scheme}.png`) });

    // Fill from the menu, then the field icons on a filled form.
    await ext.pickRow(menu, "Atlas Cloud");
    await expect(page.locator("#password")).not.toHaveValue("");
    await page.screenshot({ path: join(out, `onepass-ext-filled-${scheme}.png`) });

    // The popup page on the same tab context.
    const popup = await ext.context.newPage();
    await popup.emulateMedia({ colorScheme: scheme });
    await popup.setViewportSize({ width: 780, height: 600 });
    await popup.goto(`chrome-extension://${ext.id}/popup.html`);
    await expect(popup.getByPlaceholder("Rechercher dans OnePass")).toBeVisible();
    // Opened as a tab, the popup has no site of its own: search instead.
    await popup.getByPlaceholder("Rechercher dans OnePass").fill("Atlas");
    const first = popup.locator(".pp-list button.row").first();
    await first.click();
    await expect(popup.locator(".pp-detail")).toBeVisible();
    await popup.waitForTimeout(400);
    await popup.screenshot({ path: join(out, `onepass-ext-popup-${scheme}.png`) });
    await popup.close();
  });
}
