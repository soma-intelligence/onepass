// Visual check on the real extension and host (not part of the suite): the
// popup, the in-field icon and the inline menu anchored to its field, the
// save prompt, and every state of signing in with a provider (menu, account
// picker, offer, progress, success, stops, link prompt), in dark and light.
// Runs only with ONEPASS_E2E_SHOTS=<dir>:
//
//   ONEPASS_E2E_SHOTS=/tmp npx playwright test -c e2e/playwright.config.ts shots
//
// Real provider pages are never reached: accounts.google.com is the local,
// fictional chooser of server.ts. A provider page answers "204 No Content"
// once (page.route), so a running chain waits mid-step for its picture.
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { END_SHOWN_MS } from "../src/background/chain/driver";
import { type Ext, expect, paired } from "./fixtures";
import { FX } from "./server";

const OUT = process.env.ONEPASS_E2E_SHOTS;
const ATLAS = "https://atlas-cloud.test";
const DOCS = "https://docs.atlas-cloud.test";

paired.skip(!OUT, "set ONEPASS_E2E_SHOTS to a directory");

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function shot(page: Page, name: string, scheme: string): Promise<void> {
  await page.screenshot({ path: join(OUT ?? "", `onepass-social-${name}-${scheme}.png`) });
}

async function chainEnded(ext: Ext, reason?: string): Promise<void> {
  await expect
    .poll(async () => await ext.chainState(), { timeout: 30_000 })
    .toMatchObject(reason ? { status: "handoff", reason } : { status: "done" });
}

async function overlayText(ext: Ext, page: Page, text: string | RegExp): Promise<void> {
  // Polled on whichever overlay frame the page has now (the progress moves
  // to a new frame on each page of the chain).
  await expect
    .poll(
      async () => {
        const f = ext.findExtFrame(page, "overlay");
        return f ? await f.locator(".ov-status").textContent({ timeout: 500 }).catch(() => null) : null;
      },
      { timeout: 20_000 },
    )
    .toMatch(typeof text === "string" ? new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`) : text);
  // Shown once its height is known, then the reveal transition.
  await ext.settle(600);
}

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

  paired(`shots_social_menu_${scheme}`, async ({ ext }) => {
    const { page } = ext;
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: 900, height: 620 });

    // The offer, alone, on a page that signs in with Google.
    await page.goto(`${DOCS}/login`);
    const offer = await ext.extFrame(page, "overlay");
    await expect(offer.locator('.ov-account[data-provider="google"]')).toHaveCount(1);
    await ext.settle();
    await shot(page, "offer", scheme);

    // The menu takes its place: one surface.
    const menu = await ext.openMenu(page, "#email");
    await expect(menu.locator('button.row[data-provider="google"]').first()).toBeVisible();
    await expect.poll(() => ext.findExtFrame(page, "overlay")).toBeUndefined();
    await ext.settle();
    await shot(page, "menu-providers", scheme);

    // Keyboard: the arrows move the highlight, the focus stays in the field.
    await page.keyboard.press("ArrowDown");
    await expect(menu.locator("button.row.active")).toHaveCount(1);
    await ext.settle(300);
    await shot(page, "menu-keyboard", scheme);

    // The other Google account, unfolded inline.
    await menu.locator("button.row-fold").click();
    await expect(menu.locator("button.row-sub")).toHaveCount(1);
    await ext.settle();
    await shot(page, "menu-picker", scheme);

    // Continue with Google: the progress where the user clicked. The
    // provider's page answers 204 (no navigation), so the chain waits there
    // and the picture shows it mid-step.
    await page.route(/accounts\.google\.com\/o\/oauth2\/auth/, (route) => route.fulfill({ status: 204 }), { times: 1 });
    await ext.settle();
    await menu.locator('button.row[data-provider="google"]:not(.row-sub)').click();
    await overlayText(ext, page, "Ouverture de Google…");
    await shot(page, "progress-opening", scheme);
    const overlay = ext.findExtFrame(page, "overlay");
    await overlay?.getByRole("button", { name: "Annuler" }).click();
    await expect.poll(async () => (await ext.chainState())?.status).toBe("stopped");

    // On the provider's chooser, picking the account (the next page waits too).
    await wait(END_SHOWN_MS + 500);
    await page.goto(`${DOCS}/login`);
    await page.route(/accounts\.google\.com\/signin\/identifier/, (route) => route.fulfill({ status: 204 }), { times: 1 });
    await ext.overlayStart(page, "Atlas Docs via Google");
    await expect(page).toHaveURL(/accounts\.google\.com\/o\/oauth2\/auth/, { timeout: 20_000 });
    await overlayText(ext, page, `Choix de ${FX.googlePerso.email}…`);
    await shot(page, "progress-choosing", scheme);
    await ext.findExtFrame(page, "overlay")?.getByRole("button", { name: "Annuler" }).click();
    await expect.poll(async () => (await ext.chainState())?.status).toBe("stopped");

    // The whole chain, back on the site, signed in.
    await wait(END_SHOWN_MS + 500);
    await page.goto(`${DOCS}/login`);
    await ext.overlayStart(page, "Atlas Docs via Google");
    await expect(page).toHaveURL(/^https:\/\/atlas-cloud\.test\/oauth\/callback/, { timeout: 30_000 });
    await chainEnded(ext);
    await overlayText(ext, page, "Connecté");
    await shot(page, "success", scheme);
  });

  paired(`shots_social_stops_${scheme}`, async ({ ext }) => {
    const { page } = ext;
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: 900, height: 620 });

    await page.goto(`${ATLAS}/captcha`);
    await ext.overlayStart(page, "Atlas Cloud");
    await chainEnded(ext, "captcha");
    await overlayText(ext, page, "CAPTCHA détecté, à toi de jouer");
    await shot(page, "stop-captcha", scheme);
    // A fresh offer shows once the last outcome is old enough.
    await wait(END_SHOWN_MS + 500);

    await page.goto(`${ATLAS}/sso-login`);
    await ext.overlayStart(page, "Atlas Cloud");
    await chainEnded(ext, "domain");
    await overlayText(ext, page, "Le domaine a changé : sso.evil.test");
    await shot(page, "stop-domain", scheme);
    await wait(END_SHOWN_MS + 500);

    await page.goto(`${ATLAS}/multistep`);
    await ext.overlayStart(page, "Atlas Cloud (multi)");
    await chainEnded(ext, "otp");
    await overlayText(ext, page, "Code reçu par SMS ou email : saisis-le");
    await shot(page, "stop-otp", scheme);
    await wait(END_SHOWN_MS + 500);

    // The provider's chooser does not list the account the site uses.
    await page.route(/accounts\.google\.com\/o\/oauth2\/auth/, (route) =>
      route.fulfill({
        status: 200,
        contentType: "text/html; charset=utf-8",
        body:
          '<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Choisir un compte</title><link rel="stylesheet" href="/style.css"></head>' +
          '<body><main><h1>Choisir un compte</h1><p>pour continuer vers atlas-docs</p><ul class="accounts">' +
          `<li><a class="button" id="acc-pro" href="/signin/identifier" data-email="${FX.googlePro.email}">Alex Martin<br>${FX.googlePro.email}</a></li>` +
          '<li><a class="button" id="acc-other" href="/signin/identifier">Utiliser un autre compte</a></li></ul></main></body></html>',
      }),
    );
    await page.goto(`${DOCS}/login`);
    await ext.overlayStart(page, "Atlas Docs via Google");
    await chainEnded(ext, "account");
    await overlayText(ext, page, `${FX.googlePerso.email} n'est pas proposé par Google`);
    await shot(page, "stop-account", scheme);
  });

  paired(`shots_social_save_${scheme}`, async ({ ext }) => {
    const { page } = ext;
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: 900, height: 620 });

    // Signed in with Google by hand on a site with no link yet.
    await page.goto(`${ATLAS}/login-google`);
    await expect(page.locator("onepass-root")).toHaveCount(1);
    await page.locator("#provider").click();
    await expect(page).toHaveURL(/accounts\.google\.com\/o\/oauth2\/auth/);
    await page.locator("#acc-perso").click();
    await page.locator("#identifier-email").fill(FX.googlePerso.email);
    await page.locator("#next").click();
    await page.locator("#password").fill(FX.googlePerso.password);
    await page.locator("#next").click();
    await expect(page).toHaveURL(/^https:\/\/atlas-cloud\.test\/oauth\/callback/);
    const save = await ext.extFrame(page, "save");
    await expect(save.getByText(`atlas-cloud.test ↔ Google`)).toBeVisible();
    await ext.settle();
    await shot(page, "save-link", scheme);
  });
}
