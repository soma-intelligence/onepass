// User flows of spec 11.3, end to end: real extension, real native host
// (fixture vault), local HTTPS pages of the fictional Atlas Cloud.
import { generateKeyPairSync } from "node:crypto";
import { expect, paired, test } from "./fixtures";
import { FX } from "./server";

const ATLAS = "https://atlas-cloud.test";

test("pairing_shows_same_code", async ({ ext }) => {
  const code = await ext.pair();
  expect(code).toMatch(/^\d{3} \d{3}$/);
  // The host derived and logged exactly one code: the one the popup showed.
  expect(ext.host.codes()).toEqual([code]);
  // The popup now shows the paired state (suggestions or search), not the pairing one.
  const popup = await ext.context.newPage();
  await popup.goto(`chrome-extension://${ext.id}/popup.html`);
  await expect(popup.getByPlaceholder("Rechercher dans OnePass")).toBeVisible();
  // "Oublier cet appairage" (spec 6.4): confirmed, the popup is unpaired, and stays so.
  await popup.getByRole("button", { name: "Oublier cet appairage" }).click();
  await expect(popup.getByRole("heading", { name: "Oublier cet appairage ?" })).toBeVisible();
  await popup.getByRole("button", { name: "Oublier", exact: true }).click();
  await expect(popup.getByRole("button", { name: "Appairer avec OnePass" })).toBeVisible();
  await popup.reload();
  await expect(popup.getByRole("button", { name: "Appairer avec OnePass" })).toBeVisible();
  await popup.close();
});

paired("menu_fill_login", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/login`);
  const menu = await ext.openMenu(page, "#email");
  // Built with use_dynamic_url on Chromium: the pick below goes through the
  // router's sender.url / getURL("") prefix check of extension pages.
  expect(menu.url()).toMatch(/^chrome-extension:\/\/[a-p0-9-]+\/menu\.html#[A-Za-z0-9_-]{22}$/);
  await expect(menu.locator(".menu-head")).toContainText("atlas-cloud.test");
  // The token is bound to the exact document (fill delivered by documentId).
  const records = Object.entries(await ext.sessionStorage()).filter(([k]) => k.startsWith("menu:"));
  expect(records).toHaveLength(1);
  expect((records[0]?.[1] as { documentId?: unknown }).documentId).toEqual(expect.any(String));
  // Remplir on a sign-in form signs in: filled, then sent by OnePass.
  await ext.pickRow(menu, "Atlas Cloud");
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText(FX.atlas.email);
  // The host journaled the secret it returned (no value): positive control of S3 and S9.
  expect(ext.audit()).toContain('"op":"fill_login"');
  expect(ext.audit()).not.toContain(FX.atlas.password);

  // The pairing survives a service worker restart (IndexedDB): fill again, no new pairing.
  await (await ext.worker()).evaluate(() => {
    (globalThis as { e2eMarker?: number }).e2eMarker = 1;
  });
  await ext.stopWorker();
  await page.goto(`${ATLAS}/logout`);
  const again = await ext.openMenu(page, "#email");
  await ext.pickRow(again, "Atlas Cloud (multi)");
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText(FX.ops.email);
  expect(ext.host.codes()).toHaveLength(1);
  // A new worker served this fill: the in-memory marker is gone.
  const marker = await (await ext.worker()).evaluate(() => (globalThis as { e2eMarker?: number }).e2eMarker);
  expect(marker).toBeUndefined();
});

paired("email_first_signup_and_sign_in_steps_get_the_menu", async ({ ext }) => {
  const { page } = ext;
  // Sign-up screen: one email field and "Continue" (Dribbble's markup), no password anywhere.
  await page.goto(`${ATLAS}/join`);
  const menu = await ext.openMenu(page, "#signup-email");
  await expect(menu.locator(".menu-head")).toContainText("atlas-cloud.test");
  await expect(menu.locator("button.row .t1", { hasText: /^Atlas Cloud$/ })).toHaveCount(1);
  await page.keyboard.press("Escape");
  // Its sign-in screen on the same URL, shown by "Sign in": Remplir puts the email and continues.
  await page.locator("#to-signin").click();
  const signin = await ext.openMenu(page, "#signin-login");
  await ext.pickRow(signin, "Atlas Cloud");
  await expect(page.locator("#status")).toHaveText("Code envoyé", { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText(FX.atlas.email);
});

paired("save_new_login_then_fill", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/login`);
  // Typed by the user: a login the site knows and the vault does not.
  await page.locator("#email").fill("alex.new@atlas.dev");
  await page.locator("#password").fill("Nouv-Pass-0042");
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText("Connecté");
  const save = await ext.extFrame(page, "save");
  await expect(save.getByText("Enregistrer le login pour atlas-cloud.test ?")).toBeVisible();
  await expect(save.getByText("alex.new@atlas.dev")).toBeVisible();
  await ext.settle();
  await save.getByRole("button", { name: "Enregistrer", exact: true }).click();
  await expect(save.getByText(/^Enregistré dans /)).toBeVisible();

  await page.goto(`${ATLAS}/logout`);
  const menu = await ext.openMenu(page, "#email");
  const saved = menu.locator("button.row").filter({ hasText: "alex.new@atlas.dev" });
  await expect(saved).toHaveCount(1);
  const title = (await saved.locator(".t1").textContent()) ?? "";
  await ext.pickRow(menu, title, "alex.new@atlas.dev");
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText("alex.new@atlas.dev");
});

// ---- founder bug 2026-11-03: no prompt after signing in with credentials OnePass did not know ----

paired("save_after_identifier_then_password", async ({ ext }) => {
  const { page } = ext;
  // Identifier first, password on the next page (most large sites): the password page has no identifier field.
  await page.goto(`${ATLAS}/multistep`);
  await page.locator("#email").fill("alex.new@atlas.dev");
  await page.locator("#next").click();
  await expect(page).toHaveURL(`${ATLAS}/multistep/password`);
  await page.locator("#password").fill("Nouv-Pass-0042");
  await page.locator("#submit").click();
  await expect(page).toHaveURL(`${ATLAS}/multistep/otp`);
  const save = await ext.extFrame(page, "save");
  await expect(save.getByText("Enregistrer le login pour atlas-cloud.test ?")).toBeVisible();
  await expect(save.getByText("alex.new@atlas.dev")).toBeVisible();
  await ext.settle();
  await save.getByRole("button", { name: "Enregistrer", exact: true }).click();
  await expect(save.getByText(/^Enregistré dans /)).toBeVisible();
  expect(ext.audit()).toContain('"op":"save_login"');
  expect(ext.audit()).not.toContain("Nouv-Pass-0042");
});

paired("failed_login_offers_nothing", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/login`);
  await page.locator("#email").fill("alex.new@atlas.dev");
  await page.locator("#password").fill("Mauvais-Pass-1");
  await page.locator("#submit").click();
  await expect(page.locator("#error")).toHaveText("Identifiant ou mot de passe incorrect");
  // Well past every settle delay: still nothing (the site asked for the password again).
  await ext.settle(4000);
  expect(ext.findExtFrame(page, "save")).toBeUndefined();
  // The right password then: proposed.
  await page.locator("#email").fill("alex.new@atlas.dev");
  await page.locator("#password").fill("Nouv-Pass-0042");
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText("Connecté");
  const save = await ext.extFrame(page, "save");
  await expect(save.getByText("Enregistrer le login pour atlas-cloud.test ?")).toBeVisible();
});

paired("save_card_stacks_beside_another_manager", async ({ ext }) => {
  const { page } = ext;
  await page.setViewportSize({ width: 1100, height: 720 });
  await page.goto(`${ATLAS}/login-other-manager`);
  await page.locator("#email").fill("alex.new@atlas.dev");
  await page.locator("#password").fill("Nouv-Pass-0042");
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText("Connecté");
  const save = await ext.extFrame(page, "save");
  await expect(save.getByText("Enregistrer le login pour atlas-cloud.test ?")).toBeVisible();
  await ext.settle();
  const theirs = await page.locator("#other-manager-notification").boundingBox();
  const ours = await (await save.frameElement()).boundingBox();
  expect(theirs).not.toBeNull();
  expect(ours).not.toBeNull();
  const a = theirs!;
  const b = ours!;
  const overlap = a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;
  expect(overlap).toBe(false);
  // Right under theirs, a small gap, same corner.
  expect(b.y).toBeGreaterThanOrEqual(a.y + a.height);
  expect(b.y - (a.y + a.height)).toBeLessThanOrEqual(16);
  // Theirs goes away: ours moves back up to the corner.
  await page.evaluate(() => document.getElementById("other-manager-notification")?.remove());
  await expect.poll(async () => (await (await save.frameElement()).boundingBox())?.y ?? -1, { timeout: 5000 }).toBeLessThan(a.y + a.height);
});

paired("change_password_updates_item", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/change-password`);
  await expect(page.locator("#email")).toHaveValue(FX.ops.email);
  const current = await ext.openMenu(page, "#current-password");
  await ext.pickRow(current, "Atlas Cloud (multi)");
  await expect(page.locator("#current-password")).toHaveValue(FX.ops.password);
  const fresh = await ext.openMenu(page, "#new-password");
  await ext.pickRow(fresh, "Générer un mot de passe");
  await expect(page.locator("#new-password")).not.toHaveValue("");
  const generated = await page.locator("#new-password").inputValue();
  expect(generated).not.toBe(FX.ops.password);
  await expect(page.locator("#confirm-password")).toHaveValue(generated);
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText("Mot de passe modifié");

  const save = await ext.extFrame(page, "save");
  await expect(save.getByText("Mettre à jour le mot de passe pour atlas-cloud.test ?")).toBeVisible();
  await expect(save.getByText(`Atlas Cloud (multi) · ${FX.ops.email}`)).toBeVisible();
  await ext.settle();
  await save.getByRole("button", { name: "Mettre à jour", exact: true }).click();
  await expect(save.getByText("Mot de passe mis à jour")).toBeVisible();

  // The item now fills the new password, which the site accepts.
  await page.goto(`${ATLAS}/login`);
  const menu = await ext.openMenu(page, "#email");
  await ext.pickRow(menu, "Atlas Cloud (multi)");
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  expect(ext.server.users.get(FX.ops.email)).toBe(generated);
});

paired("signup_generates_password", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/signup`);
  await page.locator("#email").fill("alex.signup@atlas.dev");
  const menu = await ext.openMenu(page, "#new-password");
  await ext.pickRow(menu, "Générer un mot de passe");
  await expect(page.locator("#new-password")).not.toHaveValue("");
  const generated = await page.locator("#new-password").inputValue();
  expect(generated.length).toBeGreaterThanOrEqual(12);
  await expect(page.locator("#confirm-password")).toHaveValue(generated);
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText("Connecté");
  expect(ext.server.users.get("alex.signup@atlas.dev")).toBe(generated);

  // The generated password was saved as a pending login at fill time; the
  // submission confirms it with the username, no question asked: the card
  // only says it is saved.
  await expect.poll(() => ext.audit(), { timeout: 15_000 }).toContain('"op":"confirm_pending"');
  const card = await ext.extFrame(page, "save");
  await expect(card.locator(".saved")).toContainText("alex.signup@atlas.dev");
  await expect(card.locator("button", { hasText: "Enregistrer" })).toHaveCount(0);
  expect(ext.audit()).not.toContain(generated);
  await page.goto(`${ATLAS}/logout`);
  const again = await ext.openMenu(page, "#email");
  await expect(again.locator("button.row").filter({ hasText: "alex.signup@atlas.dev" })).toHaveCount(1);
});

paired("save_card_after_checkout", async ({ ext }) => {
  const { page } = ext;
  // A test card number (Luhn valid, not a real card), typed by hand.
  const typeCard = async () => {
    await page.goto(`${ATLAS}/checkout`);
    await page.locator("#cc-name").fill("Sam Leroy");
    await page.locator("#cc-number").fill("5555 5555 5555 4444");
    await page.locator("#cc-exp").fill("07/31");
    await page.locator("#cc-csc").fill("987");
    await page.locator("#submit").click();
    await expect(page.locator("#status")).toHaveText("Paiement accepté");
  };
  await typeCard();
  const card = await ext.extFrame(page, "save");
  await expect(card.getByText("Enregistrer cette carte ?")).toBeVisible();
  await expect(card.getByText("Carte •••• 4444 · exp. 07/31")).toBeVisible();
  await ext.settle();
  await card.getByRole("button", { name: "Enregistrer", exact: true }).click();
  await expect(card.getByText("Carte enregistrée")).toBeVisible();
  await expect.poll(() => ext.audit(), { timeout: 15_000 }).toContain('"op":"save_card"');
  expect(ext.audit()).not.toContain("5555555555554444");
  const saves = () => (ext.audit().match(/"op":"save_card"/g) ?? []).length;
  expect(saves()).toBe(1);
  // The same card typed again by hand: the card still shows (a page must not learn what the
  // vault holds), and its Save writes nothing.
  await typeCard();
  const again = await ext.extFrame(page, "save");
  await expect(again.getByText("Enregistrer cette carte ?")).toBeVisible();
  await ext.settle();
  await again.getByRole("button", { name: "Enregistrer", exact: true }).click();
  await expect(again.getByText("Déjà dans OnePass")).toBeVisible();
  expect(saves()).toBe(1);
});

paired("save_address_after_shipping", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/shipping`);
  await page.locator("#given-name").fill("Sam");
  await page.locator("#family-name").fill("Leroy");
  await page.locator("#address-line1").fill("8 avenue des Tilleuls");
  await page.locator("#postal-code").fill("69003");
  await page.locator("#city").fill("Lyon");
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText("Adresse enregistrée");
  const card = await ext.extFrame(page, "save");
  await expect(card.getByText("Enregistrer cette adresse ?")).toBeVisible();
  await expect(card.getByText("8 avenue des Tilleuls, 69003, Lyon")).toBeVisible();
  await ext.settle();
  await card.getByRole("button", { name: "Enregistrer", exact: true }).click();
  await expect(card.getByText("Identité enregistrée")).toBeVisible();
  await expect.poll(() => ext.audit(), { timeout: 15_000 }).toContain('"op":"save_identity"');
});

paired("chain_single_page", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/login`);
  await ext.overlayStart(page, "Atlas Cloud");
  await expect(page.locator("#status")).toHaveText("Connecté");
  await expect(page.locator("#detail")).toHaveText(FX.atlas.email);
  await expect.poll(async () => (await ext.chainState())?.status, { timeout: 20_000 }).toBe("done");
  const overlay = await ext.extFrame(page, "overlay");
  await expect(overlay.locator(".ov-status")).toHaveText("Connecté");
});

paired("chain_multistep_totp", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/multistep`);
  await ext.overlayStart(page, "Atlas Cloud");
  // Identifier, then password, then the TOTP code: one click.
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText(FX.atlas.email);
  await expect.poll(async () => (await ext.chainState())?.status, { timeout: 20_000 }).toBe("done");
});

paired("chain_google_picks_right_account", async ({ ext }) => {
  const { page } = ext;
  await page.goto("https://docs.atlas-cloud.test/login");
  // Atlas Docs is linked to the personal Google account (of two in the vault).
  await ext.overlayStart(page, "Atlas Docs via Google");
  await expect(page).toHaveURL(/^https:\/\/atlas-cloud\.test\/oauth\/callback/, { timeout: 30_000 });
  await expect(page.locator("#status")).toHaveText("Connecté");
  await expect(page.locator("#detail")).toHaveText(`avec Google (${FX.googlePerso.email})`);
  expect(ext.server.providerSignIns).toEqual([FX.googlePerso.email]);
  await expect.poll(async () => (await ext.chainState())?.status, { timeout: 20_000 }).toBe("done");
});

paired("chain_stops_on_captcha", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/captcha`);
  const overlay = await ext.overlayStart(page, "Atlas Cloud");
  await expect.poll(async () => await ext.chainState(), { timeout: 20_000 }).toMatchObject({ status: "handoff", reason: "captcha" });
  await expect(overlay.locator(".ov-status")).toHaveText("CAPTCHA détecté, à toi de jouer");
  await expect(page.locator("#email")).toHaveValue("");
  await expect(page.locator("#password")).toHaveValue("");
});

paired("chain_stops_on_domain_change", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/sso-login`);
  await ext.overlayStart(page, "Atlas Cloud");
  // The identifier is filled and submitted; the site sends the tab to another domain.
  await expect(page).toHaveURL("https://sso.evil.test/login", { timeout: 30_000 });
  await expect.poll(async () => await ext.chainState(), { timeout: 20_000 }).toMatchObject({
    status: "handoff",
    reason: "domain",
    host: "sso.evil.test",
  });
  await ext.settle(2000);
  await expect(page.locator("#email")).toHaveValue("");
  await expect(page.locator("#password")).toHaveValue("");
  expect(ext.server.captured).toEqual([]);
});

paired("card_fill", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/checkout`);
  const menu = await ext.openMenu(page, "#cc-number");
  await ext.pickRow(menu, "Carte Atlas");
  await expect(page.locator("#cc-name")).toHaveValue(FX.card.holder);
  await expect(page.locator("#cc-number")).toHaveValue(/^4242 ?4242 ?4242 ?4242$/);
  await expect(page.locator("#cc-exp")).toHaveValue(/^04 ?\/ ?(29|2029)$/);
  await expect(page.locator("#cc-csc")).toHaveValue(FX.card.cvv);
});

paired("identity_fill", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/profile`);
  const menu = await ext.openMenu(page, "#given-name");
  await ext.pickRow(menu, "Alex Martin");
  const id = FX.identity;
  await expect(page.locator("#given-name")).toHaveValue(id.given);
  await expect(page.locator("#family-name")).toHaveValue(id.family);
  await expect(page.locator("#email")).toHaveValue(id.email);
  await expect(page.locator("#tel")).toHaveValue(id.tel);
  await expect(page.locator("#organization")).toHaveValue(id.org);
  await expect(page.locator("#address-line1")).toHaveValue(id.line1);
  await expect(page.locator("#postal-code")).toHaveValue(id.zip);
  await expect(page.locator("#city")).toHaveValue(id.city);
});

// ---- signing in with a provider, seamless (one surface, picker, keyboard, link) ----

const DOCS = "https://docs.atlas-cloud.test";

paired("one_surface_menu_replaces_offer_and_fits_its_content", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/login`);
  await ext.extFrame(page, "overlay");
  const menu = await ext.openMenu(page, "#email");
  await expect(menu.locator("button.row").first()).toBeVisible();
  // Never two surfaces: the offer leaves when the menu opens.
  await expect.poll(() => ext.findExtFrame(page, "overlay")).toBeUndefined();
  // The frame is as tall as its rows (two logins and "Enregistrer un nouveau login").
  await expect.poll(async () => menu.evaluate(() => innerHeight)).toBeLessThan(260);
  const content = await menu.evaluate(() => document.querySelector(".menu")?.scrollHeight ?? 0);
  expect(Math.abs((await menu.evaluate(() => innerHeight)) - content)).toBeLessThanOrEqual(2);
});

paired("menu_keyboard_from_the_field", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/login`);
  const menu = await ext.openMenu(page, "#email");
  await ext.settle();
  // Arrows move the menu's highlight while the focus stays in the page's field.
  await page.keyboard.press("ArrowDown");
  await expect(menu.locator("button.row.active .t1")).toHaveText("Atlas Cloud");
  await page.keyboard.press("ArrowDown");
  await expect(menu.locator("button.row.active .t1")).toHaveText("Atlas Cloud (multi)");
  expect(await page.evaluate(() => document.activeElement?.id)).toBe("email");
  // Return follows the click guard: a highlight that scrolled the list, or a
  // visibility change, re-arms its delay. Wait past it, as the click tests do.
  await ext.settle();
  await page.keyboard.press("Enter");
  // Return picked the highlighted row (not the page's empty form): signed in as that login.
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText(FX.ops.email);
  // Escape closes; the focus stays where it was.
  await page.goto(`${ATLAS}/logout`);
  await ext.openMenu(page, "#email");
  await page.keyboard.press("Escape");
  await expect.poll(() => ext.findExtFrame(page, "menu")).toBeUndefined();
  expect(await page.evaluate(() => document.activeElement?.id)).toBe("email");
});

paired("provider_picker_signs_in_with_the_other_account_and_remembers_it", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${DOCS}/login`);
  const menu = await ext.openMenu(page, "#email");
  const google = menu.locator('button.row[data-provider="google"]:not(.row-sub)');
  await expect(google.locator(".t2")).toHaveText(FX.googlePerso.email);
  await ext.settle();
  await menu.locator("button.row-fold").click();
  const pro = menu.locator("button.row-sub").filter({ has: menu.locator(".t1", { hasText: FX.googlePro.email }) });
  await expect(pro).toHaveCount(1);
  await ext.settle();
  await pro.click();
  await expect(page).toHaveURL(/^https:\/\/atlas-cloud\.test\/oauth\/callback/, { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText(`avec Google (${FX.googlePro.email})`);
  expect(ext.server.providerSignIns).toEqual([FX.googlePro.email]);
  await expect.poll(async () => (await ext.chainState())?.status, { timeout: 20_000 }).toBe("done");
  // Next time on that site, the account picked last is the default.
  await page.goto(`${DOCS}/login`);
  const again = await ext.openMenu(page, "#email");
  await expect(again.locator('button.row[data-provider="google"]:not(.row-sub) .t2')).toHaveText(FX.googlePro.email);
});

paired("provider_link_offered_after_a_manual_google_sign_in", async ({ ext }) => {
  const { page } = ext;
  await page.goto(`${ATLAS}/login-google`);
  await expect(page.locator("onepass-root")).toHaveCount(1);
  await page.locator("#provider").click();
  await page.locator("#acc-perso").click();
  await page.locator("#identifier-email").fill(FX.googlePerso.email);
  await page.locator("#next").click();
  await page.locator("#password").fill(FX.googlePerso.password);
  await page.locator("#next").click();
  await expect(page).toHaveURL(/^https:\/\/atlas-cloud\.test\/oauth\/callback/);
  const save = await ext.extFrame(page, "save");
  await expect(save.locator(".link-card .t1")).toHaveText("atlas-cloud.test ↔ Google");
  await expect(save.locator(".link-card .line2")).toHaveText(`${FX.googlePerso.email} · Google perso`);
  // One compact prompt, not a sheet.
  await expect.poll(async () => save.evaluate(() => innerHeight)).toBeLessThan(300);
  await ext.settle();
  await save.getByRole("button", { name: "Enregistrer", exact: true }).click();
  await expect(save.getByText("Lien enregistré")).toBeVisible();
  // The site now signs in with that Google account in one click.
  await page.goto(`${ATLAS}/logout`);
  await page.goto(`${ATLAS}/login-google`);
  const menu = await ext.openMenu(page, "#email");
  await expect(menu.locator('button.row[data-provider="google"] .t2').first()).toHaveText(FX.googlePerso.email);
});

paired("passkey_sign_in", async ({ ext }) => {
  const { page } = ext;
  const passkeyWindow = () =>
    ext.context.waitForEvent("page", { predicate: (p) => /\/passkey\.html#[A-Za-z0-9_-]{22}$/.test(p.url()), timeout: 15_000 });
  await page.goto(`${ATLAS}/passkey`);
  await expect(page.locator("onepass-root")).toHaveCount(1);

  // The site's passkey button: OnePass's window lists the account holding a passkey of atlas-cloud.test.
  let opened = passkeyWindow();
  await page.locator("#signin").click();
  let win = await opened;
  await expect(win.getByRole("heading", { name: "Se connecter avec une passkey" })).toBeVisible();
  await expect(win.getByText("atlas-cloud.test").first()).toBeVisible();
  await expect(win.getByRole("button", { name: "Autre appareil" })).toBeVisible();
  await ext.settle();
  await win.getByRole("button", { name: `Se connecter en tant que ${FX.passkey.user}` }).click();
  await expect(page.locator("#result")).toHaveAttribute("data-status", "Connecté");
  await expect.poll(() => win.isClosed()).toBe(true);
  // A conforming PublicKeyCredential, verified by the site with the passkey's public key.
  const r = (await page.evaluate(() => (window as unknown as { __passkeyResult: unknown }).__passkeyResult)) as Record<string, unknown>;
  expect(r).toMatchObject({ origin: ATLAS, crossOrigin: false, type: "webauthn.get", user: FX.passkey.userHandle, rawIdMatches: true, proto: "true", ext: "{}" });
  await page.goto(`${ATLAS}/home`);
  await expect(page.locator("#status")).toHaveText("Connecté");
  expect(ext.audit()).toContain("passkey_get");

  // Annuler: the page gets NotAllowedError.
  await page.goto(`${ATLAS}/passkey`);
  opened = passkeyWindow();
  await page.locator("#signin").click();
  win = await opened;
  await ext.settle();
  await win.getByRole("button", { name: "Annuler" }).click();
  await expect(page.locator("#result")).toHaveAttribute("data-status", "error:NotAllowedError");

  // Creation: a new passkey saved in OnePass, then offered at the next sign-in.
  await page.goto(`${ATLAS}/passkey`);
  opened = passkeyWindow();
  await page.locator("#register").click();
  win = await opened;
  await expect(win.getByRole("heading", { name: "Enregistrer une passkey" })).toBeVisible();
  await expect(win.getByText("alex.new@atlas.dev")).toBeVisible();
  await ext.settle();
  await win.getByRole("button", { name: "Enregistrer", exact: true }).click();
  await expect(page.locator("#result")).toHaveAttribute("data-status", "Créée");
  expect(ext.audit()).toContain("passkey_create");
  // Next sign-in in a fresh tab: this tab is in its get cooldown (Annuler above)
  // and has opened its 3 windows of the minute (security README 12.11).
  const next = await ext.context.newPage();
  await next.goto(`${ATLAS}/passkey`);
  await expect(next.locator("onepass-root")).toHaveCount(1);
  opened = passkeyWindow();
  await next.locator("#signin").click();
  win = await opened;
  await expect(win.getByRole("button", { name: "Se connecter en tant que alex.new@atlas.dev" })).toBeVisible();
  await expect(win.getByRole("button", { name: `Se connecter en tant que ${FX.passkey.user}` })).toBeVisible();
  await ext.settle();
  await win.getByRole("button", { name: "Annuler" }).click();
  // The private key never left the host.
  expect(ext.audit()).not.toContain("MIGHAgEAMBMGByqGSM49");
});

paired("passkey_other_device_hands_off_to_the_browser", async ({ ext }) => {
  const { page } = ext;
  // The browser's own authenticator (Chromium's virtual one, with a key of its
  // own for this site): what answers once OnePass hands the call back.
  const cdp = await ext.context.newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  const nativeKey = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "der" });
  await cdp.send("WebAuthn.addCredential", {
    authenticatorId,
    credential: {
      credentialId: Buffer.from("native-only-2").toString("base64"), isResidentCredential: true, rpId: FX.passkey.rpId,
      userHandle: Buffer.from("native-2").toString("base64"), privateKey: nativeKey.toString("base64"), signCount: 0,
    },
  });
  let nativeAsserted = 0;
  cdp.on("WebAuthn.credentialAsserted", () => nativeAsserted++);
  await page.goto(`${ATLAS}/passkey`);
  await expect(page.locator("onepass-root")).toHaveCount(1);
  const opened = ext.context.waitForEvent("page", { predicate: (p) => /\/passkey\.html#[A-Za-z0-9_-]{22}$/.test(p.url()), timeout: 15_000 });
  await page.locator("#signin").click();
  const win = await opened;
  await ext.settle();
  // "Autre appareil": OnePass's window closes, the site's tab is focused again
  // first, so the browser's own call is not refused for an unfocused document.
  await win.getByRole("button", { name: "Autre appareil" }).click();
  await expect.poll(() => win.isClosed()).toBe(true);
  await expect.poll(() => page.evaluate(() => document.hasFocus())).toBe(true);
  await expect.poll(() => nativeAsserted, { timeout: 15_000, message: "the browser's own authenticator never answered" }).toBe(1);
  await expect(page.locator("#result")).toHaveAttribute("data-status", /.+/, { timeout: 15_000 });
  await expect(page.locator("#result")).not.toHaveAttribute("data-status", "error:NotAllowedError");
  // OnePass signed nothing.
  expect(ext.audit()).not.toContain("passkey_get");
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
});
