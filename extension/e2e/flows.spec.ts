// User flows of spec 11.3, end to end: real extension, real native host
// (fixture vault), local HTTPS pages of the fictional Atlas Cloud.
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
  await ext.pickRow(menu, "Atlas Cloud");
  await expect(page.locator("#email")).toHaveValue(FX.atlas.email);
  await expect(page.locator("#password")).toHaveValue(FX.atlas.password);
  // The host journaled the secret it returned (no value): positive control of S3 and S9.
  expect(ext.audit()).toContain('"op":"fill_login"');
  expect(ext.audit()).not.toContain(FX.atlas.password);
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText("Connecté");

  // The pairing survives a service worker restart (IndexedDB): fill again, no new pairing.
  await (await ext.worker()).evaluate(() => {
    (globalThis as { e2eMarker?: number }).e2eMarker = 1;
  });
  await ext.stopWorker();
  await page.goto(`${ATLAS}/logout`);
  const again = await ext.openMenu(page, "#email");
  await ext.pickRow(again, "Atlas Cloud (multi)");
  await expect(page.locator("#email")).toHaveValue(FX.ops.email);
  await expect(page.locator("#password")).toHaveValue(FX.ops.password);
  expect(ext.host.codes()).toHaveLength(1);
  // A new worker served this fill: the in-memory marker is gone.
  const marker = await (await ext.worker()).evaluate(() => (globalThis as { e2eMarker?: number }).e2eMarker);
  expect(marker).toBeUndefined();
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
  await expect(save.getByText("Enregistrer le login ?")).toBeVisible();
  await ext.settle();
  await save.getByRole("button", { name: "Enregistrer", exact: true }).click();
  await expect(save.getByText(/enregistré$/)).toBeVisible();

  await page.goto(`${ATLAS}/logout`);
  const menu = await ext.openMenu(page, "#email");
  const saved = menu.locator("button.row").filter({ hasText: "alex.new@atlas.dev" });
  await expect(saved).toHaveCount(1);
  const title = (await saved.locator(".t1").textContent()) ?? "";
  await ext.pickRow(menu, title, "alex.new@atlas.dev");
  await expect(page.locator("#email")).toHaveValue("alex.new@atlas.dev");
  await expect(page.locator("#password")).toHaveValue("Nouv-Pass-0042");
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText("Connecté");
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
  await expect(save.getByRole("tab", { name: "Mettre à jour (1)" })).toBeVisible();
  await ext.settle();
  await save.getByRole("tab", { name: "Mettre à jour (1)" }).click();
  await ext.settle();
  await save.getByRole("button", { name: "Mettre à jour", exact: true }).click();
  await expect(save.getByText("Atlas Cloud (multi) mis à jour")).toBeVisible();

  // The item now fills the new password, which the site accepts.
  await page.goto(`${ATLAS}/login`);
  const menu = await ext.openMenu(page, "#email");
  await ext.pickRow(menu, "Atlas Cloud (multi)");
  await expect(page.locator("#password")).toHaveValue(generated);
  await page.locator("#submit").click();
  await expect(page.locator("#status")).toHaveText("Connecté");
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

  // The generated password feeds the save proposal.
  const save = await ext.extFrame(page, "save");
  await expect(save.getByText("Enregistrer le login ?")).toBeVisible();
  await ext.settle();
  await save.getByRole("button", { name: "Enregistrer", exact: true }).click();
  await expect(save.getByText(/enregistré$/)).toBeVisible();
  await page.goto(`${ATLAS}/logout`);
  const again = await ext.openMenu(page, "#email");
  await expect(again.locator("button.row").filter({ hasText: "alex.signup@atlas.dev" })).toHaveCount(1);
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
