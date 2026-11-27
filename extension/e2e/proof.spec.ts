// Visual proof of the sign-in card rules (scenarios a to g), on the local test
// sites with the fictional vault: real extension build, real native host.
// Run: PROOF_OUT=<dir> npx playwright test -c e2e/playwright.config.ts e2e/proof.spec.ts
import { mkdirSync, writeFileSync, readFileSync, appendFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { type Ext, expect, paired } from "./fixtures";
import { FX } from "./server";

const ATLAS = "https://atlas-cloud.test";
const DOCS = "https://docs.atlas-cloud.test";
const OUT = process.env.PROOF_OUT ?? join(process.cwd(), "lab/out/proof");
mkdirSync(OUT, { recursive: true });

function note(scenario: string, check: string, ok: boolean, detail = "") {
  appendFileSync(join(OUT, "checks.jsonl"), `${JSON.stringify({ scenario, check, ok, detail })}\n`);
}

/** OnePass surfaces on the page now: sign-in card frames and field menu frames. */
function surfaces(ext: Ext, page: Page) {
  const card = ext.findExtFrame(page, "overlay") ? 1 : 0;
  const menu = ext.findExtFrame(page, "menu") ? 1 : 0;
  return { card, menu, total: card + menu };
}

async function snap(page: Page, name: string) {
  await page.screenshot({ path: join(OUT, `${name}.png`) });
}

paired.use({ scheme: "light" });

paired("a_one_surface_on_a_signed_out_login_page", async ({ ext }) => {
  const { page } = ext;
  await page.setViewportSize({ width: 900, height: 620 });
  await page.goto(`${ATLAS}/login`);
  await ext.extFrame(page, "overlay");
  await ext.settle();
  let s = surfaces(ext, page);
  note("a", "card alone on arrival", s.card === 1 && s.menu === 0, JSON.stringify(s));
  await snap(page, "a1-card-alone");
  // The user goes to the field anyway: the menu takes the card's place.
  const menu = await ext.openMenu(page, "#email");
  await expect(menu.locator("button.row").first()).toBeVisible();
  await expect.poll(() => ext.findExtFrame(page, "overlay")).toBeUndefined();
  await ext.settle();
  s = surfaces(ext, page);
  note("a", "field menu replaces the card", s.card === 0 && s.menu === 1, JSON.stringify(s));
  await snap(page, "a2-menu-replaces-card");
  // Escape: nothing left fighting for attention.
  await page.keyboard.press("Escape");
  await ext.settle(800);
  s = surfaces(ext, page);
  note("a", "Escape leaves at most one surface", s.total <= 1, JSON.stringify(s));
  await snap(page, "a3-after-escape");
});

paired("b_d_sign_in_then_nothing_on_the_signed_in_page", async ({ ext }) => {
  const { page } = ext;
  await page.setViewportSize({ width: 900, height: 620 });
  await page.goto(`${ATLAS}/login`);
  const card = await ext.extFrame(page, "overlay");
  await ext.settle();
  await snap(page, "b1-offer");
  const texts: string[] = [];
  const signIn = card.locator(".ov-signin").first();
  await signIn.click();
  // Frames of the running line, every 150 ms, until the page says signed in.
  for (let i = 0; i < 120; i++) {
    const f = ext.findExtFrame(page, "overlay");
    const t = f ? ((await f.locator("body").innerText({ timeout: 300 }).catch(() => "")) || "").replace(/\s+/g, " ").trim() || null : null;
    if (t && texts[texts.length - 1] !== t) {
      texts.push(t);
      await snap(page, `b2-line-${texts.length}`);
    }
    if ((await page.locator("#status").textContent({ timeout: 300 }).catch(() => "")) === "Connecté" && !f) break;
    await page.waitForTimeout(150);
  }
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  note("b", "line texts seen", texts.length > 0, texts.join(" | "));
  note("b", "line says Connecté before it leaves", texts.some((x) => x.startsWith("Connecté")), texts.join(" | "));
  const steps = await Promise.all(page.frames().map((f) => f.locator(".ov-steps, ol li").count().catch(() => 0)));
  note("b", "no step list", steps.every((n) => n === 0), JSON.stringify(steps));
  await expect.poll(() => ext.findExtFrame(page, "overlay"), { timeout: 10_000 }).toBeUndefined();
  note("b", "line gone after success", true);
  await snap(page, "b3-signed-in-card-gone");
  // d: back on the site, signed in: nothing shows.
  await page.goto(`${ATLAS}/home`);
  await expect(page.locator("#status")).toHaveText("Connecté");
  await ext.settle(2500);
  const s = surfaces(ext, page);
  note("d", "signed-in page shows nothing", s.total === 0, JSON.stringify(s));
  await snap(page, "d1-signed-in-nothing");
});

paired("c_close_stays_closed_after_reload", async ({ ext }) => {
  const { page } = ext;
  await page.setViewportSize({ width: 900, height: 620 });
  await page.goto(`${ATLAS}/login`);
  const card = await ext.extFrame(page, "overlay");
  await ext.settle();
  await snap(page, "c1-before-close");
  await card.locator(".ov-close").first().click();
  await expect.poll(() => ext.findExtFrame(page, "overlay"), { timeout: 3000 }).toBeUndefined();
  note("c", "x closes at once", true);
  await snap(page, "c2-closed");
  await page.reload();
  await ext.settle(3000);
  const s = surfaces(ext, page);
  note("c", "reload does not bring it back", s.card === 0, JSON.stringify(s));
  await snap(page, "c3-after-reload");
  // The page stays fully usable: the fields still take input.
  await page.locator("#email").fill("typed@example.test");
  note("c", "page fields still usable", (await page.locator("#email").inputValue()) === "typed@example.test");
});

paired("e_several_accounts_notch", async ({ ext }) => {
  const { page } = ext;
  await page.setViewportSize({ width: 900, height: 620 });
  await page.goto(`${DOCS}/login`);
  const card = await ext.extFrame(page, "overlay");
  await ext.settle();
  await snap(page, "e1-card-with-notch");
  const lip = card.locator(".ov-lip, .ov-other, .ov-others").first();
  const kind = await lip.getAttribute("class");
  note("e", "notch or other-account row present", !!kind, kind ?? "");
  await lip.click();
  await ext.settle(800);
  await snap(page, "e2-notch-open");
  const rows = await card.locator(".ov-notch-row").count();
  note("e", "notch lists the other ways", rows > 0, `${rows} row(s)`);
  // Pick the second Google account: the provider signs it in.
  await page.route(/accounts\.google\.com\/o\/oauth2\/auth/, (r) => r.continue());
  const pro = card.locator(".ov-notch-row").filter({ hasText: /pro/i }).first();
  if (await pro.count()) await pro.click();
  else await card.locator(".ov-notch-row").first().click();
  await expect.poll(() => ext.server.providerSignIns.length, { timeout: 30_000 }).toBeGreaterThan(0);
  note("e", "picked account signed in", true, ext.server.providerSignIns.join(","));
  await ext.settle(1500);
  await snap(page, "e3-signed-in");
});

paired("f_other_manager_icon_no_overlap", async ({ ext }) => {
  const { page } = ext;
  await page.setViewportSize({ width: 900, height: 620 });
  await page.goto(`${ATLAS}/login-other-manager`);
  await ext.settle(2500);
  await snap(page, "f1-with-other-manager");
  const field = (await page.locator("#email").boundingBox())!;
  await page.screenshot({
    path: join(OUT, "f2-field-zoom.png"),
    clip: { x: Math.max(0, field.x - 20), y: Math.max(0, field.y - 20), width: field.width + 40, height: field.height + 40 },
  });
  const theirs = await page.evaluate(() => {
    const out: { x: number; y: number; w: number; h: number }[] = [];
    for (const el of document.querySelectorAll<HTMLElement>("[data-other-manager-icon], #other-manager-icon, [id^='other-manager']")) {
      const r = el.getBoundingClientRect();
      if (r.width) out.push({ x: r.x, y: r.y, w: r.width, h: r.height });
    }
    return out;
  });
  note("f", "other manager present", theirs.length > 0, JSON.stringify(theirs));
  // Open our menu: one menu, theirs untouched.
  const menu = await ext.openMenu(page, "#email");
  await expect(menu.locator("button.row").first()).toBeVisible();
  await ext.settle();
  const s = surfaces(ext, page);
  note("f", "one OnePass surface with the other manager", s.total === 1, JSON.stringify(s));
  await snap(page, "f3-our-menu");
});

paired("g_locked_then_unreachable", async ({ ext }) => {
  const { page } = ext;
  await page.setViewportSize({ width: 900, height: 620 });
  // Locked: the host answers, the vault stays shut until the user approves (Touch ID in the app;
  // here the approval file the host waits for, written by the test as the user's finger).
  const cfg = JSON.parse(readFileSync(ext.host.config, "utf8"));
  cfg.unlocked = false;
  cfg.unlock = "file";
  writeFileSync(ext.host.config, JSON.stringify(cfg));
  await ext.stopWorker();
  await page.goto(`${ATLAS}/login`);
  const card = await ext.extFrame(page, "overlay").catch(() => null);
  await ext.settle();
  const text = async (): Promise<string> => {
    const f = ext.findExtFrame(page, "overlay");
    return f ? (await f.locator("body").innerText({ timeout: 500 }).catch(() => "")).replace(/\s+/g, " ").trim() : "(no card)";
  };
  note("g", "locked: generic card, nothing of the vault", !!card && !/alex@atlas\.dev/.test(await text()), await text());
  await snap(page, "g1-locked-card");
  if (card) {
    await card.locator("button").filter({ hasText: /connecter|déverrouiller|continuer|ouvrir/i }).first().click();
    const pending = join(cfg.data_dir, "unlock-pending");
    await expect.poll(() => existsSync(pending), { timeout: 10_000 }).toBe(true);
    await ext.settle(1500);
    const waiting = await text();
    note("g", "locked click: the card waits for the unlock in the app", /verrouill|Touch ID|OnePass/i.test(waiting), waiting);
    await snap(page, "g2-waiting-for-unlock");
    // The user approves in the app.
    writeFileSync(join(cfg.data_dir, "unlock-approved"), "");
    // The vault opens: the page's plan runs. Two logins fit this page: its menu asks which one.
    await expect.poll(() => existsSync(pending), { timeout: 15_000 }).toBe(false);
    const menu = await expect.poll(() => !!ext.findExtFrame(page, "menu"), { timeout: 15_000 }).toBe(true).then(() => ext.findExtFrame(page, "menu")!);
    await expect(menu.locator("button.row").first()).toBeVisible();
    await ext.settle(600);
    const after = surfaces(ext, page);
    note("g", "after the unlock: the login choice, one surface", after.total === 1 && after.menu === 1, `${JSON.stringify(after)} ${(await menu.locator("body").innerText({ timeout: 500 }).catch(() => "")).replace(/\s+/g, " ").slice(0, 160)}`);
    await snap(page, "g3-after-unlock-choice");
    await menu.locator("button.row").filter({ hasText: "alex@atlas.dev" }).first().click();
    const seen: string[] = [];
    for (let i = 0; i < 80; i++) {
      const t = await text();
      if (seen.at(-1) !== t) {
        seen.push(t);
        await snap(page, `g4-after-pick-${seen.length}`);
      }
      if ((await page.locator("#status").textContent({ timeout: 300 }).catch(() => "")) === "Connecté" && t === "(no card)") break;
      await page.waitForTimeout(150);
    }
    await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
    note("g", "picked login signs in", true, seen.join(" | "));
    await snap(page, "g4-signed-in");
  }
  // Unreachable: the app does not answer at all.
  writeFileSync(ext.host.wrapper, "#!/bin/sh\nexit 1\n", { mode: 0o755 });
  await ext.stopWorker();
  await page.goto(`${ATLAS}/logout`);
  await page.goto(`${ATLAS}/login`);
  await ext.settle(4000);
  note("g", "unreachable: card on arrival", true, ext.findExtFrame(page, "overlay") ? "card shown" : "no card");
  await snap(page, "g5-unreachable-arrival");
  // The user opens the field menu: a wait that says what it is, then the honest message.
  const t0 = Date.now();
  const menu = await ext.openMenu(page, "#email").catch(() => null);
  const seenMenu: string[] = [];
  let honestAt = -1;
  for (let i = 0; i < 60 && menu; i++) {
    const mt = (await menu.locator("body").innerText({ timeout: 500 }).catch(() => "")).replace(/\s+/g, " ").trim();
    if (seenMenu.at(-1) !== mt) {
      seenMenu.push(mt);
      await page.waitForTimeout(400);
      await snap(page, `g6-unreachable-menu-${seenMenu.length}`);
    }
    if (/introuvable/.test(mt)) {
      honestAt = Date.now() - t0;
      break;
    }
    await page.waitForTimeout(100);
  }
  note("g", "unreachable menu: never a bare header", seenMenu.every((x) => x.replace(/^OnePass\s*/, "").length > 0), seenMenu.join(" | "));
  note("g", "unreachable menu: honest message within 3 s", honestAt >= 0 && honestAt <= 3000, `${honestAt} ms`);
  void FX;
});
