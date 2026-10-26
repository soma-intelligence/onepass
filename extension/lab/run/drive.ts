// Scenario drivers of the autofill lab (spec 7.3, 7.4): each one plays a
// scenario the way a user would and returns an Observation for the oracle,
// never a verdict. one_click goes through the real overlay and the sign-in
// chain, menu_fill through the in-field menu (trusted ArrowDown) and the
// site's submit button, lookalike opens the trap copy and looks for the real
// site's item, passkey_control proves the bench's WebAuthn relying party with
// Chromium's virtual authenticator and no extension. Driver steps that the
// page cannot satisfy are recorded as observations; only bench failures
// (navigation to a lab host, browser launch, host rate limit) carry `lab:`.
import { createPrivateKey } from "node:crypto";
import type { Frame, Page } from "@playwright/test";
import type { FieldSpec, Site } from "../gen/model.ts";
import { PAGE_PATH } from "../gen/render.ts";
import type { LabEvent } from "../server/ledger.ts";
import { type Lab, type PlainBrowser, sleep } from "./browser.ts";
import type { Observation } from "./oracle.ts";

const OVERLAY_WAIT_MS = 15_000;
const CHAIN_WAIT_MS = 60_000;
const LOOKALIKE_WAIT_MS = 5_000;
/** The menu row of the password generator (signup). */
export const GENERATE_ROW = "Générer un mot de passe";
const RATE_LIMITED_TEXT = "Trop de demandes";

/** CSS selector of an element id (generated ids may start with a digit). */
const byId = (id: string) => `[id="${id.replace(/["\\]/g, "\\$&")}"]`;

function blank(driver: Observation["driver"]): Observation {
  return { driver, overlayShown: false, itemOffered: false, events: [], filled: {}, durationMs: 0 };
}

function message(e: unknown): string {
  return ((e as Error)?.message ?? String(e)).split("\n")[0] ?? "error";
}

async function goto(page: Page, url: string): Promise<void> {
  try {
    await page.goto(url);
  } catch (e) {
    throw new Error(`lab: navigation to ${url} failed: ${message(e)}`);
  }
}

/**
 * Which of the site's fields hold a value, in every frame of the page (open
 * shadow roots included; closed ones are out of reach). Split OTP cells
 * count for their field. ORed into `acc`, so a value seen once stays seen.
 */
async function snapshotFilled(page: Page, site: Site, acc: Record<string, boolean>): Promise<void> {
  const fields = site.fields.map((f) => ({ id: f.id, name: f.name }));
  for (const f of fields) acc[f.name] ??= false;
  for (const frame of page.frames()) {
    if (frame.url().startsWith("chrome-extension://")) continue;
    const seen = await frame.evaluate((list) => {
      const roots: (Document | ShadowRoot)[] = [document];
      for (let k = 0; k < roots.length; k++) {
        for (const el of roots[k]!.querySelectorAll("*")) if (el.shadowRoot) roots.push(el.shadowRoot);
      }
      const value = (id: string) => {
        for (const r of roots) {
          const el = r.querySelector(`[id="${id.replace(/["\\]/g, "\\$&")}"]`) as HTMLInputElement | null;
          if (el && "value" in el && el.value !== "") return true;
        }
        return false;
      };
      return list.filter((f) => value(f.id) || [1, 2, 3, 4, 5, 6].some((k) => value(`${f.id}-${k}`))).map((f) => f.name);
    }, fields).catch(() => [] as string[]);
    for (const name of seen) acc[name] = true;
  }
}

/** Whether an extension frame of the page says the native host refused for rate limiting. */
async function rateLimited(page: Page): Promise<boolean> {
  for (const f of page.frames()) {
    if (!f.url().startsWith("chrome-extension://")) continue;
    const text = await f.locator("body").innerText({ timeout: 1_000 }).catch(() => "");
    if (text.includes(RATE_LIMITED_TEXT)) return true;
  }
  return false;
}

/** The frame holding the site's form: its /frame document for framed sites, else the top document. */
async function formScope(page: Page, site: Site): Promise<Frame> {
  if (!site.traits.includes("iframe_same_origin") && !site.traits.includes("iframe_cross_site")) return page.mainFrame();
  const end = Date.now() + 10_000;
  for (;;) {
    const f = page.frames().find((x) => x !== page.mainFrame() && !x.url().startsWith("chrome-extension://")
      && x.url().includes(PAGE_PATH.frame));
    if (f) return f;
    if (Date.now() >= end) return page.mainFrame();
    await sleep(200);
  }
}

/** Waits until `pred` holds over the server events, or `ms` elapse. */
async function waitEvents(lab: Lab, pred: (e: LabEvent[]) => boolean, ms: number): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end && !pred(lab.server.events())) await sleep(200);
}

const signedIn = (site: Site) => (es: LabEvent[]) => es.some((e) => e.kind === "signin" && e.host === site.host);
const submitted = (site: Site) => (es: LabEvent[]) =>
  es.some((e) => (e.kind === "submit" || e.kind === "signin") && (e.host === site.host || e.host === site.frameHost));

/** LAB_DEBUG: the page as the driver left it (screenshot, URL, extension frame text) under <LAB_DEBUG>/. */
async function debugDump(page: Page, o: Observation): Promise<void> {
  const dir = process.env.LAB_DEBUG;
  if (!dir) return;
  const name = `${o.driver}-${Date.now()}`;
  await page.screenshot({ path: `${dir}/${name}.png`, fullPage: true }).catch(() => undefined);
  const frames: string[] = [];
  for (const f of page.frames()) {
    const text = f.url().startsWith("chrome-extension://") ? await f.locator("body").innerText({ timeout: 1_000 }).catch(() => "") : "";
    frames.push(`${f.url()} ${text.replace(/\s+/g, " ").slice(0, 300)}`);
  }
  console.log(`[lab debug] ${name} url=${page.url()}\n  ${frames.join("\n  ")}`);
}

async function finish(lab: Lab, page: Page | undefined, o: Observation, started: number): Promise<Observation> {
  if (page && o.error === undefined && (await rateLimited(page).catch(() => false))) o.error = "lab: rate_limited";
  if (page) await debugDump(page, o);
  o.events = lab.server.events();
  o.durationMs = Date.now() - started;
  await page?.close().catch(() => undefined);
  return o;
}

/** one_click: the overlay's "Se connecter" on the site's item, then the chain to its end. */
export async function oneClick(lab: Lab, site: Site): Promise<Observation> {
  const started = Date.now();
  const o = blank("one_click");
  let page: Page | undefined;
  try {
    page = await lab.newPage();
    await goto(page, `https://${site.host}/`);
    const overlay = await lab.waitExtFrame(page, "overlay", OVERLAY_WAIT_MS);
    o.overlayShown = overlay !== undefined;
    if (overlay && site.itemTitle) o.itemOffered = await lab.overlayHas(overlay, site.itemTitle);
    if (overlay && site.itemTitle && o.itemOffered) {
      await lab.overlayStart(overlay, site.itemTitle);
      const end = Date.now() + CHAIN_WAIT_MS;
      for (;;) {
        await snapshotFilled(page, site, o.filled);
        const c = await lab.chainState(site.host).catch(() => null);
        if (c) o.chain = { status: c.status, ...(c.reason !== undefined ? { reason: c.reason } : {}) };
        if ((c && c.status !== "running") || Date.now() >= end) {
          if (process.env.LAB_DEBUG) console.log(`[lab debug] chain ${JSON.stringify(c)}`);
          break;
        }
        await sleep(500);
      }
      // The last post can still be in flight when the chain reports done.
      await waitEvents(lab, signedIn(site), 3_000);
    } else {
      await snapshotFilled(page, site, o.filled);
    }
  } catch (e) {
    o.error = message(e);
  }
  return finish(lab, page, o, started);
}

/**
 * The fields the menu is tried in, in order, and the menu row picked there.
 * The extension offers its menu on some roles only (a card form opens it from
 * the number, not the cardholder name): like a user, the driver moves on to
 * the next field of the form when the first one offers no menu.
 */
function menuTarget(site: Site): { fields: FieldSpec[]; title: string | undefined } {
  if (site.flow === "signup") return { fields: site.fields.filter((f) => f.role === "new_password").slice(0, 1), title: GENERATE_ROW };
  return { fields: site.fields, title: site.cardTitle ?? site.identityTitle ?? site.itemTitle };
}

/** Submits the form as a user would: its submit button, else (closed shadow root) the light-DOM relay. */
async function submitForm(scope: Frame): Promise<void> {
  const button = scope.locator(byId("lab-submit")).first();
  if (await button.isVisible().catch(() => false)) {
    await button.click({ timeout: 5_000 });
    return;
  }
  await scope.evaluate(() => (document.getElementById("lab-form") as HTMLFormElement | null)?.submit());
}

/** menu_fill: focus the first field offering the menu, ArrowDown, pick the item, then submit. */
export async function menuFill(lab: Lab, site: Site): Promise<Observation> {
  const started = Date.now();
  const o = blank("menu_fill");
  let page: Page | undefined;
  try {
    page = await lab.newPage();
    await goto(page, `https://${site.host}/`);
    const scope = await formScope(page, site);
    const { fields, title } = menuTarget(site);
    if (site.flow === "signup") {
      // Typed by the user before asking for a generated password.
      const email = site.fields.find((f) => f.role === "email" || f.role === "username");
      if (email && site.account) await scope.locator(byId(email.id)).first().fill(site.account.username, { timeout: 10_000 }).catch(() => undefined);
    }
    let menu: Frame | undefined;
    for (const [k, f] of fields.entries()) {
      // The first field waits for delayed fields; the next ones are already there.
      menu = await lab.openMenu(page, scope, byId(f.id), k === 0 ? 10_000 : 3_000).catch(() => undefined);
      if (menu) break;
    }
    o.overlayShown = menu !== undefined;
    if (menu && title) o.itemOffered = await lab.menuRow(menu, title);
    if (menu && title && o.itemOffered) {
      await lab.pickRow(menu, title);
      await sleep(1_500);
      if (process.env.LAB_DEBUG) await debugDump(page, o);
    }
    await snapshotFilled(page, site, o.filled);
    await submitForm(scope).catch(() => undefined);
    await waitEvents(lab, submitted(site), 10_000);
    await waitEvents(lab, signedIn(site), site.flow === "signup" ? 3_000 : 0);
  } catch (e) {
    o.error = message(e);
  }
  return finish(lab, page, o, started);
}

/** lookalike: the trap copy must not get the real site's item; its form is then sent as it is. */
export async function lookalike(lab: Lab, site: Site): Promise<Observation> {
  const started = Date.now();
  const o = blank("lookalike");
  let page: Page | undefined;
  try {
    if (!site.lookalike) throw new Error("lab: the site has no lookalike host");
    page = await lab.newPage();
    await goto(page, `https://${site.lookalike.host}/`);
    await sleep(LOOKALIKE_WAIT_MS);
    const overlay = lab.findExtFrame(page, "overlay");
    o.overlayShown = overlay !== undefined;
    if (overlay && site.itemTitle) o.itemOffered = await lab.overlayHas(overlay, site.itemTitle, 1_000);
    const first = site.fields.find((f) => f.role !== "otp");
    if (first) {
      const menu = await lab.openMenu(page, page.mainFrame(), byId(first.id), 5_000).catch(() => undefined);
      if (menu) {
        o.overlayShown = true;
        if (site.itemTitle && (await lab.menuRow(menu, site.itemTitle, 2_000))) o.itemOffered = true;
        await page.keyboard.press("Escape");
      }
    }
    await snapshotFilled(page, site, o.filled);
    await submitForm(page.mainFrame()).catch(() => undefined);
    await sleep(1_500);
  } catch (e) {
    o.error = message(e);
  }
  return finish(lab, page, o, started);
}

/** PKCS#8 DER (base64) of the site's P-256 passkey, for WebAuthn.addCredential. */
export function passkeyPkcs8(key: { d: string; x: string; y: string }): string {
  const jwk = { kty: "EC", crv: "P-256", x: key.x, y: key.y, d: Buffer.from(key.d, "hex").toString("base64url") };
  return createPrivateKey({ key: jwk, format: "jwk" }).export({ type: "pkcs8", format: "der" }).toString("base64");
}

/** Types the password step by hand (passkey control: no extension), in the site's login style. */
async function typePassword(page: Page, site: Site): Promise<void> {
  const account = site.account!;
  const id = site.fields.find((f) => f.role === "username" || f.role === "email");
  const pw = site.fields.find((f) => f.role === "password");
  if (!id || !pw) throw new Error("lab: password-then-passkey site without identifier or password field");
  const fill = (f: FieldSpec, v: string) => page.locator(byId(f.id)).first().fill(v, { timeout: 10_000 });
  await fill(id, account.username);
  if (site.loginStyle === "username_first") {
    await page.locator(byId("lab-submit")).first().click();
    await page.waitForURL((u) => u.pathname === PAGE_PATH.password, { timeout: 10_000 });
  } else if (site.loginStyle === "email_then_password") {
    await page.locator(byId("lab-next")).first().click();
  }
  await fill(pw, account.password);
  await page.locator(byId("lab-submit")).first().click();
  await page.waitForURL((u) => u.pathname === PAGE_PATH.passkey, { timeout: 10_000 });
}

/** passkey_control: Chromium's virtual authenticator holds the site's key; the lab RP must accept it. */
export async function passkeyControl(lab: Pick<Lab, "server">, plain: PlainBrowser, site: Site): Promise<Observation> {
  const started = Date.now();
  // Not an extension scenario: the UI flags hold so that a failure is explained by the RP's refusal.
  const o: Observation = { ...blank("passkey_control"), overlayShown: true, itemOffered: true };
  let page: Page | undefined;
  try {
    const key = site.account?.passkey;
    if (!key) throw new Error("lab: the site has no passkey");
    page = await plain.context.newPage();
    const cdp = await plain.context.newCDPSession(page);
    await cdp.send("WebAuthn.enable", { enableUI: false });
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
        isUserVerified: true, automaticPresenceSimulation: true,
      },
    });
    await cdp.send("WebAuthn.addCredential", {
      authenticatorId,
      credential: {
        credentialId: Buffer.from(key.credentialId, "base64url").toString("base64"),
        isResidentCredential: false, rpId: site.host, privateKey: passkeyPkcs8(key), signCount: 0,
      },
    });
    await goto(page, `https://${site.host}/`);
    if (!site.passkeyOnly) await typePassword(page, site);
    await page.locator(byId("lab-passkey")).first().click({ timeout: 10_000 });
    const end = Date.now() + 15_000;
    while (Date.now() < end && !lab.server.events().some((e) => e.kind === "signin" && e.host === site.host)) {
      if (lab.server.events().some((e) => e.kind === "submit" && e.form === "passkey" && !e.ok)) break;
      await sleep(200);
    }
  } catch (e) {
    o.error = message(e);
  }
  o.events = lab.server.events();
  o.durationMs = Date.now() - started;
  await page?.close().catch(() => undefined);
  return o;
}
