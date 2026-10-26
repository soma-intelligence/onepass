// Scenario drivers of the autofill lab (spec 7.3, 7.4): each one plays a
// scenario the way a user would and returns an Observation for the oracle,
// never a verdict. one_click goes through the real overlay and the sign-in
// chain, menu_fill through the in-field menu (trusted ArrowDown) and the
// site's submit button, lookalike opens the trap copy and looks for the real
// site's item, passkey_control proves the bench's WebAuthn relying party with
// Chromium's virtual authenticator and no extension. The autofill itself is
// reached only through the Driver interface (driver.ts). Driver steps that
// the page cannot satisfy are recorded as observations; only bench failures
// (navigation to a lab host, browser launch, host rate limit) carry `lab:`.
import { createPrivateKey } from "node:crypto";
import type { Frame, Page } from "@playwright/test";
import type { FieldSpec, Site } from "../gen/model.ts";
import { PAGE_PATH } from "../gen/render.ts";
import type { LabEvent } from "../server/ledger.ts";
import type { LabServer } from "../server/server.ts";
import { type PlainBrowser, shadowField, sleep } from "./browser.ts";
import type { Driver } from "./driver.ts";
import type { Observation } from "./oracle.ts";

/** What a scenario runs against: the autofill under test, the lab server, a fresh tab. */
export interface ScenarioEnv {
  driver: Driver;
  server: LabServer;
  newPage(): Promise<Page>;
}

const OVERLAY_WAIT_MS = 15_000;
const CHAIN_WAIT_MS = 60_000;
const LOOKALIKE_WAIT_MS = 5_000;
/** The menu row of the password generator (signup). */
export const GENERATE_ROW = "Générer un mot de passe";

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
 * shadow roots directly, a closed one through its page hook `__labField`).
 * Split OTP cells count for their field. ORed into `acc`, so a value seen
 * once stays seen.
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
      const hook = (window as unknown as { __labField?: (sel: string) => { filled: boolean } | null }).__labField;
      const value = (id: string) => {
        const sel = `[id="${id.replace(/["\\]/g, "\\$&")}"]`;
        for (const r of roots) {
          const el = r.querySelector(sel) as HTMLInputElement | null;
          if (el && "value" in el && el.value !== "") return true;
        }
        return hook?.(sel)?.filled === true;
      };
      return list.filter((f) => value(f.id) || [1, 2, 3, 4, 5, 6].some((k) => value(`${f.id}-${k}`))).map((f) => f.name);
    }, fields).catch(() => [] as string[]);
    for (const name of seen) acc[name] = true;
  }
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
async function waitEvents(server: LabServer, pred: (e: LabEvent[]) => boolean, ms: number): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end && !pred(server.events())) await sleep(200);
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

/** After the page closes, how long requests still in flight get to reach the server before its events are read. */
const LATE_GRACE_MS = 500;

async function finish(env: ScenarioEnv, page: Page | undefined, o: Observation, started: number): Promise<Observation> {
  if (page && o.error === undefined && (await env.driver.rateLimited(page).catch(() => false))) o.error = "lab: rate_limited";
  if (page) await debugDump(page, o);
  o.durationMs = Date.now() - started;
  // Read the events last: a late post (a leak) must not be lost to the next scenario's reset.
  await page?.close().catch(() => undefined);
  await sleep(LATE_GRACE_MS);
  o.events = env.server.events();
  return o;
}

/** one_click: the one-click UI's sign-in with the site's item, then the sign-in progress to its end. */
export async function oneClick(env: ScenarioEnv, site: Site): Promise<Observation> {
  const started = Date.now();
  const o = blank("one_click");
  let page: Page | undefined;
  try {
    page = await env.newPage();
    await goto(page, `https://${site.host}/`);
    const ui = await env.driver.openOneClick(page, OVERLAY_WAIT_MS);
    o.overlayShown = ui !== undefined;
    if (ui && site.itemTitle) o.itemOffered = await ui.offers(site.itemTitle);
    if (ui && site.itemTitle && o.itemOffered) {
      await env.driver.pickAccount(ui, site.itemTitle);
      const end = Date.now() + CHAIN_WAIT_MS;
      for (;;) {
        await snapshotFilled(page, site, o.filled);
        const c = await env.driver.progress(site.host);
        if (c) o.chain = c;
        if ((c && c.status !== "running") || Date.now() >= end) {
          if (process.env.LAB_DEBUG) console.log(`[lab debug] progress ${JSON.stringify(c)} at ${page.url()}`);
          break;
        }
        await sleep(500);
      }
      // The last post can still be in flight when the chain reports done.
      await waitEvents(env.server, signedIn(site), 3_000);
    } else {
      await snapshotFilled(page, site, o.filled);
    }
  } catch (e) {
    o.error = message(e);
  }
  return finish(env, page, o, started);
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

/**
 * Types `value` into the field `id` as a user would: through its locator, or
 * (closed shadow root) by clicking the box its page hook reports and typing.
 */
async function typeField(page: Page, scope: Frame, id: string, value: string): Promise<void> {
  const field = scope.locator(byId(id)).first();
  const end = Date.now() + 10_000;
  for (;;) {
    if ((await field.count().catch(() => 0)) > 0) {
      await field.fill(value, { timeout: Math.max(1, end - Date.now()) });
      return;
    }
    const box = await shadowField(scope, byId(id));
    if (box && box.width > 0 && box.height > 0) {
      await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
      await page.keyboard.type(value);
      return;
    }
    if (Date.now() >= end) throw new Error(`no field ${id}`);
    await sleep(200);
  }
}

/**
 * Submits the form as a user would: its submit button; else (closed shadow
 * root) the page hook that submits the shadow form through its own handler
 * (which copies the values to the light-DOM relay); else (button hidden, as
 * before the password step is revealed) the form itself.
 */
async function submitForm(scope: Frame): Promise<void> {
  const button = scope.locator(byId("lab-submit")).first();
  if (await button.isVisible().catch(() => false)) {
    await button.click({ timeout: 5_000 });
    return;
  }
  await scope.evaluate(() => {
    const hook = (window as unknown as { __labSubmit?: () => void }).__labSubmit;
    if (hook) hook();
    else (document.getElementById("lab-form") as HTMLFormElement | null)?.submit();
  });
}

/** menu_fill: focus the first field offering the menu, ArrowDown, pick the item, then submit. */
export async function menuFill(env: ScenarioEnv, site: Site): Promise<Observation> {
  const started = Date.now();
  const o = blank("menu_fill");
  let page: Page | undefined;
  try {
    page = await env.newPage();
    await goto(page, `https://${site.host}/`);
    const scope = await formScope(page, site);
    const { fields, title } = menuTarget(site);
    if (site.flow === "signup") {
      // Typed by the user before asking for a generated password: never counted as an extension fill.
      const email = site.fields.find((f) => f.role === "email" || f.role === "username");
      if (email && site.account) {
        o.typed = [email.name];
        await typeField(page, scope, email.id, site.account.username).catch(() => undefined);
      }
    }
    const menu = await env.driver.menuFill(page, scope, fields.map((f) => byId(f.id)), title, true);
    o.overlayShown = menu.shown;
    o.itemOffered = menu.offered;
    if (menu.offered) await debugDump(page, o);
    await snapshotFilled(page, site, o.filled);
    await submitForm(scope).catch(() => undefined);
    await waitEvents(env.server, submitted(site), 10_000);
    await waitEvents(env.server, signedIn(site), site.flow === "signup" ? 3_000 : 0);
  } catch (e) {
    o.error = message(e);
  }
  return finish(env, page, o, started);
}

/** lookalike: the trap copy must not get the real site's item; its form is then sent as it is. */
export async function lookalike(env: ScenarioEnv, site: Site): Promise<Observation> {
  const started = Date.now();
  const o = blank("lookalike");
  let page: Page | undefined;
  try {
    if (!site.lookalike) throw new Error("lab: the site has no lookalike host");
    page = await env.newPage();
    await goto(page, `https://${site.lookalike.host}/`);
    await sleep(LOOKALIKE_WAIT_MS);
    const ui = await env.driver.openOneClick(page, 0);
    o.overlayShown = ui !== undefined;
    if (ui && site.itemTitle) o.itemOffered = await ui.offers(site.itemTitle, 1_000);
    const first = site.fields.find((f) => f.role !== "otp");
    if (first) {
      const menu = await env.driver.menuFill(page, page.mainFrame(), [byId(first.id)], site.itemTitle, false, { first: 5_000, next: 0 });
      if (menu.shown) o.overlayShown = true;
      if (menu.offered) o.itemOffered = true;
    }
    await snapshotFilled(page, site, o.filled);
    await submitForm(page.mainFrame()).catch(() => undefined);
    await sleep(1_500);
  } catch (e) {
    o.error = message(e);
  }
  return finish(env, page, o, started);
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
  const top = page.mainFrame();
  await typeField(page, top, id.id, account.username);
  if (site.loginStyle === "username_first") {
    await submitForm(top);
    await page.waitForURL((u) => u.pathname === PAGE_PATH.password, { timeout: 10_000 });
  } else if (site.loginStyle === "email_then_password") {
    const next = page.locator(byId("lab-next")).first();
    // Out of reach in a closed shadow root: Enter in the identifier reveals the password step too.
    if ((await next.count()) > 0) await next.click();
    else await page.keyboard.press("Enter");
  }
  await typeField(page, top, pw.id, account.password);
  await submitForm(top);
  await page.waitForURL((u) => u.pathname === PAGE_PATH.passkey, { timeout: 10_000 });
}

/** passkey_control: Chromium's virtual authenticator holds the site's key; the lab RP must accept it. */
export async function passkeyControl(server: LabServer, plain: PlainBrowser, site: Site): Promise<Observation> {
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
    while (Date.now() < end && !server.events().some((e) => e.kind === "signin" && e.host === site.host)) {
      if (server.events().some((e) => e.kind === "submit" && e.form === "passkey" && !e.ok)) break;
      await sleep(200);
    }
  } catch (e) {
    o.error = message(e);
  }
  o.durationMs = Date.now() - started;
  await page?.close().catch(() => undefined);
  await sleep(LATE_GRACE_MS);
  o.events = server.events();
  return o;
}
