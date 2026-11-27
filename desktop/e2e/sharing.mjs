// End-to-end test of sharing (sharing spec 5 to 14): two accounts, A and B,
// each its own instance of the debug app, against one test mailbox.
//
//   ONEPASS_APP, ONEPASS_EDGEDRIVER, ONEPASS_TEST_MAILBOX_EXE, ONEPASS_SHOTS
//   node e2e/sharing.mjs
//
// A and B become contacts by link and compare their safety numbers; A
// shares a vault with B (Write), B joins, sees and edits its item, A sees
// the edit; A removes B; A sends B a copy of an item, B keeps it; A makes a
// family, invites B, B joins; B enrolls in recovery with A, A asks, B's PC
// shows the request and cancels it.
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir, tmpdir } from "node:os";
import { createInterface } from "node:readline";

const app = process.env.ONEPASS_APP;
const edgedriver = process.env.ONEPASS_EDGEDRIVER;
const mailboxExe = process.env.ONEPASS_TEST_MAILBOX_EXE;
const shots = process.env.ONEPASS_SHOTS ?? join(tmpdir(), "onepass-e2e-shots");
const root = join(tmpdir(), "onepass-e2e-sharing");
if (!app || !edgedriver || !mailboxExe) throw new Error("set ONEPASS_APP, ONEPASS_EDGEDRIVER and ONEPASS_TEST_MAILBOX_EXE");
rmSync(root, { recursive: true, force: true });
mkdirSync(root, { recursive: true });
mkdirSync(join(shots, "sharing"), { recursive: true });

const PASSWORD = "Correct-Cheval-42-Agrafe-Lune";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? " - " + detail : ""}`);
}
const children = [];
process.on("exit", () => children.forEach((c) => c.kill()));

// The test mailbox, on a fixed port: its first line is the base URL.
const caFile = join(root, "ca.pem");
const mailbox = spawn(mailboxExe, ["--port", "47821", "--ca-out", caFile], { stdio: ["ignore", "pipe", "inherit"] });
children.push(mailbox);
const base = await new Promise((resolve, reject) => {
  const lines = createInterface({ input: mailbox.stdout });
  lines.once("line", (l) => resolve(l.trim()));
  mailbox.once("exit", (c) => reject(new Error(`test mailbox exited (${c})`)));
});
console.log(`test mailbox: ${base}`);

const ELEM = "element-6066-11e4-a52f-4f735eb9fb5e";

/** One app instance behind its own tauri-driver. */
async function instance(name, port) {
  const data = join(root, name);
  mkdirSync(data, { recursive: true });
  const driver = spawn(join(homedir(), ".cargo", "bin", "tauri-driver"), ["--port", String(port), "--native-port", String(port + 1), "--native-driver", edgedriver], {
    env: {
      ...process.env,
      ONEPASS_DATA_DIR: data,
      WEBVIEW2_USER_DATA_FOLDER: data + "-webview",
      ONEPASS_LANG: "fr",
      ONEPASS_MAILBOX_URL: base,
      ONEPASS_MAILBOX_CA: caFile,
      ONEPASS_DEVICE_NAME: `PC ${name}`,
      ONEPASS_SYNC_PERIOD_SECS: "3",
      ONEPASS_INVITE_POLL_SECS: "1",
      ONEPASS_E2E_DIALOG: join(root, "dialog.txt"),
      ONEPASS_SYNC_LOG: join(root, `${name}-sync.log`),
    },
    stdio: "ignore",
  });
  children.push(driver);
  const D = `http://127.0.0.1:${port}`;
  for (let i = 0; ; i++) {
    try {
      await fetch(D + "/status");
      break;
    } catch {
      if (i > 40) throw new Error("tauri-driver did not start");
      await sleep(250);
    }
  }
  async function wd(method, path, body) {
    const r = await fetch(D + path, { method, headers: { "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
    const json = await r.json();
    if (!r.ok) throw new Error(`${name} ${method} ${path}: ${JSON.stringify(json.value).slice(0, 300)}`);
    return json.value;
  }
  const session = await wd("POST", "/session", { capabilities: { alwaysMatch: { browserName: "wry", "tauri:options": { application: app } } } });
  const S = `/session/${session.sessionId}`;
  const I = {
    name,
    wd,
    S,
    async find(xpath, timeout = 20000) {
      const end = Date.now() + timeout;
      for (;;) {
        try {
          const e = await wd("POST", `${S}/element`, { using: "xpath", value: xpath });
          const id = e[ELEM] ?? e.ELEMENT ?? Object.values(e)[0];
          if (!id) throw new Error("no element id");
          return id;
        } catch {
          if (Date.now() > end) throw new Error(`${name}: not found: ${xpath}`);
          await sleep(250);
        }
      }
    },
    async exists(xpath) {
      return (await wd("POST", `${S}/elements`, { using: "xpath", value: xpath })).length > 0;
    },
    async click(xpath, timeout) {
      for (let i = 0; ; i++) {
        try {
          return await wd("POST", `${S}/element/${await I.find(xpath, timeout)}/click`, {});
        } catch (e) {
          if (i >= 5 || !/stale|intercepted|not interactable/.test(String(e.message))) throw e;
          await sleep(300);
        }
      }
    },
    type: async (xpath, text) => wd("POST", `${S}/element/${await I.find(xpath)}/value`, { text }),
    clear: async (xpath) => wd("POST", `${S}/element/${await I.find(xpath)}/clear`, {}),
    text: async (xpath, timeout) => wd("GET", `${S}/element/${await I.find(xpath, timeout)}/text`),
    attr: async (xpath, a) => wd("GET", `${S}/element/${await I.find(xpath)}/attribute/${a}`),
    async waitFor(xpath, timeout = 30000) {
      return !!(await I.find(xpath, timeout).catch(() => null));
    },
    async shot(file) {
      await sleep(400);
      const png = await wd("GET", `${S}/screenshot`);
      writeFileSync(join(shots, `${file}.png`), Buffer.from(png, "base64"));
    },
    async quit() {
      await wd("DELETE", S).catch(() => {});
    },
  };
  await wd("POST", `${S}/window/rect`, { width: 1280, height: 800 });
  return I;
}

const button = (label) => `//button[normalize-space(.)='${label}']`;
const sheetAction = (label) => `//dialog[@open]//div[@class='sheet-bar']//button[normalize-space(.)='${label}']`;
const nav = (label) => `//nav//button[.//span[@class='nav-label' and normalize-space(.)='${label}']]`;
const row = (title) => `//div[contains(@class,'list')]//button[contains(@class,'item-row')][.//span[@class='row-title' and normalize-space(.)='${title}']]`;
const menuItem = (label) => `//div[@class='menu']//button[.//span[normalize-space(.)='${label}']]`;
const closeSheet = (I) => I.click("(//dialog[@open])[last()]//div[@class='sheet-bar']/button[1]");
async function settings(I, page) {
  await I.click("//button[@title='Compte']");
  await I.click(menuItem("Réglages"));
  await I.click(`//div[@class='settings-side']//button[.//span[normalize-space(.)='${page}']]`);
}
async function welcome(I) {
  await I.find("//h1[contains(., 'Tous tes mots de passe')]");
  await I.click(button("Continuer"));
  await I.click(button("Continuer"));
  await I.click(button("Commencer"));
  await I.find("//h1[normalize-space(.)='Bienvenue dans Cleon']");
}
async function syncState(I, state, timeout = 60000) {
  const end = Date.now() + timeout;
  let last = "";
  while (Date.now() < end) {
    last = await I.attr("//div[@id='sync-status']", "data-state").catch(() => "");
    if (last === state) return true;
    await sleep(500);
  }
  return last;
}
/** A new account on the Cleon server (the test mailbox), synced. */
async function newAccount(I, name) {
  await welcome(I);
  await I.click("//button[.//span[normalize-space(.)='Créer un coffre']]");
  await I.type("//input[@id='name']", name);
  await I.type("//input[@id='pw']", PASSWORD);
  await I.type("//input[@id='pw2']", PASSWORD);
  await I.click("//form//button[@type='submit']");
  await I.find("//div[@class='secret-key']", 120000);
  await I.click("//input[@id='ok']");
  await I.click(button("Continuer"));
  await I.find(`//*[contains(@class,'hero-greeting') and normalize-space(.)='Bonjour ${name}']`, 60000);
  await settings(I, "Sync");
  const idle = await syncState(I, "idle");
  await closeSheet(I);
  return idle === true;
}
async function newLogin(I, title, vault) {
  if (vault) await I.click(nav(vault));
  await I.click("//button[@title='Nouvel élément']");
  await I.click("//button[contains(@class,'picker-cell')][.//span[normalize-space(.)='Connexion']]");
  await I.type("//input[@id='f-title']", title);
  await I.type("//dialog//label[.//span[@class='field-label' and normalize-space(.)='Identifiant']]//input", "moi@example.com");
  await I.click(sheetAction("Enregistrer"));
  await I.find(`//main//h2[normalize-space(.)='${title}']`);
}
/** Waits until `xpath` exists, running `refresh` between looks. */
async function until(I, xpath, refresh, timeout = 60000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (await I.exists(xpath)) return true;
    if (refresh) await refresh().catch(() => {});
    await sleep(1500);
  }
  return false;
}
const reopen = (I, page) => () => I.click(`//div[@class='settings-side']//button[.//span[normalize-space(.)='${page}']]`);
const home = (I) => () => I.click(nav("Accueil"));
/** Closes every open sheet. */
async function closeAll(I) {
  for (let i = 0; i < 6 && (await I.exists("//dialog[@open]")); i++) await closeSheet(I).catch(() => {});
}
const sheetError = (I) => I.text("(//dialog[@open])[last()]//div[contains(@class,'error')]", 500).catch(() => "");

let A, B;
try {
  // ---- two accounts ----------------------------------------------------------------------
  A = await instance("A", 4560);
  B = await instance("B", 4570);
  check("A's account syncs", await newAccount(A, "Camille"));
  check("B's account syncs", await newAccount(B, "Bastien"));

  // ---- contacts by link -----------------------------------------------------------------------
  await settings(A, "Contacts");
  await A.shot("sharing/01-A-contacts-vide");
  await A.click("//button[@id='contacts-add-link']");
  await A.click("//button[@id='invite-create']");
  const link = (await A.text("//div[@id='invite-link']", 60000)).trim();
  check("A makes an invitation link", link.startsWith("onepass://contact#"), link.slice(0, 18) + "…");
  await A.shot("sharing/02-A-lien");
  await settings(B, "Contacts");
  await B.click("//button[@id='contacts-add-link']");
  await B.type("//input[@id='invite-link-in']", link);
  await B.click("//button[@id='invite-open']");
  check("B's reply reaches A, A pins B", await A.waitFor("//div[@id='invite-done']//div[@data-name='Bastien']", 90000),
    await A.text("//p[@id='invite-error']", 500).catch(() => ""));
  check("A's answer reaches B, B pins A", await B.waitFor("//div[@id='invite-done']//div[@data-name='Camille']", 90000),
    await B.text("//p[@id='invite-error']", 500).catch(() => ""));
  check("a contact added by link is not verified", await B.exists("//div[@id='invite-done']//span[@data-id='unverified']"));
  await B.shot("sharing/03-B-contact-ajoute");
  await closeSheet(A);
  await closeSheet(B);

  // ---- safety numbers -------------------------------------------------------------------------
  await reopen(A, "Contacts")();
  await A.click("//div[@id='contacts-list']//button[@data-name='Bastien']");
  await A.click("//button[@id='contact-compare']");
  const numA = (await A.text("//div[@id='safety-number']")).replace(/\s+/g, " ").trim();
  await reopen(B, "Contacts")();
  await B.click("//div[@id='contacts-list']//button[@data-name='Camille']");
  await B.click("//button[@id='contact-compare']");
  const numB = (await B.text("//div[@id='safety-number']")).replace(/\s+/g, " ").trim();
  check("both PCs show the same safety number", numA === numB && numA.replace(/\D/g, "").length === 60, numA);
  await A.shot("sharing/04-A-numero-de-securite");
  await A.click("//button[@id='safety-match']");
  await B.click("//button[@id='safety-match']");
  await sleep(800);
  await reopen(A, "Contacts")();
  await reopen(B, "Contacts")();
  check("A's contact is verified", (await A.waitFor("//div[@id='contacts-list']//button[@data-name='Bastien']", 5000)) &&
    !(await A.exists("//div[@id='contacts-list']//button[@data-name='Bastien']//span[@data-id='unverified']")));
  check("B's contact is verified", (await B.waitFor("//div[@id='contacts-list']//button[@data-name='Camille']", 5000)) &&
    !(await B.exists("//div[@id='contacts-list']//button[@data-name='Camille']//span[@data-id='unverified']")));
  await A.shot("sharing/05-A-contact-verifie");
  await closeSheet(A);
  await closeSheet(B);

  // ---- a shared vault --------------------------------------------------------------------------
  await A.click("//nav//button[@title='Nouveau coffre']");
  await A.type("//input[@id='v-name']", "Maison");
  await A.click(sheetAction("Enregistrer"));
  await newLogin(A, "Code alarme", "Maison");
  await settings(A, "Coffres");
  await A.click("//div[contains(@class,'settings-pane')]//button[.//span[normalize-space(.)='Maison']]");
  await A.click("//button[@id='vault-share']");
  await A.click("//div[@id='share-contacts']//div[@data-name='Bastien']");
  await A.click("//div[@id='share-role']//button[@data-role='write']");
  await A.shot("sharing/06-A-partager-le-coffre");
  await A.click(sheetAction("Partager"));
  const shared = await A.waitFor("//div[@id='toast' and contains(., 'Invitation envoyée')]", 90000);
  check("A shares Maison with B (Write)", shared, shared ? "" : await sheetError(A));
  await closeAll(A);
  check("Maison shows as shared on A", await until(A, "//nav//button[.//span[normalize-space(.)='Maison']]//span[contains(@class,'shared-mark')]", home(A), 30000));
  check("B sees the invitation", await until(B, "//button[@id='banner-invites']", home(B), 90000));
  await B.shot("sharing/07-B-invitation");
  await B.click("//button[@id='banner-invites']");
  await B.shot("sharing/08-B-invitations");
  await B.click("//button[@id='invite-accept']");
  check("B joined Maison", await until(B, nav("Maison"), home(B), 90000), await sheetError(B));
  await B.click(nav("Maison"));
  check("B sees the shared item", await until(B, row("Code alarme"), () => B.click(nav("Maison")), 90000));
  await B.shot("sharing/09-B-coffre-partage");

  // B edits (Write), A sees it.
  await B.click(row("Code alarme"));
  await B.click("//main//button[normalize-space(.)='Modifier']");
  await B.clear("//input[@id='f-title']");
  await B.type("//input[@id='f-title']", "Code alarme garage");
  await B.click(sheetAction("Enregistrer"));
  check("B can edit with Write", await B.waitFor("//main//h2[normalize-space(.)='Code alarme garage']", 15000), await sheetError(B));
  await A.click(nav("Maison"));
  check("B's edit reaches A", await until(A, row("Code alarme garage"), () => A.click(nav("Maison")), 90000));
  await A.shot("sharing/10-A-voit-la-modif-de-B");

  // Members, then the removal.
  await settings(A, "Coffres");
  await A.click("//div[contains(@class,'settings-pane')]//button[.//span[normalize-space(.)='Maison']]");
  await A.click("//button[@id='vault-members']");
  check("A's member list shows B with Write", await A.waitFor("//div[@id='members-list']//div[@data-name='Bastien']//span[contains(., 'Écriture')]", 20000));
  await A.shot("sharing/11-A-membres");
  await A.click("//div[@id='members-list']//button[@data-name='Bastien']");
  await A.click(menuItem("Retirer"));
  await A.click("//button[@id='member-remove-confirm']");
  const prompt = await A.text("//p[@id='removal-prompt']", 30000).catch(() => "");
  check("the removal says what B could keep", prompt.includes("Bastien ne verra plus rien de nouveau dans Maison"), prompt || (await sheetError(A)));
  await A.shot("sharing/12-A-retrait");
  await closeAll(A);
  check("Maison leaves B after the removal", await until(B, "//nav[not(.//span[@class='nav-label' and normalize-space(.)='Maison'])]", home(B), 120000));
  await B.shot("sharing/13-B-apres-retrait");

  // ---- send a copy of an item ----------------------------------------------------------------------
  await newLogin(A, "Banque", "Personnel");
  await A.click("//main//button[@title='Actions']");
  await A.click(menuItem("Envoyer une copie…"));
  await A.click("//div[@id='send-contacts']//div[@data-name='Bastien']");
  await A.shot("sharing/14-A-envoyer-une-copie");
  await A.click(sheetAction("Envoyer"));
  check("A sends a copy", await A.waitFor("//div[@id='toast' and contains(., 'Copie envoyée')]", 15000), await sheetError(A));
  check("B sees the received item", await until(B, "//button[@id='banner-received']", home(B), 90000));
  await B.click("//button[@id='banner-received']");
  await B.shot("sharing/15-B-elements-recus");
  await B.click("//button[@id='received-keep']");
  await B.click(nav("Tous les éléments"));
  check("B keeps the copy", await until(B, row("Banque"), () => B.click(nav("Tous les éléments")), 20000));

  // ---- family ----------------------------------------------------------------------------------------
  await settings(A, "Famille");
  await A.shot("sharing/16-A-famille-vide");
  await A.click("//button[@id='family-create']");
  check("A creates a family", await A.waitFor("//button[@id='family-invite']", 120000), await sheetError(A));
  await A.click("//button[@id='family-invite']");
  await A.click("//div[@id='family-invite-list']//div[@data-name='Bastien']//button[contains(@class,'family-as-member')]");
  check("A invites B", await A.waitFor("//div[@id='toast' and contains(., 'Invitation envoyée')]", 10000), await sheetError(A));
  await closeSheet(A);
  await settings(B, "Famille");
  check("B sees the family invitation", await until(B, "//button[@id='family-join']", reopen(B, "Famille"), 90000));
  await B.shot("sharing/17-B-invitation-famille");
  await B.click("//button[@id='family-join']");
  check("B joined A's family", await until(B, "//div[@id='family-members']//div[@data-name='Camille']", reopen(B, "Famille"), 60000), await sheetError(B));
  await B.shot("sharing/18-B-famille");
  await settings(A, "Famille");
  check("A sees B in the family", await until(A, "//div[@id='family-members']//div[@data-name='Bastien']", reopen(A, "Famille"), 90000));
  await A.shot("sharing/19-A-famille");
  await closeSheet(A);

  // ---- recovery with A's help: enroll, request, the alert, cancel ---------------------------------------
  await B.click("//button[@id='recovery-enroll']");
  await B.click("//input[@id='enroll-understood']");
  await B.type("//input[@id='enroll-pw']", PASSWORD);
  await B.shot("sharing/20-B-recuperation");
  await B.click(sheetAction("Activer"));
  check("B enrolls with A as organizer", await until(B, "//div[@id='recovery-enrolled']", reopen(B, "Famille"), 30000), await sheetError(B));
  await closeSheet(B);
  await settings(A, "Famille");
  check("A sees that B chose it", await until(A, "//button[contains(@class,'helper-row')]", reopen(A, "Famille"), 90000));
  await A.click("//button[contains(@class,'helper-row')]");
  await A.type("//input[@id='helper-pw']", PASSWORD);
  await A.click("//button[@id='helper-request']");
  check("A's request starts the delay", await A.waitFor("//div[@id='helper-waiting']", 30000), await sheetError(A));
  await A.shot("sharing/21-A-demande");
  await closeAll(A);
  check("B's PC shows the recovery request", await until(B, "//div[@id='recovery-alert']", home(B), 90000));
  await B.shot("sharing/22-B-alerte-recuperation");
  await B.click("//button[@id='recovery-cancel']");
  await settings(A, "Famille");
  await A.click("//button[contains(@class,'helper-row')]");
  check("A sees the cancel", await until(A, "//p[@id='helper-cancelled']", async () => {
    await closeSheet(A);
    await A.click("//button[contains(@class,'helper-row')]");
  }, 90000));
  await A.shot("sharing/23-A-annulee");
} catch (e) {
  check("run", false, String(e.message ?? e));
  for (const I of [A, B]) if (I) await I.shot(`sharing/zz-failure-${I.name}`).catch(() => {});
} finally {
  for (const I of [A, B]) if (I) await I.quit();
}

if (results.some((r) => !r.ok)) {
  for (const n of ["A", "B"]) {
    try {
      const log = readFileSync(join(root, `${n}-sync.log`), "utf8").trim().split(/\r?\n/);
      console.log(`--- ${n} sync log (last 12)`);
      console.log(log.slice(-12).join("\n"));
    } catch {}
  }
}
writeFileSync(join(shots, "sharing", "results.json"), JSON.stringify(results, null, 2));
const failed = results.filter((r) => !r.ok).length;
console.log(`${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
