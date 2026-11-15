// End-to-end test of sync: three instances of the debug app (each its own
// data folder and WebView2 folder) against one test mailbox process.
//
//   ONEPASS_APP=<path to debug onepass-desktop.exe>
//   ONEPASS_TEST_MAILBOX_EXE=<path to test-mailbox.exe (cargo build --features test-mailbox)>
//   ONEPASS_EDGEDRIVER=<msedgedriver.exe of the installed WebView2>
//   ONEPASS_SHOTS=<folder for the screenshots>
//   node e2e/sync.mjs
//
// A creates an account on the "OnePass server" (the test mailbox, through
// ONEPASS_MAILBOX_URL, debug builds only) and adds an item; B restores it
// from the Emergency Kit and sees the item; an edit on B reaches A; C joins
// as a new device with A's code; then Travel Mode goes and comes back on A.
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir, tmpdir } from "node:os";
import { createInterface } from "node:readline";

const app = process.env.ONEPASS_APP;
const edgedriver = process.env.ONEPASS_EDGEDRIVER;
const mailboxExe = process.env.ONEPASS_TEST_MAILBOX_EXE;
const shots = process.env.ONEPASS_SHOTS ?? join(tmpdir(), "onepass-e2e-shots");
const root = join(tmpdir(), "onepass-e2e-sync");
if (!app || !edgedriver || !mailboxExe) throw new Error("set ONEPASS_APP, ONEPASS_EDGEDRIVER and ONEPASS_TEST_MAILBOX_EXE");
rmSync(root, { recursive: true, force: true });
mkdirSync(root, { recursive: true });
mkdirSync(join(shots, "sync"), { recursive: true });

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
const mailbox = spawn(mailboxExe, ["--port", "47811", "--ca-out", caFile], { stdio: ["ignore", "pipe", "inherit"] });
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
      ONEPASS_SYNC_PERIOD_SECS: "4",
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
  await I.find("//h1[normalize-space(.)='Bienvenue dans OnePass']");
}
/** Settings > Sync until its status is `state` (or `timeout`). */
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

let A, B, C;
try {
  // ---- A: a new account on the OnePass server --------------------------------------------
  A = await instance("A", 4460);
  await welcome(A);
  await A.shot("sync/01-A-bienvenue");
  await A.click("//button[.//span[normalize-space(.)='Créer un coffre']]");
  check("the account creation names the OnePass server by default", (await A.text("//button[@id='sync-choice']")).includes("Serveur OnePass"));
  await A.click("//button[@id='sync-choice']");
  await A.find("//dialog[@open]//button[@id='sync-option-selfHost']");
  await A.click("//dialog[@open]//button[@id='sync-option-selfHost']");
  await A.type("//input[@id='sync-url']", "http://pas-https.example");
  check("a self-host URL must be https", (await A.text("//dialog[@open]//p[contains(@class,'error-text')]")).includes("https://"));
  await A.clear("//input[@id='sync-url']");
  await A.type("//input[@id='sync-url']", base);
  await A.wd("POST", `${A.S}/execute/sync`, { script: "document.getElementById('sync-ca').value = arguments[0]", args: [await (await import("node:fs/promises")).readFile(caFile, "utf8")] });
  await A.click("//button[@id='sync-test']");
  const tested = await (async () => {
    for (let i = 0; i < 40; i++) {
      const t = await A.text("//span[@id='sync-test-result']").catch(() => "");
      if (t && t !== "…") return t;
      await sleep(250);
    }
    return "";
  })();
  check("Tester reaches a self-hosted server", tested.includes("Le serveur répond"), tested);
  await A.shot("sync/02-A-ou-est-range-mon-coffre");
  await A.click("//dialog[@open]//button[@id='sync-option-hosted']");
  await A.click(sheetAction("Terminé"));
  await A.type("//input[@id='name']", "Camille");
  await A.type("//input[@id='pw']", PASSWORD);
  await A.type("//input[@id='pw2']", PASSWORD);
  await A.click("//form//button[@type='submit']");
  await A.find("//div[@class='secret-key']", 120000);
  const secretKey = (await A.text("//div[@class='secret-key']")).replace(/\s/g, "");
  await A.click("//input[@id='ok']");
  await A.click(button("Continuer"));
  await A.find("//h1[normalize-space(.)='Bonjour Camille']", 60000);
  await settings(A, "Sync");
  const aIdle = await syncState(A, "idle");
  check("A's mailbox is set up and synced", aIdle === true, String(aIdle));
  check("Settings > Sync names the OnePass server", (await A.text("//div[@id='sync-backend']")).includes("Serveur OnePass"));
  await A.shot("sync/03-A-reglages-sync");
  await closeSheet(A);

  await A.click("//button[normalize-space(.)='Créer ton premier élément']");
  await A.click("//button[contains(@class,'picker-cell')][.//span[normalize-space(.)='Connexion']]");
  await A.type("//input[@id='f-title']", "Banque");
  await A.type("//input[@id='f-url']", "https://www.banque.fr");
  await A.type("//dialog//label[.//span[@class='field-label' and normalize-space(.)='Identifiant']]//input", "camille@example.com");
  await A.click(sheetAction("Enregistrer"));
  await A.find("//main//h2[normalize-space(.)='Banque']");
  await sleep(3000);
  await settings(A, "Sync");
  await A.click("//button[@id='sync-now']");
  check("A sends the new item", (await syncState(A, "idle")) === true);
  await closeSheet(A);

  // ---- B: restore from the Emergency Kit --------------------------------------------------
  B = await instance("B", 4470);
  await welcome(B);
  await B.click("//button[.//span[normalize-space(.)='Restaurer avec mon Emergency Kit']]");
  await B.type("//input[@id='restore-key']", secretKey.toLowerCase());
  await B.type("//input[@id='restore-pw']", "pas-le-bon-mot-de-passe");
  await B.click("//button[@id='restore-go']");
  const wrong = await (async () => {
    for (let i = 0; i < 240; i++) {
      const t = await B.text("//form//div[contains(@class,'error')]").catch(() => "");
      if (t) return t;
      await sleep(500);
    }
    return "";
  })();
  check("a wrong master password is refused, nothing kept", wrong.includes("Mot de passe incorrect"), wrong);
  await B.shot("sync/04-B-kit-mauvais-mot-de-passe");
  await B.type("//input[@id='restore-pw']", PASSWORD);
  await B.click("//button[@id='restore-go']");
  await B.find("//nav//button[@title='Compte' or contains(@class,'account')]", 180000);
  await B.click(nav("Tous les éléments"));
  check("B restored from the kit sees A's item", await B.waitFor(row("Banque"), 20000));
  await B.shot("sync/05-B-restaure");

  // ---- an edit on B reaches A --------------------------------------------------------------
  await B.click(row("Banque"));
  await B.find("//main//h2[normalize-space(.)='Banque']");
  await B.click("//main//button[normalize-space(.)='Modifier']");
  await B.clear("//input[@id='f-title']");
  await B.type("//input[@id='f-title']", "Banque Pro");
  await B.click(sheetAction("Enregistrer"));
  await B.find("//main//h2[normalize-space(.)='Banque Pro']");
  await A.click(nav("Tous les éléments"));
  check("B's edit appears on A without a click", await A.waitFor(row("Banque Pro"), 60000));
  await A.shot("sync/06-A-voit-la-modif-de-B");

  // ---- C joins with A's code -----------------------------------------------------------------
  C = await instance("C", 4480);
  await welcome(C);
  await C.click("//button[.//span[normalize-space(.)='Ajouter cet appareil']]");
  await settings(A, "Appareils");
  await A.click("//button[@id='add-device']");
  const code = (await A.text("//div[@id='host-code']", 60000)).trim();
  check("A shows a pairing code", /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code), code.replace(/./g, "•"));
  await A.shot("sync/07-A-code-appairage");
  await C.type("//input[@id='join-code']", code);
  await C.click("//button[@id='join-go']");
  await C.find("//div[@id='pair-sas']", 60000);
  const sas = (await C.text("//div[@id='pair-sas']")).replace(/\D/g, "");
  check("C shows the 6 digits", sas.length === 6);
  await C.shot("sync/08-C-compare-les-codes");
  await A.find("//div[@id='host-peer']", 30000);
  await A.type("//input[@id='host-sas']", "000000");
  await A.type("//input[@id='host-pw']", PASSWORD);
  await A.click("//button[@id='host-approve']");
  check("A refuses digits that differ", (await A.text("//dialog[@open]//div[contains(@class,'error')]")).includes("pas le code"));
  await A.clear("//input[@id='host-sas']");
  await A.type("//input[@id='host-sas']", sas);
  await A.clear("//input[@id='host-pw']");
  await A.type("//input[@id='host-pw']", PASSWORD);
  await A.shot("sync/09-A-approuve");
  await A.click("//button[@id='host-approve']");
  await C.click("//button[@id='join-match']");
  await C.find("//input[@id='join-pw']", 120000);
  await C.shot("sync/10-C-mot-de-passe");
  await C.type("//input[@id='join-pw']", PASSWORD);
  await C.click("//button[@id='join-unlock']");
  await C.find("//nav//button[contains(@class,'account')]", 180000);
  await C.click(nav("Tous les éléments"));
  check("C joined and sees the account's items", await C.waitFor(row("Banque Pro"), 30000));
  check("A says the device was added", await A.waitFor("//h2[@id='host-done']", 30000));
  await A.shot("sync/11-A-appareil-ajoute");
  await closeSheet(A);
  await closeSheet(A);
  await settings(C, "Sync");
  check("C syncs through the mailbox", (await syncState(C, "idle")) === true);
  await closeSheet(C);
  await settings(A, "Appareils");
  // B was restored with the kit: A trusts it (spec 7.5).
  let kitRow = false;
  for (let i = 0; i < 20 && !kitRow; i++) {
    kitRow = await A.exists("//dialog[@open]//div[contains(@class,'kit-row')]");
    if (!kitRow) {
      await sleep(1500);
      await A.click(`//div[@class='settings-side']//button[.//span[normalize-space(.)='Appareils']]`);
    }
  }
  check("A sees B, restored with the kit, asking for trust", kitRow);
  if (kitRow) {
    await A.shot("sync/12a-A-restaure-par-kit");
    await A.click("//dialog[@open]//div[contains(@class,'kit-row')]//button[normalize-space(.)='Faire confiance']");
    await A.type("//input[@id='kit-pw']", PASSWORD);
    await A.click(sheetAction("Faire confiance"));
    await sleep(2000);
    check("A trusts B", !(await A.exists("//dialog[@open]//div[contains(@class,'kit-row')]")), await A.text("(//dialog[@open])[last()]//div[contains(@class,'error')]", 500).catch(() => ""));
  }
  let devices = [];
  for (let i = 0; i < 20; i++) {
    devices = await A.wd("POST", `${A.S}/elements`, { using: "xpath", value: "//dialog[@open]//button[contains(@class,'device-row')]" });
    if (devices.length === 3) break;
    await sleep(1500);
    await A.click(`//div[@class='settings-side']//button[.//span[normalize-space(.)='Appareils']]`);
  }
  check("A's device list holds A, B and C", devices.length === 3, String(devices.length));
  await A.shot("sync/12-A-appareils");
  await closeSheet(A);

  // ---- an item made on C reaches B -----------------------------------------------------------
  await C.click("//button[@title='Nouvel élément']");
  await C.click("//button[contains(@class,'picker-cell')][.//span[normalize-space(.)='Connexion']]");
  await C.type("//input[@id='f-url']", "https://www.exemple-c.fr");
  await C.type("//dialog//label[.//span[@class='field-label' and normalize-space(.)='Identifiant']]//input", "c@example.com");
  await C.type("//input[@id='f-title']", "Note de C");
  await C.click(sheetAction("Enregistrer"));
  const saved = await C.waitFor("//main//h2[normalize-space(.)='Note de C']", 8000);
  check("C writes to the account", saved, saved ? "" : await C.text("//dialog[@open]//div[contains(@class,'error')]", 1000).catch(() => ""));
  if (!saved) await closeSheet(C);
  await B.click(nav("Tous les éléments"));
  check("an item made on C appears on B", await B.waitFor(row("Note de C"), 60000));

  // ---- Travel Mode, now that the vaults are synced -------------------------------------------
  await settings(A, "Sync");
  await A.click("//button[@id='sync-now']");
  await syncState(A, "idle");
  await A.click(`//div[@class='settings-side']//button[.//span[normalize-space(.)='Travel Mode']]`);
  await A.click("//dialog[@open]//button[normalize-space(.)='Activer le Travel Mode']");
  await A.click(sheetAction("Activer"));
  check("Travel Mode turns on once synced", await A.waitFor("//dialog[@open]//span[normalize-space(.)='Travel Mode activé']", 20000),
    await A.text("(//dialog[@open])[last()]//div[contains(@class,'error')]", 1000).catch(() => ""));
  await A.shot("sync/13-A-travel-mode");
  await closeSheet(A);
  await A.click(nav("Tous les éléments"));
  await sleep(800);
  check("the vault left A in Travel Mode", !(await A.exists(row("Banque Pro"))));
  await settings(A, "Travel Mode");
  await A.click("//dialog[@open]//button[normalize-space(.)='Désactiver le Travel Mode']");
  check("Travel Mode turns off", await A.waitFor("//dialog[@open]//span[normalize-space(.)='Travel Mode désactivé']", 30000),
    await A.text("(//dialog[@open])[last()]//div[contains(@class,'error')]", 1000).catch(() => ""));
  await closeSheet(A);
  await A.click(nav("Tous les éléments"));
  check("the vault came back on A", await A.waitFor(row("Banque Pro"), 30000));
} catch (e) {
  check("run", false, String(e.message ?? e));
  for (const I of [A, B, C]) if (I) await I.shot(`sync/zz-failure-${I.name}`).catch(() => {});
} finally {
  for (const I of [A, B, C]) if (I) await I.quit();
}

if (results.some((r) => !r.ok)) {
  for (const n of ["A", "B", "C"]) {
    try {
      const log = readFileSync(join(root, `${n}-sync.log`), "utf8").trim().split(/\r?\n/);
      console.log(`--- ${n} sync log (last 8)`);
      console.log(log.slice(-8).join("\n"));
    } catch {}
  }
}
writeFileSync(join(shots, "sync", "results.json"), JSON.stringify(results, null, 2));
const failed = results.filter((r) => !r.ok).length;
console.log(`${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
