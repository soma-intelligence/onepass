// End-to-end test of the Windows app, over WebDriver (tauri-driver and the
// msedgedriver of the installed WebView2). No npm dependency: plain fetch.
//
//   ONEPASS_APP=<path to debug onepass-desktop.exe>
//   ONEPASS_EDGEDRIVER=<msedgedriver.exe of the installed WebView2>
//   ONEPASS_SHOTS=<folder for the screenshots>
//   node e2e/run.mjs
//
// The script starts tauri-driver itself, with ONEPASS_DATA_DIR in its
// environment: the app (a debug build) then runs on a throwaway vault and
// never touches the user's.
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir, tmpdir } from "node:os";

const DRIVER = "http://127.0.0.1:4444";
const app = process.env.ONEPASS_APP;
const edgedriver = process.env.ONEPASS_EDGEDRIVER;
const shots = process.env.ONEPASS_SHOTS ?? join(tmpdir(), "onepass-e2e-shots");
const data = process.env.ONEPASS_DATA_DIR ?? join(tmpdir(), "onepass-e2e-data");
if (!app || !edgedriver) throw new Error("set ONEPASS_APP and ONEPASS_EDGEDRIVER");
// What the app would hand to Windows (a website, an attachment), recorded
// instead of opening a browser or a viewer (debug builds only).
const shellLog = join(data + "-shell.log");
rmSync(shellLog, { force: true });
const opened = () => (existsSync(shellLog) ? readFileSync(shellLog, "utf8").split("\n").map((l) => l.trim()).filter(Boolean) : []);
rmSync(data, { recursive: true, force: true });
mkdirSync(data, { recursive: true });
mkdirSync(shots, { recursive: true });
// The native open and save dialogs answer with the path written here (an
// empty file is "Cancel"); files the test hands to the app live in `files`.
const dialogAnswer = data + "-dialog.txt";
const files = data + "-files";
rmSync(files, { recursive: true, force: true });
mkdirSync(files, { recursive: true });
const answerDialog = (path) => writeFileSync(dialogAnswer, path ?? "");
answerDialog("");

const driver = spawn(join(homedir(), ".cargo", "bin", "tauri-driver"), ["--native-driver", edgedriver], {
  env: { ...process.env, ONEPASS_DATA_DIR: data, ONEPASS_LANG: "fr", ONEPASS_E2E_SHELL_LOG: shellLog, ONEPASS_E2E_DIALOG: dialogAnswer, ONEPASS_E2E_HELLO: "verified" },
  stdio: "ignore",
});
process.on("exit", () => driver.kill());
for (let i = 0; ; i++) {
  try {
    await fetch(DRIVER + "/status");
    break;
  } catch {
    if (i > 40) throw new Error("tauri-driver did not start");
    await new Promise((r) => setTimeout(r, 250));
  }
}

const PASSWORD = "Correct-Cheval-42-Agrafe-Lune";

async function wd(method, path, body) {
  const r = await fetch(DRIVER + path, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await r.json();
  if (!r.ok) throw new Error(`${method} ${path}: ${JSON.stringify(json.value)}`);
  return json.value;
}

const session = await wd("POST", "/session", {
  capabilities: {
    alwaysMatch: { browserName: "wry", "tauri:options": { application: app } },
  },
});
const sid = session.sessionId;
const S = `/session/${sid}`;
const ELEM = "element-6066-11e4-a52f-4f735eb9fb5e";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];

async function find(xpath, timeout = 20000) {
  const end = Date.now() + timeout;
  for (;;) {
    try {
      const e = await wd("POST", `${S}/element`, { using: "xpath", value: xpath });
      // W3C key, or the legacy JSON wire key some drivers still send.
      const id = e[ELEM] ?? e.ELEMENT ?? Object.values(e)[0];
      if (!id) throw new Error("no element id");
      return id;
    } catch (err) {
      if (Date.now() > end) throw new Error(`not found: ${xpath}`);
      await sleep(250);
    }
  }
}
async function exists(xpath) {
  const all = await wd("POST", `${S}/elements`, { using: "xpath", value: xpath });
  return all.length > 0;
}
// The UI redraws lists and panes: a click on a node just replaced retries.
async function click(xpath) {
  for (let i = 0; ; i++) {
    try {
      return await wd("POST", `${S}/element/${await find(xpath)}/click`, {});
    } catch (e) {
      if (i >= 5 || !String(e.message).includes("stale")) throw e;
      await sleep(200);
    }
  }
}
async function waitText(xpath, pred, timeout = 10000) {
  const end = Date.now() + timeout;
  for (;;) {
    const t = await textOf(xpath).catch(() => "");
    if (pred(t) || Date.now() > end) return t;
    await sleep(200);
  }
}
const type = async (xpath, text) => wd("POST", `${S}/element/${await find(xpath)}/value`, { text });
const textOf = async (xpath) => wd("GET", `${S}/element/${await find(xpath)}/text`);
async function shot(name) {
  await sleep(400);
  const png = await wd("GET", `${S}/screenshot`);
  writeFileSync(join(shots, `${name}.png`), Buffer.from(png, "base64"));
}
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? " - " + detail : ""}`);
}
const button = (label) => `//button[normalize-space(.)='${label}']`;
const input = (label) => `//label[normalize-space(.)='${label}']/following-sibling::input[1]`;
// Fields of the editor: the input under a field label.
const editField = (label) => `//dialog//label[.//span[@class='field-label' and normalize-space(.)='${label}']]//input`;
const sheetAction = (label) => `//dialog[@open]//div[@class='sheet-bar']//button[normalize-space(.)='${label}']`;
const nav = (label) => `//nav//button[.//span[@class='nav-label' and normalize-space(.)='${label}']]`;
const row = (title) => `//div[contains(@class,'list')]//button[contains(@class,'item-row')][.//span[@class='row-title' and normalize-space(.)='${title}']]`;
const menuItem = (label) => `//div[@class='menu']//button[.//span[normalize-space(.)='${label}']]`;
const clear = async (xpath) => wd("POST", `${S}/element/${await find(xpath)}/clear`, {});

try {
  await wd("POST", `${S}/window/rect`, { width: 1280, height: 800 });

  // Intro, welcome
  await find("//h1[contains(., 'Tous tes mots de passe')]");
  await shot("01-intro");
  await click(button("Continuer"));
  await click(button("Continuer"));
  await click(button("Commencer"));
  await find("//h1[normalize-space(.)='Bienvenue dans OnePass']");
  await shot("02-bienvenue");
  await click("//button[.//span[normalize-space(.)='Créer un coffre']]");

  // Master password
  await type("//input[@id='name']", "Camille");
  await type("//input[@id='pw']", "court");
  await type("//input[@id='pw2']", "court");
  await click("//form//button[@type='submit']");
  check("a weak password is refused", (await waitText("//div[contains(@class,'error')]", (t) => t.length > 0)).includes("solide"));
  await shot("03-mot-de-passe-faible");
  await clear("//input[@id='pw']");
  await clear("//input[@id='pw2']");
  await type("//input[@id='pw']", PASSWORD);
  await type("//input[@id='pw2']", PASSWORD);
  await sleep(500);
  await shot("04-mot-de-passe");
  await click("//form//button[@type='submit']");

  // Secret Key (Argon2id at 256 MiB and the identity keys: slow in a debug build)
  await find("//div[@class='secret-key']", 120000);
  const key = await textOf("//div[@class='secret-key']");
  check("the Secret Key is shown once", /^[A-Z0-9]+(-[A-Z0-9]+){5,}$/.test(key.replace(/\s/g, "")), key.slice(0, 7) + "…");
  await shot("05-emergency-kit");
  await click("//input[@id='ok']");
  await click(button("Continuer"));

  // Accueil, empty
  await find("//*[contains(@class,'hero-greeting') and normalize-space(.)='Bonjour Camille']");
  check("Accueil greets by first name", true);
  check("the Personnel vault exists", await exists(nav("Personnel")));
  await shot("06-accueil-vide");

  // New login: type picker, editor, generator
  await click("//button[normalize-space(.)='Créer ton premier élément']");
  await find("//h1[normalize-space(.)='Que veux-tu ajouter ?']");
  await shot("07-type");
  await click("//button[contains(@class,'picker-cell')][.//span[normalize-space(.)='Connexion']]");
  await type("//input[@id='f-title']", "GitHub");
  await type("//input[@id='f-url']", "https://github.com");
  await type(editField("Identifiant"), "alice@example.com");
  await click("//dialog//button[@title='Générer un mot de passe']");
  const gen = await waitText("//dialog[@open]//div[@class='generated']", (t) => t.length === 20);
  check("the generator makes a 20-character password", gen.length === 20, `${gen.length}`);
  await shot("08-generateur");
  await click(sheetAction("Utiliser"));
  await type(editField("TOTP"), "JBSWY3DPEHPK3PXP");
  await shot("09-edition");
  await click(sheetAction("Enregistrer"));

  // Item
  await find("//main//h2[normalize-space(.)='GitHub']");
  check("the new login is saved", true);
  check("a site icon from the icon pack shows", !!(await find("//main//header//span[contains(@class,'site-icon')]", 5000).catch(() => null)));
  await click("//main//button[contains(@class,'timeline-head')]");
  check("the item timeline shows its creation", !!(await find("//main//div[contains(@class,'timeline-row')][contains(., 'Élément créé')]", 5000).catch(() => null)));
  check("its password is masked", await exists("//main//span[contains(@class,'field-value') and normalize-space(.)='••••••••••']"));
  check("its strength shows", (await textOf("//main//span[@class='meter-label']")).length > 0);
  const otp = await waitText("//main//span[contains(@class,'otp')]", (t) => /\d/.test(t));
  check("a live TOTP code shows", /^\d{3} • \d{3}$/.test(otp), otp);
  await shot("10-element");
  await wd("POST", `${S}/execute/sync`, { script: "document.querySelectorAll('.more').forEach(e => e.style.opacity = 1)", args: [] });
  await click("//main//span[@title='Ouvrir dans le navigateur']");
  await sleep(300);
  check("a website opens in the browser (http/https only)", opened().includes("https://github.com/"), opened().join(", "));
  await click("(//main//span[contains(@class,'more')])[2]");
  await shot("11-menu-champ");
  await click(menuItem("Révéler"));
  const shown = await waitText("(//main//span[contains(@class,'field-value') and contains(@class,'mono')])[1]", (t) => !t.includes("•"));
  check("Révéler shows the generated password", shown.length === 20, `${shown.length} characters`);
  await shot("12-mot-de-passe-revele");
  await click("(//main//button[contains(@class,'field-row')])[2]");
  check("a copy announces the 90 s clear", (await waitText("//div[@id='toast']", (t) => t.includes("90"))).includes("90 s"));
  await click("//main//button[@title='Ajouter aux favoris']");
  await find("//main//button[@title='Retirer des favoris']");
  check("favorite", true);

  // Second item: a Wi-Fi router
  await click("//button[@title='Nouvel élément']");
  await click("//button[contains(@class,'picker-cell')][.//span[normalize-space(.)='Routeur Wi-Fi']]");
  await type("//input[@id='f-title']", "Box maison");
  await type(editField("SSID"), "Maison-5G");
  await type(editField("Mot de passe Wi-Fi"), "un-mot-de-passe-wifi");
  await click(sheetAction("Enregistrer"));
  await find("//main//h2[normalize-space(.)='Box maison']");
  check("a Wi-Fi router is saved", true);
  await click("//main//button[contains(@class,'qr-area')]");
  await find("//main//*[local-name()='svg' and @class='qr']");
  check("a Wi-Fi router shows its join QR code", (await textOf("//main//div[contains(@class,'qr-card')]/p")).includes("Maison-5G"));
  await shot("38-wifi-qr");

  // Every field kind: menu, date, address, custom fields, tags (an identity)
  const js = (script, ...args) => wd("POST", `${S}/execute/sync`, { script, args });
  const setValue = (css, value) => js(`const e = document.querySelector(arguments[0]); e.value = arguments[1]; e.dispatchEvent(new Event('change', { bubbles: true })); e.dispatchEvent(new Event('input', { bubbles: true }));`, css, value);
  await click("//button[@title='Nouvel élément']");
  await click("//button[contains(@class,'picker-cell')][.//span[normalize-space(.)='Identité']]");
  await type("//input[@id='f-title']", "Moi");
  await type(editField("Prénom"), "Camille");
  await setValue("#f-sex", (await js("return [...document.querySelectorAll('#f-sex option')].map(o => o.value).find(Boolean)")));
  await click("//button[@id='f-birth_date']");
  await setValue("input#f-birth_date", "1990-05-17");
  await type("//input[@id='f-address']", "12 rue des Lilas");
  await type("//input[@aria-label='Code postal']", "75011");
  await type("//input[@aria-label='Ville']", "Paris");
  await click("//dialog[@open]//button[contains(@class,'add-row') and contains(., 'ajouter plus')]");
  await click(menuItem("Texte"));
  await type("//dialog[@open]//input[contains(@class,'custom-label')]", "Numéro client");
  await type("//dialog[@open]//div[contains(@class,'custom-wrap')]//input[not(contains(@class,'custom-label'))]", "A-1234");
  await type("//input[@id='f-tags']", "famille");
  await type("//textarea[@id='f-notes']", "Première ligneDeuxième ligne");
  await shot("24-edition-identite");
  await click(sheetAction("Enregistrer"));
  await find("//main//h2[normalize-space(.)='Moi']");
  const fieldText = async (label) => textOf(`//main//button[contains(@class,'field-row')][.//span[@class='field-label' and normalize-space(.)='${label}']]//span[contains(@class,'field-value')]`).catch(() => "");
  check("a date saves", (await fieldText("Date de naissance")) === "1990-05-17", await fieldText("Date de naissance"));
  check("an address saves", (await fieldText("Adresse")).includes("75011, Paris"), await fieldText("Adresse"));
  check("a custom field saves in Champs perso", (await fieldText("Numéro client")) === "A-1234" && (await exists("//main//div[@class='caps' and normalize-space(.)='Champs perso']")));
  check("a tag saves", await exists("//main//span[@class='chip' and normalize-space(.)='famille']"));
  check("multiline notes save", (await textOf("//main//div[contains(@class,'notes')]")).includes("\n"));
  await shot("25-identite");

  // Attachments: add (file dialog), open (temporary file), export, delete
  const attached = join(files, "carte-vitale.txt");
  writeFileSync(attached, "pièce jointe de test");
  answerDialog(attached);
  await click("//main//button[contains(., 'Ajouter un fichier')]");
  await find("//main//button[contains(@class,'attachment-row')][.//span[normalize-space(.)='carte-vitale.txt']]");
  check("a file is attached", true);
  await shot("26-piece-jointe");
  await click("//main//button[contains(@class,'attachment-row')]");
  await sleep(500);
  const tempCopy = opened().find((p) => p.endsWith("carte-vitale.txt"));
  check("an attachment opens from a temporary copy", !!tempCopy && readFileSync(tempCopy, "utf8") === "pièce jointe de test", tempCopy ?? opened().join(", "));
  const exported = join(files, "export.txt");
  answerDialog(exported);
  await js("document.querySelectorAll('.more').forEach(e => e.style.opacity = 1)");
  await click("//main//button[contains(@class,'attachment-row')]//span[contains(@class,'more')]");
  await click(menuItem("Exporter…"));
  await sleep(500);
  check("an attachment exports", existsSync(exported) && readFileSync(exported, "utf8") === "pièce jointe de test");
  await click("//main//button[contains(@class,'attachment-row')]//span[contains(@class,'more')]");
  await click(menuItem("Supprimer…"));
  await click(sheetAction("Supprimer le fichier"));
  await sleep(800);
  check("an attachment is removed", !(await exists("//main//button[contains(@class,'attachment-row')]")));
  answerDialog("");

  // Remove the custom field, month-year and money on a card
  await click("//main//button[normalize-space(.)='Modifier']");
  await click("//dialog[@open]//div[contains(@class,'custom-wrap')]//button[contains(@class,'destructive')]");
  await click(sheetAction("Enregistrer"));
  await sleep(800);
  check("a custom field is removed", !(await exists("//main//span[@class='field-label' and normalize-space(.)='Numéro client']")));
  await click("//button[@title='Nouvel élément']");
  await click("//button[contains(@class,'picker-cell')][.//span[normalize-space(.)='Carte bancaire']]");
  await type("//input[@id='f-title']", "Visa");
  await type(editField("Titulaire"), "Camille Martin");
  await type(editField("Numéro"), "4242424242424242");
  await click("//button[@id='f-expiry']");
  await setValue("select#f-expiry", "3");
  await setValue("select[aria-label='Année']", "2030");
  await type(editField("Plafond"), "1500,50 EUR");
  await shot("27-edition-carte");
  await click(sheetAction("Enregistrer"));
  await find("//main//h2[normalize-space(.)='Visa']");
  check("a month and year save", (await fieldText("Expiration")) === "03/2030", await fieldText("Expiration"));
  check("an amount saves", (await fieldText("Plafond")) === "1500.50 EUR", await fieldText("Plafond"));
  await click("//main//button[normalize-space(.)='Modifier']");
  await clear("//input[@id='f-title']");
  await type("//input[@id='f-title']", "Visa perso");
  await click("//dialog[@open]//div[@class='sheet-bar']/button[1]");
  await find("//dialog[@open]//p[contains(., 'Abandonner les modifications')]");
  check("Annuler with changes asks first", true);
  await click(sheetAction("Abandonner"));
  await sleep(400);
  check("the discarded edit is not saved", await exists("//main//h2[normalize-space(.)='Visa']"));

  // Lists, search, favorites, categories
  check("the list shows both items", (await exists(row("GitHub"))) && (await exists(row("Box maison"))));
  await type("//input[@type='search']", "git");
  await sleep(300);
  check("search narrows the list", !(await exists(row("Box maison"))));
  await shot("13-recherche");
  await click(nav("Favoris"));
  check("Favoris lists GitHub only", (await exists(row("GitHub"))) && !(await exists(row("Box maison"))));
  await click(nav("Routeurs Wi-Fi"));
  check("a category lists its items", (await exists(row("Box maison"))) && !(await exists(row("GitHub"))));
  await click(nav("Accueil"));
  await find("//*[contains(@class,'hero-greeting') and normalize-space(.)='Bonjour Camille']");
  await sleep(800);
  await shot("14-accueil");

  // Watchtower
  await click(nav("Watchtower"));
  await find("//*[local-name()='svg' and @class='dial']");
  await sleep(800);
  check("Watchtower shows a score", /\d/.test(await textOf("//*[local-name()='text' and @class='dial-figure']")));
  check("Watchtower shows its check cards", (await wd("POST", `${S}/elements`, { using: "xpath", value: "//div[contains(@class,'wt-card')]" })).length === 15);
  await shot("15-watchtower");

  // Generator modes
  await click("//button[@title='Compte']");
  await shot("16-menu-compte");
  await click(menuItem("Générateur"));
  await click("//div[@class='segmented']//button[normalize-space(.)='Mots']");
  check("Mots makes a passphrase", (await waitText("//dialog[@open]//div[@class='generated']", (t) => t.includes("-"))).includes("-"));
  await click("//div[@class='segmented']//button[normalize-space(.)='PIN']");
  check("PIN makes digits", /^\d{6}$/.test(await waitText("//dialog[@open]//div[@class='generated']", (t) => /^\d+$/.test(t))));
  await shot("17-generateur-pin");
  await click(sheetAction("Fermer") + " | //dialog[@open]//div[@class='sheet-bar']/button[1]");

  // Edit, archive
  await click(nav("Tous les éléments"));
  await click(row("GitHub"));
  await click("//main//button[normalize-space(.)='Modifier']");
  await clear("//input[@id='f-title']");
  await type("//input[@id='f-title']", "GitHub perso");
  await click(sheetAction("Enregistrer"));
  await find("//main//h2[normalize-space(.)='GitHub perso']");
  check("editing the title saves", true);
  await click(row("Box maison"));
  await find("//main//h2[normalize-space(.)='Box maison']");
  await click("//main//button[@title='Actions']");
  await shot("18-actions");
  await click(menuItem("Archiver"));
  await sleep(800);
  await click(nav("Archive"));
  check("Archiver moves the router to Archive", !!(await find(row("Box maison"), 5000).catch(() => null)));

  // Vault, settings
  await click("//nav//button[@title='Nouveau coffre']");
  await type("//input[@id='v-name']", "Travail");
  await click("//dialog[@open]//button[@title='orange']");
  await click(sheetAction("Enregistrer"));
  await find(nav("Travail"));
  check("a new vault appears in the sidebar", true);
  await click("//button[@title='Compte']");
  await click(menuItem("Réglages"));
  await find("//h2[normalize-space(.)='Général']");
  await shot("19-reglages");
  await click("//div[@class='settings-side']//button[.//span[normalize-space(.)='Sécurité']]");
  await find("//h2[normalize-space(.)='Sécurité']");
  await shot("20-securite");
  await click("//dialog[@open]//div[@class='sheet-bar']/button[1]");

  // Lock, wrong password, unlock
  await click("//button[@title='Compte']");
  await click(menuItem("Verrouiller"));
  await find("//h1[normalize-space(.)='Déverrouille OnePass']");
  check("Verrouiller locks", true);
  await shot("21-verrouille");
  await type("//input[@id='pw']", "mauvais-mot-de-passe");
  await click("//button[@title='Déverrouiller']");
  await find("//div[contains(@class,'error') and contains(., 'incorrect')]", 60000);
  check("a wrong password is refused", true);
  await shot("22-mauvais-mot-de-passe");
  await clear("//input[@id='pw']");
  await type("//input[@id='pw']", PASSWORD);
  await click("//button[@title='Déverrouiller']");
  await find("//*[contains(@class,'hero-greeting') and normalize-space(.)='Bonjour Camille']", 60000);
  check("the right password unlocks", true);

  // Windows Hello (answered "verified" by the debug build's stand-in)
  await click("//button[@title='Compte']");
  await click(menuItem("Réglages"));
  await click("//div[@class='settings-side']//button[.//span[normalize-space(.)='Sécurité']]");
  await click("//label[@for='hello-toggle']");
  await type("//input[@id='hello-pw']", PASSWORD);
  await shot("28-activer-windows-hello");
  await click(sheetAction("Activer"));
  check("Windows Hello turns on after the master password", (await waitText("//div[@id='toast']", (t) => t.includes("Windows Hello"), 60000)).includes("activé"));
  await find("//input[@id='hello-toggle' and @checked]").catch(() => null);
  await shot("29-securite-windows-hello");
  await click("//dialog[@open]//div[@class='sheet-bar']/button[1]");
  await click("//button[@title='Compte']");
  await click(menuItem("Verrouiller"));
  await find("//button[@aria-label='Déverrouiller avec Windows Hello']");
  check("the lock screen offers Windows Hello", true);
  await shot("30-verrouille-windows-hello");
  await click("//button[@aria-label='Déverrouiller avec Windows Hello']");
  await find("//*[contains(@class,'hero-greeting') and normalize-space(.)='Bonjour Camille']", 30000);
  check("Windows Hello unlocks without the password", true);

  // Encrypted backup, restore, import from another manager, plaintext CSV
  const settingsPage = async (name) => {
    await click("//button[@title='Compte']");
    await click(menuItem("Réglages"));
    await click(`//div[@class='settings-side']//button[.//span[normalize-space(.)='${name}']]`);
  };
  const closeSheet = () => click("(//dialog[@open])[last()]//div[@class='sheet-bar']/button[1]");
  const backupFile = join(files, "sauvegarde.onepass");
  await settingsPage("Général");
  await click("//button[@id='open-backup']");
  await type("//input[@id='bk-pw']", PASSWORD);
  await type("//input[@id='bk-pass']", "tapis-orage-girafe-violon-nuage-42");
  await type("//input[@id='bk-pass2']", "tapis-orage-girafe-violon-nuage-42");
  await shot("31-sauvegarde-chiffree");
  answerDialog(backupFile);
  await click(sheetAction("Exporter"));
  check("an encrypted backup is saved", (await waitText("//div[@id='toast']", (t) => t.includes("Sauvegarde"), 120000)).includes("enregistrée") && existsSync(backupFile));
  await closeSheet();
  // Delete an item for good, then bring it back from the backup.
  await click(nav("Tous les éléments"));
  await click(row("Visa"));
  await find("//main//h2[normalize-space(.)='Visa']");
  await click("//main//button[@title='Actions']");
  await click(menuItem("Supprimer"));
  await click(sheetAction("Supprimer"));
  await sleep(600);
  await click(nav("Supprimés récemment"));
  await click(row("Visa"));
  await find("//main//h2[normalize-space(.)='Visa']");
  await click("//main//button[@title='Actions']");
  await click(menuItem("Supprimer définitivement"));
  await click(sheetAction("Supprimer"));
  await sleep(600);
  await settingsPage("Général");
  await click("//button[@id='open-restore']");
  answerDialog(backupFile);
  await click("//button[@id='pick-backup']");
  await find("//dialog[@open]//span[contains(., 'ton compte')]", 60000);
  await sleep(500);
  await shot("32-restaurer-apercu");
  await click(sheetAction("Restaurer"));
  check("a backup restores the deleted item", (await textOf("//dialog[@open]//div[@class='done-head']//h2")).includes("1 élément restauré"));
  await shot("33-restaure");
  await closeSheet();
  await closeSheet().catch(() => {});
  await click(nav("Tous les éléments"));
  check("the restored item is back", await exists(row("Visa")));

  // Import a Chrome export
  const chromeCsv = join(files, "Chrome Passwords.csv");
  writeFileSync(chromeCsv, "name,url,username,password,note\nExemple,https://exemple.fr/login,bob@example.com,password123,\n");
  await settingsPage("Général");
  await click("//button[@id='open-import']");
  await shot("34-importer");
  answerDialog(chromeCsv);
  await click("//button[@id='pick-import']");
  await find("//dialog[@open]//span[contains(., 'Chrome et navigateurs Chromium')]", 30000);
  check("an import detects the Chrome format", true);
  await shot("35-importer-apercu");
  await click(sheetAction("Importer"));
  check("an import adds the items to the vault", (await waitText("//dialog[@open]//p[contains(@class,'center-text')]", (t) => t.length > 0, 30000)).includes("1 élément importé dans « Personnel »"));
  await closeSheet();
  await closeSheet().catch(() => {});
  await click(nav("Tous les éléments"));
  check("the imported login is listed", await exists(row("Exemple")));

  // Watchtower with "Vérifier les fuites" (on by default): HIBP ranges
  await click(nav("Watchtower"));
  const compromised = "//div[contains(@class,'wt-card')][.//div[normalize-space(.)='Mots de passe compromis']]//span[contains(@class,'wt-figure')]";
  const pwned = await waitText(compromised, (t) => /^[1-9]/.test(t), 60000);
  check("Watchtower finds a breached password through Have I Been Pwned", /^[1-9]/.test(pwned), pwned);
  check("the breach setting shows on Watchtower", await exists("//input[@id='check-breaches']"));
  await shot("37-watchtower-fuites");
  await click("//label[@for='check-breaches']");
  const off = await waitText("//div[contains(@class,'wt-card')][.//div[normalize-space(.)='Mots de passe compromis']]//p", (t) => t.includes("désactivée"), 30000);
  check("turning breach checks off stops them", off.includes("désactivée"), off);
  await click("//label[@for='check-breaches']");

  // Plaintext CSV export
  const csvFile = join(files, "export.csv");
  await settingsPage("Général");
  await click("//button[@id='open-csv']");
  await click("//label[@for='csv-ok']");
  await type("//input[@id='csv-pw']", PASSWORD);
  await shot("36-export-csv");
  answerDialog(csvFile);
  await click(sheetAction("Exporter"));
  await waitText("//div[@id='toast']", (t) => t.includes("Fichier enregistré") || t.includes("Supprime"), 120000);
  const csv = existsSync(csvFile) ? readFileSync(csvFile, "utf8") : "";
  check("a plaintext CSV export holds the items", csv.startsWith("title,type,vault") && csv.includes("Exemple"), csv.split("\n")[0]);
  answerDialog("");
  await closeSheet().catch(() => {});

  // Possible duplicates: a copy of the imported login, merged back
  await click(nav("Tous les éléments"));
  await click(row("Exemple"));
  await find("//main//h2[normalize-space(.)='Exemple']");
  await click("//main//button[@title='Actions']");
  await click(menuItem("Dupliquer"));
  await click(nav("Doublons possibles"));
  await find("//h1[normalize-space(.)='Doublons possibles']");
  check("possible duplicates are listed", await exists("//div[contains(@class,'dup-group') or contains(@class,'dup-review')]"));
  await shot("39-doublons");
  const mergeButton = (await exists("//button[contains(., 'Fusionner la sélection')]")) ? "//button[contains(., 'Fusionner la sélection')]" : "//div[contains(@class,'dup-review')]//button[normalize-space(.)='Fusionner']";
  await click(mergeButton);
  await sleep(1200);
  check("merging clears the duplicates", !(await exists("//div[contains(@class,'dup-group') or contains(@class,'dup-review')]")));

  // Travel Mode: the plan, a vault safe for travel, and the refusal without sync
  await settingsPage("Travel Mode");
  await find("//dialog[@open]//span[normalize-space(.)='Travel Mode désactivé']");
  await click("//dialog[@open]//label[.//span[normalize-space(.)='Travail']]");
  await find("//dialog[@open]//label[.//span[normalize-space(.)='Travail']]//span[normalize-space(.)=\"Reste sur l'appareil\"]");
  check("a vault becomes safe for travel", true);
  await click("//dialog[@open]//button[normalize-space(.)='Activer le Travel Mode']");
  await click(sheetAction("Activer"));
  const travel = await waitText("(//dialog[@open])[last()]//div[contains(@class,'error')]", (t) => t.length > 0);
  check("Travel Mode refuses to remove vaults that were never synced", travel.includes("Synchronise d'abord"), travel.slice(0, 60));
  await shot("40-travel-mode");
  await closeSheet();

  // Keyboard shortcuts of the Mac app (Ctrl for Cmd)
  const press = (key, shift = false) => js("document.dispatchEvent(new KeyboardEvent('keydown', { key: arguments[0], ctrlKey: true, shiftKey: arguments[1], bubbles: true }))", key, shift);
  await press("I", true);
  check("Ctrl+Shift+I opens Importer", !!(await find("//dialog[@open]//div[@class='sheet-title' and normalize-space(.)='Importer']", 5000).catch(() => null)));
  await closeSheet();
  await press(",");
  check("Ctrl+, opens Réglages", !!(await find("//dialog[@open]//div[@class='sheet-title' and normalize-space(.)='Réglages']", 5000).catch(() => null)));
  await closeSheet();

  // Trash
  await click(nav("Tous les éléments"));
  await click(row("GitHub perso"));
  await find("//main//h2[normalize-space(.)='GitHub perso']");
  await click("//main//button[@title='Actions']");
  await click(menuItem("Supprimer"));
  await click(sheetAction("Supprimer"));
  await sleep(800);
  await click(nav("Supprimés récemment"));
  check("Supprimés récemment holds the login", !!(await find(row("GitHub perso"), 5000).catch(() => null)));
  await shot("23-supprimes");
} catch (e) {
  check("run", false, String(e.message ?? e));
  await shot("zz-failure").catch(() => {});
} finally {
  await wd("DELETE", S).catch(() => {});
}

writeFileSync(join(shots, "results.json"), JSON.stringify(results, null, 2));
const failed = results.filter((r) => !r.ok).length;
console.log(`${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
