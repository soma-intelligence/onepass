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
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir, tmpdir } from "node:os";

const DRIVER = "http://127.0.0.1:4444";
const app = process.env.ONEPASS_APP;
const edgedriver = process.env.ONEPASS_EDGEDRIVER;
const shots = process.env.ONEPASS_SHOTS ?? join(tmpdir(), "onepass-e2e-shots");
const data = process.env.ONEPASS_DATA_DIR ?? join(tmpdir(), "onepass-e2e-data");
if (!app || !edgedriver) throw new Error("set ONEPASS_APP and ONEPASS_EDGEDRIVER");
rmSync(data, { recursive: true, force: true });
mkdirSync(data, { recursive: true });
mkdirSync(shots, { recursive: true });

const driver = spawn(join(homedir(), ".cargo", "bin", "tauri-driver"), ["--native-driver", edgedriver], {
  env: { ...process.env, ONEPASS_DATA_DIR: data, ONEPASS_LANG: "fr" },
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
  await find("//h1[normalize-space(.)='Bonjour Camille']");
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
  check("its password is masked", await exists("//main//span[contains(@class,'field-value') and normalize-space(.)='••••••••••']"));
  check("its strength shows", (await textOf("//main//span[@class='meter-label']")).length > 0);
  const otp = await waitText("//main//span[contains(@class,'otp')]", (t) => /\d/.test(t));
  check("a live TOTP code shows", /^\d{3} • \d{3}$/.test(otp), otp);
  await shot("10-element");
  await wd("POST", `${S}/execute/sync`, { script: "document.querySelectorAll('.more').forEach(e => e.style.opacity = 1)", args: [] });
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
  await find("//h1[normalize-space(.)='Bonjour Camille']");
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
  await click("//main//button[@title='Actions']");
  await shot("18-actions");
  await click(menuItem("Archiver"));
  await sleep(800);
  await click(nav("Archive"));
  check("Archiver moves the router to Archive", !!(await find(row("Box maison"), 5000).catch(() => null)));

  // Vault, settings
  await click("//nav//button[.//span[normalize-space(.)='Nouveau coffre']]");
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
  await find("//h1[normalize-space(.)='Bonjour Camille']", 60000);
  check("the right password unlocks", true);

  // Trash
  await click(nav("Tous les éléments"));
  await click(row("GitHub perso"));
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
