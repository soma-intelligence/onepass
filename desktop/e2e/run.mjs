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
  env: { ...process.env, ONEPASS_DATA_DIR: data },
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

const PASSWORD = "Correct-Cheval-42";

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

try {
  await wd("POST", `${S}/window/rect`, { width: 1180, height: 760 });

  // Welcome
  await find("//h1[contains(., 'Bienvenue')]");
  await shot("01-bienvenue");
  await type("//input[@id='pw']", "court");
  await type("//input[@id='pw2']", "court");
  await click(button("Créer mon coffre"));
  check("a short password is refused", (await textOf("//div[@class='error']")).includes("10 caractères"));
  await shot("02-mot-de-passe-trop-court");
  await wd("POST", `${S}/element/${await find("//input[@id='pw']")}/clear`, {});
  await wd("POST", `${S}/element/${await find("//input[@id='pw2']")}/clear`, {});
  await type("//input[@id='pw']", PASSWORD);
  await type("//input[@id='pw2']", PASSWORD);
  await click(button("Créer mon coffre"));

  // Secret Key (Argon2id at 256 MiB and the identity keys: slow in a debug build)
  await find("//div[@class='secret-key']", 120000);
  const key = await textOf("//div[@class='secret-key']");
  check("the Secret Key is shown once", /^[A-Z0-9]+(-[A-Z0-9]+){5,}$/.test(key.replace(/\s/g, "")), key.slice(0, 7) + "…");
  await shot("03-secret-key");
  await click("//input[@id='ok']");
  await click(button("Continuer"));

  // Empty vault
  await find("//nav[contains(@class,'sidebar')]//span[normalize-space(.)='Personnel']");
  check("the Personnel vault exists", true);
  await shot("04-coffre-vide");

  // New login
  await click(button("+ Nouvel élément"));
  await type("//input[@id='n-title']", "GitHub");
  await shot("05-nouvel-element");
  await click(button("Créer"));
  await find("//dialog//h2[normalize-space(.)='Nouvel élément']");
  await type("//input[@id='f-url']", "https://github.com");
  await type(input("Identifiant"), "alice@example.com");
  await click(`//label[normalize-space(.)='Mot de passe']/following-sibling::button`);
  await type(input("TOTP"), "JBSWY3DPEHPK3PXP");
  await shot("06-edition");
  await click(button("Enregistrer"));

  // Detail
  await find("//main//h2[normalize-space(.)='GitHub']");
  check("the new login is saved", true);
  check("its password is masked", await exists("//main//div[contains(@class,'value') and normalize-space(.)='••••••••••']"));
  const otp = await textOf("//main//div[contains(@class,'otp')]");
  check("a live TOTP code shows", /^\d{3} \d{3} {2}· {2}\d+s$/.test(otp), otp);
  await shot("07-detail");
  await click("(//main//button[normalize-space(.)='Afficher'])[1]");
  const shown = await waitText("(//main//div[contains(@class,'value') and contains(@class,'mono')])[1]", (t) => !t.includes("•"));
  check("Afficher reveals the generated password", shown.length === 20, `${shown.length} characters`);
  await shot("08-mot-de-passe-affiche");
  await click("(//main//button[normalize-space(.)='Copier'])[3]");
  check("Copier confirms and announces the 90 s clear", (await textOf("//div[@id='toast']")).includes("90 s"));
  await shot("09-copie");
  await click("//main//button[@title='Ajouter aux favoris']");
  await find("//main//button[@title='Retirer des favoris']");
  check("favorite", true);

  // Second item: a Wi-Fi router
  await click(button("+ Nouvel élément"));
  await wd("POST", `${S}/execute/sync`, {
    script: "const s=document.getElementById('n-type'); s.value='router'; s.dispatchEvent(new Event('change'));",
    args: [],
  });
  await type("//input[@id='n-title']", "Box maison");
  await click(button("Créer"));
  await type(input("SSID"), "Maison-5G");
  await type(input("Mot de passe Wi-Fi"), "un-mot-de-passe-wifi");
  await click(button("Enregistrer"));
  await find("//main//h2[normalize-space(.)='Box maison']");
  check("a Wi-Fi router is saved", true);
  await shot("10-routeur");

  // List, search, favorites
  check("the list shows both items", (await exists("//button[contains(@class,'row')]//div[contains(.,'GitHub')]")) && (await exists("//button[contains(@class,'row')]//div[contains(.,'Box maison')]")));
  await type("//input[@type='search']", "git");
  await sleep(300);
  check("search narrows the list", !(await exists("//button[contains(@class,'row')]//div[contains(.,'Box maison')]")));
  await shot("11-recherche");
  await wd("POST", `${S}/element/${await find("//input[@type='search']")}/clear`, {});
  await wd("POST", `${S}/execute/sync`, { script: "document.querySelector('input[type=search]').dispatchEvent(new Event('input'))", args: [] });
  await click("//nav//button[.//span[normalize-space(.)='Favoris']]");
  check("favorites list GitHub only", !(await exists("//button[contains(@class,'row')]//div[contains(.,'Box maison')]")));
  await shot("12-favoris");
  await click("//nav//button[.//span[normalize-space(.)='Tous les éléments']]");

  // Generator
  await click(button("Générateur"));
  const gen = await textOf("//dialog//div[@class='generated']");
  check("the generator makes a 20-character password", gen.length === 20);
  await shot("13-generateur");
  await click("//input[@id='g-words']");
  await sleep(300);
  check("passphrase mode uses words", (await textOf("//dialog//div[@class='generated']")).includes("-"));
  await shot("14-generateur-mots");
  await click(button("Fermer"));

  // Edit
  await click("//button[contains(@class,'row')]//div[contains(.,'GitHub')]");
  await click(button("Modifier"));
  const title = await find("//input[@id='f-title']");
  await wd("POST", `${S}/element/${title}/clear`, {});
  await wd("POST", `${S}/element/${title}/value`, { text: "GitHub perso" });
  await click(button("Enregistrer"));
  await find("//main//h2[normalize-space(.)='GitHub perso']");
  check("editing the title saves", true);
  await shot("15-modifie");

  // Lock, wrong password, unlock
  await click(button("Verrouiller"));
  await find("//h1[contains(., 'verrouillé')]");
  check("Verrouiller locks", true);
  await shot("16-verrouille");
  await type("//input[@id='pw']", "mauvais-mot-de-passe");
  await click(button("Déverrouiller"));
  await find("//div[@class='error' and contains(., 'incorrect')]", 60000);
  check("a wrong password is refused", true);
  await shot("17-mauvais-mot-de-passe");
  await wd("POST", `${S}/element/${await find("//input[@id='pw']")}/clear`, {});
  await type("//input[@id='pw']", PASSWORD);
  await click(button("Déverrouiller"));
  await find("//button[contains(@class,'row')]//div[contains(.,'GitHub perso')]", 60000);
  check("the right password unlocks, items are still there", true);
  await shot("18-deverrouille");

  // Trash
  await click("//button[contains(@class,'row')]//div[contains(.,'Box maison')]");
  await wd("POST", `${S}/execute/sync`, { script: "window.confirm = () => true", args: [] });
  await click(button("Corbeille"));
  await click("//nav//button[.//span[normalize-space(.)='Corbeille']]");
  check("trash holds the router", await exists("//button[contains(@class,'row')]//div[contains(.,'Box maison')]"));
  await shot("19-corbeille");
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
