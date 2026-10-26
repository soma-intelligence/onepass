// Dev-only visual harness: renders the built extension pages (dist/chromium)
// outside the extension with a stubbed `chrome.runtime` that answers with
// fictional fixture replies, then photographs every state in light and dark
// at the real popup and frame sizes.
//
//   npm run build:chromium && node scripts/ui-shots.mjs <out-dir> [--only name,name]
//
// Output: <out-dir>/site/ (the harness pages, also usable with any browser
// or page inspector) and <out-dir>/<state>-<light|dark>.png. Nothing here is
// bundled into the extension.
import { chromium } from "@playwright/test";
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const onlyIdx = args.indexOf("--only");
const only = onlyIdx === -1 ? null : new Set(args.splice(onlyIdx, 2)[1].split(","));
const out = resolve(args[0] ?? join(root, "test-results", "ui-shots"));
const dist = join(root, "dist", "chromium");
if (!existsSync(join(dist, "popup.js"))) {
  console.error("dist/chromium is missing: run `npm run build:chromium` first");
  process.exit(2);
}

const TOKEN = "AbCdEfGhIjKlMnOpQrStUv";
const SIZE = { popup: [780, 600], menu: [360, 320], overlay: [360, 440], save: [360, 520] };

// ---- fixture replies (fictional data only) ----
const login = (id, extra = {}) => ({
  item_id: id,
  vault_id: "v1",
  vault_name: "Personnel",
  title: "Atlas Cloud",
  subtitle: "alex@atlas.dev",
  kind: "login",
  icon_letter: "A",
  icon_color: "#14532D",
  has_password: true,
  has_totp: false,
  methods: [],
  match: "domain",
  ...extra,
});
const ITEMS = [
  login("it_01", { has_totp: true, match: "exact_host" }),
  login("it_02", { title: "Atlas Cloud (ops)", subtitle: "ops@atlas.dev", icon_letter: "AO", icon_color: "#1E3A8A" }),
  login("it_03", {
    title: "Atlas Cloud (Google)",
    subtitle: "alex.perso@example.com",
    icon_color: "#7C2D12",
    has_password: false,
    methods: [{ provider: "google", account_email: "alex.perso@example.com" }],
  }),
];
const CARD = login("cd_01", { kind: "card", title: "Visa Alex Martin", subtitle: "•••• 4242", icon_letter: "V", icon_color: "#334155", has_password: false });
const VAULTS = [
  { id: "v1", name: "Personnel" },
  { id: "v2", name: "Atlas (travail)" },
];
const STEPS_RUNNING = [
  { label: "Identifiant", detail: "alex@atlas.dev", state: "done" },
  { label: "Mot de passe", state: "active" },
  { label: "Code à usage unique", state: "pending" },
];

// Each state: page, its stub replies (by message type) and Playwright steps.
const STATES = {
  "popup-main": { page: "popup", replies: {} },
  "popup-detail": {
    page: "popup",
    replies: {},
    steps: async (p) => {
      await p.locator("button.row").first().click();
      await p.getByRole("button", { name: "Afficher" }).click();
      await p.getByText("pw-Atlas-2026").waitFor();
    },
  },
  "popup-search-empty": {
    page: "popup",
    replies: { popup_search: { ok: { items: [] } } },
    steps: async (p) => {
      await p.getByPlaceholder("Rechercher dans OnePass").fill("zzz");
      await p.getByText("Aucun résultat").waitFor();
    },
  },
  "popup-generator": {
    page: "popup",
    replies: {},
    steps: async (p) => {
      await p.getByRole("button", { name: "Générateur de mot de passe" }).click();
      await p.getByRole("button", { name: "Historique du générateur" }).click();
      await p.getByText("old-Pass-1").waitFor();
    },
  },
  "popup-toast": {
    page: "popup",
    replies: {},
    steps: async (p) => {
      await p.locator("button.row").first().click();
      await p.getByRole("button", { name: "Remplir" }).click();
      await p.getByText("Rempli sur atlas-cloud.test").waitFor();
    },
  },
  "popup-no-https": { page: "popup", replies: { popup_suggestions: { ok: { domain: null, items: [] } } } },
  "popup-unpaired": { page: "popup", replies: { popup_status: { err: "unpaired" } } },
  "popup-sas": {
    page: "popup",
    replies: { popup_status: { err: "unpaired" } },
    steps: async (p) => {
      await p.getByRole("button", { name: "Appairer avec OnePass" }).click();
      await p.locator(".sas").waitFor();
    },
  },
  "popup-locked": { page: "popup", replies: { popup_status: { ok: { locked: true, account: "alex@atlas.dev", vaults: 2 } } } },
  "popup-host-missing": { page: "popup", replies: { popup_status: { err: "host_missing" } } },
  "menu-login": { page: "menu", replies: {} },
  "menu-signup": {
    page: "menu",
    replies: { menu_init: { ok: { origin: "https://atlas-cloud.test", formKind: "signup", items: [] } } },
  },
  "menu-provider": {
    page: "menu",
    replies: {
      menu_init: {
        ok: {
          origin: "https://accounts.google.com",
          formKind: "login",
          items: [
            login("g1", { title: "Google perso", subtitle: "alex.perso@example.com", icon_letter: "G", icon_color: "#1E3A8A" }),
            login("g2", { title: "Google pro", subtitle: "alex.pro@example.com", icon_letter: "G", icon_color: "#7C2D12" }),
          ],
          linked: { itemId: "g1", site: "atlas-cloud.test" },
        },
      },
    },
  },
  "menu-card": { page: "menu", replies: { menu_init: { ok: { origin: "https://atlas-cloud.test", formKind: "card", items: [CARD] } } } },
  "menu-locked": { page: "menu", replies: { menu_init: { err: "locked" } } },
  "overlay-idle": { page: "overlay", replies: {} },
  "overlay-running": {
    page: "overlay",
    replies: {
      overlay_init: { ok: { origin: "https://atlas-cloud.test", accounts: [], chain: { itemId: "it_01", status: "running", steps: STEPS_RUNNING } } },
      overlay_state: { ok: { chain: { itemId: "it_01", status: "running", steps: STEPS_RUNNING } } },
    },
  },
  "overlay-stopped": {
    page: "overlay",
    replies: {
      overlay_init: {
        ok: {
          origin: "https://atlas-cloud.test",
          accounts: [],
          chain: {
            itemId: "it_01",
            status: "handoff",
            reason: "captcha",
            steps: [
              { label: "Identifiant", detail: "alex@atlas.dev", state: "done" },
              { label: "Mot de passe", state: "stopped" },
              { label: "Code à usage unique", state: "pending" },
            ],
          },
        },
      },
    },
  },
  "overlay-done": {
    page: "overlay",
    replies: {
      overlay_init: {
        ok: {
          origin: "https://atlas-cloud.test",
          accounts: [],
          chain: { itemId: "it_01", status: "done", steps: STEPS_RUNNING.map((s) => ({ ...s, state: "done" })) },
        },
      },
    },
  },
  "save-new": { page: "save", replies: {} },
  "save-more": {
    page: "save",
    replies: {},
    steps: async (p) => {
      await p.waitForTimeout(350);
      await p.getByRole("button", { name: "Options" }).click();
    },
  },
  "save-update": {
    page: "save",
    replies: {
      save_init: {
        ok: {
          origin: "https://atlas-cloud.test",
          site: "atlas-cloud.test",
          kind: "login",
          status: "update",
          title: "Atlas Cloud",
          username: "alex@atlas.dev",
          update: { itemId: "it_01", title: "Atlas Cloud" },
          vaults: VAULTS,
        },
      },
    },
  },
  "save-edit": {
    page: "save",
    replies: {},
    steps: async (p) => {
      await p.waitForTimeout(350);
      await p.getByRole("button", { name: "Modifier" }).click();
      await p.waitForTimeout(350);
      await p.getByRole("button", { name: "Afficher" }).click();
      await p.getByText("pw-Atlas-2026").waitFor();
    },
  },
  "save-link": {
    page: "save",
    replies: {
      save_init: {
        ok: {
          origin: "https://atlas-cloud.test",
          site: "atlas-cloud.test",
          kind: "provider_link",
          status: "new",
          title: "Atlas Cloud",
          username: "",
          vaults: VAULTS,
          provider: { id: "google", email: "alex.perso@example.com" },
        },
      },
    },
  },
  "save-saved": {
    page: "save",
    replies: {},
    steps: async (p) => {
      await p.waitForTimeout(350);
      await p.getByRole("button", { name: "Enregistrer", exact: true }).click();
      await p.getByText(/enregistré$/).waitFor();
    },
  },
};

const DEFAULTS = {
  popup_status: { ok: { locked: false, account: "alex@atlas.dev", vaults: 2 } },
  popup_suggestions: { ok: { domain: "atlas-cloud.test", items: ITEMS } },
  popup_item: { ok: { summary: ITEMS[0], website: "https://atlas-cloud.test" } },
  popup_reveal: { ok: { value: "pw-Atlas-2026" } },
  popup_totp: { ok: { code: "703083", remaining: 18 } },
  popup_fill: { ok: { domain: "atlas-cloud.test" } },
  popup_fill_generated: { ok: { domain: "atlas-cloud.test" } },
  popup_search: { ok: { items: [ITEMS[1]] } },
  popup_generate: { ok: { password: "kTr7-vapo2-Xeline.9q", entropy_bits: 92 } },
  popup_history: {
    ok: {
      entries: [
        { password: "old-Pass-1", kind: "random", at: 1 },
        { password: "mauve-tissu-orbite-42", kind: "memorable", at: 2 },
      ],
    },
  },
  popup_pair_start: { ok: { sas: "482 913" } },
  menu_init: { ok: { origin: "https://atlas-cloud.test", formKind: "login", items: ITEMS } },
  overlay_init: {
    ok: {
      origin: "https://atlas-cloud.test",
      accounts: [
        { itemId: "it_01", title: "Atlas Cloud", subtitle: "alex@atlas.dev", iconLetter: "A", iconColor: "#14532D" },
        {
          itemId: "it_03",
          title: "Se connecter avec Google",
          subtitle: "alex.perso@example.com",
          iconLetter: "G",
          iconColor: "#1E3A8A",
          provider: "google",
          email: "alex.perso@example.com",
        },
      ],
      chain: null,
    },
  },
  overlay_state: { ok: { chain: null } },
  save_init: {
    ok: {
      origin: "https://atlas-cloud.test",
      site: "atlas-cloud.test",
      kind: "login",
      status: "new",
      title: "Atlas Cloud",
      username: "alex.new@atlas.dev",
      vaults: VAULTS,
    },
  },
  save_reveal: { ok: { password: "pw-Atlas-2026" } },
  save_generate: { ok: { password: "kTr7-vapo2-Xeline.9q" } },
};

// ---- harness site ----
const site = join(out, "site");
rmSync(out, { recursive: true, force: true });
mkdirSync(site, { recursive: true });
for (const f of ["theme.css", "popup.js", "menu.js", "overlay.js", "save.js"]) cpSync(join(dist, f), join(site, f));

const stub = (replies) => `"use strict";
// Harness stub: a fake extension runtime with fixture replies.
(() => {
  const replies = ${JSON.stringify({ ...DEFAULTS, ...replies })};
  globalThis.chrome = { runtime: { id: "harness", sendMessage: async (m) => structuredClone(replies[m.type] ?? { ok: {} }) } };
  history.replaceState(null, "", "#${TOKEN}");
})();
`;

for (const [name, s] of Object.entries(STATES)) {
  writeFileSync(join(site, `${name}.stub.js`), stub(s.replies));
  writeFileSync(
    join(site, `${name}.html`),
    `<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>OnePass</title>
    <link rel="stylesheet" href="theme.css" />
  </head>
  <body class="${s.page === "popup" ? "popup" : "frame"}">
    <div id="root"></div>
    <script src="${name}.stub.js"></script>
    <script src="${s.page}.js"></script>
  </body>
</html>
`,
  );
}

// ---- photographs ----
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css" };
const server = createServer((req, res) => {
  const f = join(site, decodeURIComponent(new URL(req.url, "http://x").pathname));
  if (!f.startsWith(site) || !existsSync(f) || statSync(f).isDirectory()) {
    res.writeHead(404);
    res.end();
    return;
  }
  res.writeHead(200, { "content-type": MIME[extname(f)] ?? "application/octet-stream" });
  createReadStream(f).pipe(res);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch();
try {
  for (const [name, s] of Object.entries(STATES)) {
    if (only && !only.has(name)) continue;
    for (const scheme of ["light", "dark"]) {
      const [width, height] = SIZE[s.page];
      const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 2, colorScheme: scheme });
      await page.goto(`${base}/${name}.html`);
      await page.waitForTimeout(150);
      if (s.steps) await s.steps(page);
      await page.mouse.move(0, 0);
      await page.waitForTimeout(120);
      await page.screenshot({ path: join(out, `${name}-${scheme}.png`) });
      await page.close();
    }
    console.log(`shot ${name}`);
  }
} finally {
  await browser.close();
  server.close();
}
console.log(`screenshots in ${out}`);
