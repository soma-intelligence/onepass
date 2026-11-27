// Signed-in variant of a captured home page: every sign-in or sign-up entry
// point and every sign-in form is removed, and a realistic account cluster
// (avatar button with initials, account menu, a sign-out control in the
// site's language) is put into the site's own header.
// CLI: node --experimental-strip-types lab/real/replica/signed-in.ts [--dir lab/out/replicas]
//   rebuilds every <host>/signed-in.html from <host>/home.html.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { defaultReplicaDir, listReplicas, readMeta } from "./common.ts";
import { parse, serialize } from "./transform.ts";

/** Fictional account shown in the header. */
export const FAKE_USER = { name: "Alex Martin", initials: "AM" };

interface Labels { menu: string; profile: string; settings: string; signOut: string; }

/** Account menu wording by language (primary subtag of `<html lang>`). */
export const LABELS: Record<string, Labels> = {
  en: { menu: "Account menu", profile: "Your profile", settings: "Settings", signOut: "Sign out" },
  fr: { menu: "Menu du compte", profile: "Votre profil", settings: "Paramètres", signOut: "Se déconnecter" },
  de: { menu: "Kontomenü", profile: "Dein Profil", settings: "Einstellungen", signOut: "Abmelden" },
  es: { menu: "Menú de la cuenta", profile: "Tu perfil", settings: "Configuración", signOut: "Cerrar sesión" },
  it: { menu: "Menu dell'account", profile: "Il tuo profilo", settings: "Impostazioni", signOut: "Esci" },
  pt: { menu: "Menu da conta", profile: "O seu perfil", settings: "Definições", signOut: "Sair" },
  nl: { menu: "Accountmenu", profile: "Je profiel", settings: "Instellingen", signOut: "Uitloggen" },
  pl: { menu: "Menu konta", profile: "Twój profil", settings: "Ustawienia", signOut: "Wyloguj się" },
  tr: { menu: "Hesap menüsü", profile: "Profilin", settings: "Ayarlar", signOut: "Çıkış yap" },
  ru: { menu: "Меню аккаунта", profile: "Ваш профиль", settings: "Настройки", signOut: "Выйти" },
  uk: { menu: "Меню облікового запису", profile: "Ваш профіль", settings: "Налаштування", signOut: "Вийти" },
  ja: { menu: "アカウントメニュー", profile: "プロフィール", settings: "設定", signOut: "ログアウト" },
  ko: { menu: "계정 메뉴", profile: "내 프로필", settings: "설정", signOut: "로그아웃" },
  zh: { menu: "账户菜单", profile: "个人资料", settings: "设置", signOut: "退出登录" },
};

export function labelsFor(lang: string | undefined): Labels & { lang: string } {
  const primary = (lang ?? "").toLowerCase().split(/[-_]/)[0] ?? "";
  const l = LABELS[primary];
  return l ? { ...l, lang: primary } : { ...LABELS.en!, lang: "en" };
}

const fold = (s: string): string => s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase().replace(/\s+/g, " ").trim();

/** Whole labels of sign-in and sign-up entry points (folded, no accents). */
const ENTRY_TEXT = new RegExp(
  "^(" +
    [
      "sign ?in", "log ?in", "login", "signin", "sign ?up", "register", "create (an |your )?account", "join( now| free)?", "get started",
      "sign in ?/ ?register", "sign in or register", "log ?in ?/ ?sign ?up", "sign in ?/ ?sign up", "my account", "account", "sign in to .{1,30}",
      "se connecter", "connexion", "s'identifier", "identifiez-vous", "inscription", "s'inscrire", "creer un compte", "mon compte",
      "anmelden", "einloggen", "registrieren", "konto erstellen", "mein konto",
      "iniciar sesion", "acceder", "entrar", "registrarse", "crear cuenta", "mi cuenta",
      "accedi", "registrati", "iscriviti", "crea account",
      "iniciar sessao", "registar", "criar conta", "minha conta",
      "inloggen", "aanmelden", "registreren",
      "zaloguj sie", "zaloguj", "zarejestruj sie",
      "giris yap", "kaydol", "uye ol",
      "войти", "вход", "регистрация",
      "ログイン", "新規登録", "로그인", "회원가입", "登录", "注册", "登入",
    ].join("|") +
    ")$",
);
const ENTRY_PATH = /\/(login|log-in|signin|sign-in|signup|sign-up|register|registration|join|connexion|inscription|anmelden|registrieren|accounts?\/(login|signin))(\/|\.|$)/i;
const ENTRY_HOST = /^(login|signin|accounts?|auth|id|sso|passport)\./i;

/** Whether an element is a sign-in or sign-up entry point (by label or by target). */
export function isEntryPoint(el: Element, base: string): boolean {
  for (const raw of [el.getAttribute("aria-label"), el.textContent]) {
    const label = fold(raw ?? "");
    if (label && label.length <= 60 && ENTRY_TEXT.test(label)) return true;
  }
  const href = el.getAttribute("href");
  if (href) {
    try {
      const u = new URL(href, base);
      if (ENTRY_PATH.test(u.pathname) || (ENTRY_HOST.test(u.hostname) && u.hostname !== new URL(base).hostname)) return true;
    } catch { /* not a URL */ }
  }
  return false;
}

const CSS = `
[data-onepass-lab="signed-in"]{all:initial;display:inline-flex;align-items:center;gap:10px;position:relative;font:500 14px/1.2 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;color:inherit;z-index:2147480000;vertical-align:middle}
[data-onepass-lab="signed-in"].op-lab-bar{display:flex;justify-content:flex-end;width:100%;box-sizing:border-box;padding:8px 16px;background:#fff;color:#1d1d1f;border-bottom:1px solid #e5e5ea}
[data-onepass-lab="signed-in"] details{position:relative}
[data-onepass-lab="signed-in"] summary{list-style:none;cursor:pointer;display:inline-flex;align-items:center;gap:8px}
[data-onepass-lab="signed-in"] summary::-webkit-details-marker{display:none}
[data-onepass-lab="signed-in"] .op-lab-avatar{width:32px;height:32px;border-radius:50%;background:#5b5bd6;color:#fff;display:inline-flex;align-items:center;justify-content:center;font-weight:700;font-size:13px}
[data-onepass-lab="signed-in"] [role=menu]{position:absolute;right:0;top:40px;min-width:200px;background:#fff;border:1px solid #e5e5ea;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.14);padding:6px;display:flex;flex-direction:column}
[data-onepass-lab="signed-in"] [role=menuitem]{display:block;padding:8px 10px;border-radius:6px;color:#1d1d1f;text-decoration:none;font-size:14px;text-align:left;background:none;border:0;cursor:pointer}
[data-onepass-lab="signed-in"] [role=menuitem]:hover{background:#f2f2f7}
[data-onepass-lab="signed-in"] .op-lab-who{padding:8px 10px;color:#6e6e73;font-size:13px;border-bottom:1px solid #f2f2f7;margin-bottom:4px}
`;

/** The account cluster: avatar summary toggling a menu (no script needed). */
function accountCluster(doc: Document, labels: Labels): HTMLElement {
  const root = doc.createElement("div");
  root.setAttribute("data-onepass-lab", "signed-in");
  root.innerHTML =
    `<details><summary role="button" aria-haspopup="menu" aria-label="${esc(labels.menu)}" title="${esc(FAKE_USER.name)}">` +
    `<span class="op-lab-avatar" aria-hidden="true">${FAKE_USER.initials}</span><span class="op-lab-name">${esc(FAKE_USER.name.split(" ")[0]!)}</span></summary>` +
    `<div role="menu" aria-label="${esc(labels.menu)}"><div class="op-lab-who">${esc(FAKE_USER.name)}</div>` +
    `<a role="menuitem" href="/account/profile">${esc(labels.profile)}</a>` +
    `<a role="menuitem" href="/account/settings">${esc(labels.settings)}</a>` +
    `<a role="menuitem" href="/logout" data-onepass-lab-signout="">${esc(labels.signOut)}</a></div></details>`;
  return root;
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** The site's header: a banner landmark or the first header element at the top of the page. */
function findHeader(doc: Document): Element | undefined {
  const candidates = [
    ...Array.from(doc.querySelectorAll("header, [role=banner]")),
    ...Array.from(doc.querySelectorAll("body > nav, body > div > nav, nav")),
  ];
  return candidates.find((el) => !el.closest("footer, [role=contentinfo], article, aside, dialog"));
}

export interface SignedInResult { html: string; removed: number; placement: "header" | "bar"; lang: string; }

/** Builds the signed-in variant of a cleaned home page. */
export function makeSignedIn(html: string, opts: { url: string; lang?: string }): SignedInResult {
  const dom = parse(html);
  const doc = dom.window.document;
  const labels = labelsFor(opts.lang ?? doc.documentElement.getAttribute("lang") ?? undefined);
  let removed = 0;

  // Sign-in forms (a password field, or an identifier-first form) do not exist once signed in.
  for (const form of Array.from(doc.querySelectorAll("form"))) {
    if (form.querySelector("input[type=password]") || (form.querySelector("input[type=email], input[autocomplete~=username]") && form.querySelectorAll("input:not([type=hidden])").length <= 3)) {
      form.remove();
      removed++;
    }
  }
  for (const pw of Array.from(doc.querySelectorAll("input[type=password]"))) {
    (pw.closest("div") ?? pw).remove();
    removed++;
  }
  // Entry points: links and buttons whose label or target is sign-in or sign-up. The first
  // one in the header leaves a slot: the account cluster goes where "Sign in" was.
  // The capture marks controls it saw on screen near the top (data-onepass-lab-vis); without
  // marks (older captures) any header entry point outside a hidden subtree is taken.
  const header = findHeader(doc);
  const marked = doc.querySelector("[data-onepass-lab-vis]") !== null;
  const canSlot = (el: Element, target: Element): boolean =>
    marked ? el.hasAttribute("data-onepass-lab-vis") : header?.contains(target) === true && !target.closest("[hidden], [aria-hidden=true], dialog, details");
  let slot: Element | undefined;
  for (const el of Array.from(doc.querySelectorAll("a, button, [role=button], [role=link], [role=menuitem]"))) {
    if (!el.isConnected) continue;
    if (isEntryPoint(el, opts.url)) {
      const target = el.parentElement?.tagName === "LI" && el.parentElement.children.length === 1 ? el.parentElement : el;
      if (!slot && canSlot(el, target)) {
        slot = doc.createElement(target.tagName === "LI" ? "li" : "span");
        slot.setAttribute("data-onepass-lab-slot", "");
        target.replaceWith(slot);
      } else {
        target.remove();
      }
      removed++;
    }
  }

  const style = doc.createElement("style");
  style.setAttribute("data-onepass-lab", "signed-in-style");
  style.textContent = CSS;
  (doc.head ?? doc.documentElement).append(style);
  const meta = doc.createElement("meta");
  meta.setAttribute("name", "onepass-lab-variant");
  meta.setAttribute("content", "signed-in");
  doc.head?.append(meta);

  const cluster = accountCluster(doc, labels);
  let placement: SignedInResult["placement"];
  if (slot?.isConnected) {
    slot.append(cluster);
    placement = "header";
  } else if (header?.isConnected) {
    header.append(cluster);
    placement = "header";
  } else {
    cluster.classList.add("op-lab-bar");
    doc.body.prepend(cluster);
    placement = "bar";
  }
  for (const el of Array.from(doc.querySelectorAll("[data-onepass-lab-vis]"))) el.removeAttribute("data-onepass-lab-vis");
  return { html: serialize(dom.window.document), removed, placement, lang: labels.lang };
}

/** Rebuilds `signed-in.html` of one host from its `home.html`. Returns false when there is no home page. */
export function writeSignedIn(dir: string, host: string): boolean {
  const home = join(dir, host, "home.html");
  if (!existsSync(home)) return false;
  const meta = readMeta(dir, host);
  const out = makeSignedIn(readFileSync(home, "utf8"), { url: meta?.homeUrl ?? `https://${host}/`, lang: meta?.lang });
  writeFileSync(join(dir, host, "signed-in.html"), out.html);
  return true;
}

function main(): void {
  const i = process.argv.indexOf("--dir");
  const dir = i > 0 ? process.argv[i + 1]! : defaultReplicaDir();
  let n = 0;
  for (const m of listReplicas(dir)) if (writeSignedIn(dir, m.host)) n++;
  console.log(`signed-in variants written: ${n}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
