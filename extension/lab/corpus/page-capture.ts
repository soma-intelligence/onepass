// In-page helpers shared by the rendered corpus tools (extract.ts, crawl-top.ts).
import type { PageExtra } from "./build.ts";

// Passive init script: records calls to navigator.credentials, never alters them.
export const INIT_SCRIPT = `(() => {
  const calls = (window.__lab_webauthn = []);
  const c = navigator.credentials;
  if (!c) return;
  for (const k of ["get", "create"]) {
    const orig = c[k] && c[k].bind(c);
    if (!orig) continue;
    c[k] = function (opts) { if (opts && opts.publicKey) calls.push(k); return orig(opts); };
  }
})();`;

/** Runs inside the page: document language and the text of sign-in provider buttons. */
export function pageExtra(): PageExtra {
  const textOf = (el: Element) => (el.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, 200);
  const providerTexts: string[] = [];
  document.querySelectorAll("button, a, [role=button]").forEach((b) => {
    const t = textOf(b);
    if (/google|apple|microsoft/i.test(t) && t.length < 80) providerTexts.push(t);
  });
  return { lang: document.documentElement.lang || undefined, providerTexts };
}
