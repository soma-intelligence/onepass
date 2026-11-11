// CAPTCHA and push-approval detection (spec 8.6). A CAPTCHA challenge shown to the user and a
// push approval stop the chain. A widget that only sits on the page (a checkbox not asked yet, a
// managed Turnstile, an invisible reCAPTCHA) does not: they are on most sign-in pages and most
// of them never ask anything. The chain sends the form; if the site then refuses it, that stop
// is named a CAPTCHA (machine.ts). Nothing here, or anywhere, solves or gets around one.

import { pageText } from "./text";
import { domGeometry, type Geometry, isRendered } from "./visibility";

/** Hosts (and their subdomains) that serve CAPTCHA widgets. */
const CAPTCHA_HOSTS: readonly string[] = ["recaptcha.net", "hcaptcha.com", "challenges.cloudflare.com"];
/** Hosts that serve reCAPTCHA under the /recaptcha path. */
const RECAPTCHA_PATH_HOSTS: ReadonlySet<string> = new Set(["google.com", "www.google.com"]);

/**
 * Widget containers. The hidden `*-response` textareas are deliberately not
 * counted: invisible reCAPTCHA (v3) adds them to many login pages without ever
 * blocking the user, and stopping the chain there would hand off every time.
 */
const CAPTCHA_SELECTOR = ".g-recaptcha, .h-captcha, .cf-turnstile";

const CAPTCHA_TEXT =
  /\b(i'?m not a robot|i am not a robot|je ne suis pas un robot|verify (that )?you are (a )?human|verifiez que vous etes (un )?humain)/;

const PUSH_TEXT =
  /\b(approuvez|confirmez sur votre telephone|validez sur votre telephone|check your phone|approve (the |this )?sign[ -]?in|approve (the |this )?login)/;

/** Most iframes inspected per page. */
const MAX_IFRAMES = 200;

/** What a CAPTCHA frame is: the challenge itself (pictures to pick), or the widget that may open one. */
function captchaFrame(src: string, base: string): CaptchaState {
  let url: URL;
  try {
    url = new URL(src, base);
  } catch {
    return null;
  }
  if (url.searchParams.get("size") === "invisible") return null;
  const host = url.hostname.toLowerCase();
  const recaptcha = (host === "recaptcha.net" || host.endsWith(".recaptcha.net") || RECAPTCHA_PATH_HOSTS.has(host)) && url.pathname.startsWith("/recaptcha/");
  // reCAPTCHA keeps its challenge in a `bframe`, hCaptcha in a frame named so in its fragment.
  if (recaptcha) return /\/bframe$/.test(url.pathname) ? "challenge" : "widget";
  if (!CAPTCHA_HOSTS.some((h) => host === h || host.endsWith(`.${h}`))) return null;
  const hcaptcha = host === "hcaptcha.com" || host.endsWith(".hcaptcha.com");
  return hcaptcha && /(^|[#&])frame=challenge(&|$)/.test(url.hash) ? "challenge" : "widget";
}

/** `challenge`: shown to the user now. `widget`: on the page, asking nothing (yet). */
export type CaptchaState = "challenge" | "widget" | null;

/** Most widget containers inspected per page. */
const MAX_WIDGETS = 50;

/**
 * `challenge`: a rendered reCAPTCHA or hCaptcha challenge frame (hidden until the widget asks), or
 * "I'm not a robot" wording in the page itself. `widget`: a rendered reCAPTCHA, hCaptcha or
 * Turnstile frame or container that asks nothing yet. Invisible widgets (`size=invisible`,
 * `data-size="invisible"`, hidden or zero-size) do not count at all.
 */
export function detectCaptcha(doc: Document, geometry: Geometry = domGeometry): CaptchaState {
  const frames = Array.from(doc.querySelectorAll("iframe[src]")).slice(0, MAX_IFRAMES);
  let widget = false;
  for (const f of frames) {
    const kind = captchaFrame(f.getAttribute("src") ?? "", doc.baseURI);
    if (kind === null || !isRendered(f, geometry)) continue;
    if (kind === "challenge") return "challenge";
    widget = true;
  }
  if (CAPTCHA_TEXT.test(pageText(doc))) return "challenge";
  if (widget) return "widget";
  const widgets = Array.from(doc.querySelectorAll(CAPTCHA_SELECTOR)).slice(0, MAX_WIDGETS);
  const visibleWidget = widgets.some(
    (w) => (w.getAttribute("data-size") ?? "").toLowerCase() !== "invisible" && isRendered(w, geometry),
  );
  return visibleWidget ? "widget" : null;
}

/** Push approval wording in French or English ("approuvez", "check your phone"...). */
export function detectPush(doc: Document): boolean {
  return PUSH_TEXT.test(pageText(doc));
}
