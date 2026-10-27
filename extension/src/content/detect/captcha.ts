// CAPTCHA and push-approval detection (spec 8.6): either stops the chain.

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

function isCaptchaFrameUrl(src: string, base: string): boolean {
  let url: URL;
  try {
    url = new URL(src, base);
  } catch {
    return false;
  }
  if (url.searchParams.get("size") === "invisible") return false;
  const host = url.hostname.toLowerCase();
  if (CAPTCHA_HOSTS.some((h) => host === h || host.endsWith(`.${h}`))) return true;
  return RECAPTCHA_PATH_HOSTS.has(host) && url.pathname.startsWith("/recaptcha/");
}

/** Most widget containers inspected per page. */
const MAX_WIDGETS = 50;

/**
 * A visible reCAPTCHA, hCaptcha or Turnstile iframe or widget container, or
 * "I'm not a robot" text. Invisible widgets (`size=invisible`,
 * `data-size="invisible"`, hidden or zero-size) do not count.
 */
export function detectCaptcha(doc: Document, geometry: Geometry = domGeometry): boolean {
  const frames = Array.from(doc.querySelectorAll("iframe[src]")).slice(0, MAX_IFRAMES);
  const visibleFrame = frames.some(
    (f) => isCaptchaFrameUrl(f.getAttribute("src") ?? "", doc.baseURI) && isRendered(f, geometry),
  );
  if (visibleFrame) return true;
  const widgets = Array.from(doc.querySelectorAll(CAPTCHA_SELECTOR)).slice(0, MAX_WIDGETS);
  const visibleWidget = widgets.some(
    (w) => (w.getAttribute("data-size") ?? "").toLowerCase() !== "invisible" && isRendered(w, geometry),
  );
  if (visibleWidget) return true;
  return CAPTCHA_TEXT.test(pageText(doc));
}

/** Push approval wording in French or English ("approuvez", "check your phone"...). */
export function detectPush(doc: Document): boolean {
  return PUSH_TEXT.test(pageText(doc));
}
