// CAPTCHA and push-approval detection (spec 8.6): either stops the chain.

import { pageText } from "./text";

/** Hosts (and their subdomains) that serve CAPTCHA widgets. */
const CAPTCHA_HOSTS: readonly string[] = ["recaptcha.net", "hcaptcha.com", "challenges.cloudflare.com"];
/** Hosts that serve reCAPTCHA under the /recaptcha path. */
const RECAPTCHA_PATH_HOSTS: ReadonlySet<string> = new Set(["google.com", "www.google.com"]);

const CAPTCHA_SELECTOR = [
  ".g-recaptcha",
  ".h-captcha",
  ".cf-turnstile",
  '[name="g-recaptcha-response"]',
  '[name="h-captcha-response"]',
  '[name="cf-turnstile-response"]',
].join(", ");

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
  const host = url.hostname.toLowerCase();
  if (CAPTCHA_HOSTS.some((h) => host === h || host.endsWith(`.${h}`))) return true;
  return RECAPTCHA_PATH_HOSTS.has(host) && url.pathname.startsWith("/recaptcha/");
}

/** reCAPTCHA, hCaptcha or Turnstile iframes or containers, or "I'm not a robot" text. */
export function detectCaptcha(doc: Document): boolean {
  const frames = Array.from(doc.querySelectorAll("iframe[src]")).slice(0, MAX_IFRAMES);
  if (frames.some((f) => isCaptchaFrameUrl(f.getAttribute("src") ?? "", doc.baseURI))) return true;
  if (doc.querySelector(CAPTCHA_SELECTOR) !== null) return true;
  return CAPTCHA_TEXT.test(pageText(doc));
}

/** Push approval wording in French or English ("approuvez", "check your phone"...). */
export function detectPush(doc: Document): boolean {
  return PUSH_TEXT.test(pageText(doc));
}
