import { describe, expect, it } from "vitest";
import { detectCaptcha, detectPush } from "../../src/content/detect/captcha";
import { testGeometry } from "./helpers";

describe("detectCaptcha", () => {
  // A challenge the user must answer now: the chain stops there.
  it.each([
    '<iframe src="https://www.google.com/recaptcha/api2/bframe?hl=fr&amp;k=t"></iframe>',
    '<iframe src="https://www.recaptcha.net/recaptcha/enterprise/bframe?k=t"></iframe>',
    '<iframe src="https://newassets.hcaptcha.com/captcha/v1/abc/static/hcaptcha.html#frame=challenge&amp;id=x"></iframe>',
    "<p>I'm not a robot</p>",
    "<p>Je ne suis pas un robot</p>",
    "<p>Verify you are human</p>",
  ])("challenge shown: %s", (html) => {
    document.body.innerHTML = html;
    expect(detectCaptcha(document, testGeometry)).toBe("challenge");
  });

  // A widget on the page that asks nothing yet (a checkbox, a managed Turnstile): never a stop by itself.
  it.each([
    '<iframe src="https://www.google.com/recaptcha/api2/anchor?k=t"></iframe>',
    '<iframe src="https://www.recaptcha.net/recaptcha/api2/anchor"></iframe>',
    '<iframe src="https://newassets.hcaptcha.com/captcha/v1/x"></iframe>',
    '<iframe src="https://newassets.hcaptcha.com/captcha/v1/abc/static/hcaptcha.html#frame=checkbox&amp;id=x"></iframe>',
    '<iframe src="https://challenges.cloudflare.com/cdn-cgi/challenge-platform/x"></iframe>',
    '<div class="g-recaptcha" data-sitekey="k"></div>',
    '<div class="h-captcha"></div>',
    '<div class="cf-turnstile"></div>',
    '<div class="g-recaptcha" data-size="normal"></div>',
  ])("passive widget: %s", (html) => {
    document.body.innerHTML = html;
    expect(detectCaptcha(document, testGeometry)).toBe("widget");
  });

  it("a shown challenge wins over the widget beside it", () => {
    document.body.innerHTML =
      '<div class="g-recaptcha"></div><iframe src="https://www.google.com/recaptcha/api2/anchor?k=t"></iframe><iframe src="https://www.google.com/recaptcha/api2/bframe?k=t"></iframe>';
    expect(detectCaptcha(document, testGeometry)).toBe("challenge");
  });

  it.each([
    '<iframe src="https://www.google.com/maps/embed"></iframe>',
    '<iframe src="https://hcaptcha.com.evil.test/x"></iframe>',
    "<p>Robots welcome</p>",
    // Invisible reCAPTCHA (v3 or invisible v2): present on many login pages, never blocks.
    '<iframe src="https://www.google.com/recaptcha/api2/anchor?k=t&amp;size=invisible"></iframe>',
    '<div class="g-recaptcha" data-size="invisible"></div>',
    '<textarea name="g-recaptcha-response" style="display:none"></textarea>',
    // The challenge frame every reCAPTCHA page keeps hidden until it asks something.
    '<iframe style="display:none" src="https://www.google.com/recaptcha/api2/bframe?k=t"></iframe>',
    '<div style="visibility:hidden"><iframe src="https://www.google.com/recaptcha/api2/bframe?k=t"></iframe></div>',
    '<iframe data-test-rect="0,-10000,400,580" src="https://www.google.com/recaptcha/api2/bframe?k=t"></iframe>',
    '<div style="visibility:hidden"><iframe src="https://newassets.hcaptcha.com/captcha/v1/abc/static/hcaptcha.html#frame=challenge"></iframe></div>',
    '<div class="grecaptcha-badge" style="visibility:hidden"><iframe src="https://www.recaptcha.net/recaptcha/api2/anchor"></iframe></div>',
    '<iframe data-test-rect="0,0,0,0" src="https://newassets.hcaptcha.com/captcha/v1/x"></iframe>',
  ])("ignores %s", (html) => {
    document.body.innerHTML = html;
    expect(detectCaptcha(document, testGeometry)).toBeNull();
  });
});

describe("detectPush", () => {
  it.each([
    "Approuvez la demande sur votre appareil.",
    "Confirmez sur votre téléphone",
    "Check your phone",
    "Approve the sign-in request in the app",
    "Please approve the sign in",
  ])("detects %s", (text) => {
    document.body.innerHTML = `<p>${text}</p>`;
    expect(detectPush(document)).toBe(true);
  });

  it("ignores script and hidden text", () => {
    document.body.innerHTML =
      '<script>var s = "check your phone";</script><template><p>Check your phone</p></template><p>Hello</p>';
    expect(detectPush(document)).toBe(false);
  });
});
