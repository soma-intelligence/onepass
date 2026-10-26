import { describe, expect, it } from "vitest";
import { detectCaptcha, detectPush } from "../../src/content/detect/captcha";

describe("detectCaptcha", () => {
  it.each([
    '<iframe src="https://www.google.com/recaptcha/api2/anchor?k=t"></iframe>',
    '<iframe src="https://www.recaptcha.net/recaptcha/api2/anchor"></iframe>',
    '<iframe src="https://newassets.hcaptcha.com/captcha/v1/x"></iframe>',
    '<iframe src="https://challenges.cloudflare.com/cdn-cgi/challenge-platform/x"></iframe>',
    '<div class="g-recaptcha" data-sitekey="k"></div>',
    '<div class="h-captcha"></div>',
    '<div class="cf-turnstile"></div>',
    "<p>I'm not a robot</p>",
    "<p>Je ne suis pas un robot</p>",
  ])("detects %s", (html) => {
    document.body.innerHTML = html;
    expect(detectCaptcha(document)).toBe(true);
  });

  it.each([
    '<iframe src="https://www.google.com/maps/embed"></iframe>',
    '<iframe src="https://hcaptcha.com.evil.test/x"></iframe>',
    "<p>Robots welcome</p>",
  ])("ignores %s", (html) => {
    document.body.innerHTML = html;
    expect(detectCaptcha(document)).toBe(false);
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
