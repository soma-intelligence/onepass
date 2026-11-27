// Replica cleaning: no script or handler, no outside request, no session or
// personal value, loaded stylesheets inlined.
import { describe, expect, it } from "vitest";
import { cleanPage, IMG_PLACEHOLDER, neutralizeCssUrls, redactText } from "../../../../lab/real/replica/transform.ts";

const URL_ = "https://www.example.com/";
const doc = (html: string): Document => new DOMParser().parseFromString(html, "text/html");

describe("replica transform", () => {
  it("drops scripts, handlers and javascript urls", () => {
    const { html } = cleanPage(
      `<html><head><script>x()</script><noscript>n</noscript></head><body onload="y()"><a href="javascript:z()" onclick="w()">a</a><button onmouseover="q()">b</button><script type="application/ld+json">{}</script></body></html>`,
      { url: URL_, kind: "home" },
    );
    const d = doc(html);
    expect(d.querySelectorAll("script, noscript")).toHaveLength(0);
    expect(html).not.toMatch(/onload|onclick|onmouseover|javascript:/);
    expect(d.querySelector("a")!.hasAttribute("href")).toBe(false);
  });

  it("inlines loaded stylesheets and drops the others", () => {
    const css = new Map([["https://www.example.com/a.css", "body{color:red;background:url(/bg.png)}"]]);
    const { html, inlinedCss } = cleanPage(
      `<html><head><link rel="stylesheet" href="/a.css" media="screen"><link rel="stylesheet" href="https://cdn.other.net/b.css"><link rel="preload" href="/x.js"><link rel="icon" href="/f.ico"></head><body></body></html>`,
      { url: URL_, css, kind: "home" },
    );
    const d = doc(html);
    expect(inlinedCss).toBe(1);
    expect(d.querySelectorAll("link")).toHaveLength(0);
    const style = d.querySelector("style[data-onepass-lab-from]")!;
    expect(style.textContent).toContain("color:red");
    expect(style.textContent).toContain('url("data:,")');
    expect(style.getAttribute("media")).toBe("screen");
  });

  it("makes no outside request: images, iframes, css urls", () => {
    const { html } = cleanPage(
      `<body><img src="https://cdn.x.com/a.png" srcset="a.png 2x"><img src="data:image/png;base64,AAAA"><iframe src="https://ads.x.com" width="300" height="250"></iframe><div style="background:url('https://x.com/i.png')"></div><video src="v.mp4"><source src="v.webm"></video></body>`,
      { url: URL_, kind: "home" },
    );
    const d = doc(html);
    const imgs = d.querySelectorAll("img");
    expect(imgs[0]!.getAttribute("src")).toBe(IMG_PLACEHOLDER);
    expect(imgs[0]!.hasAttribute("srcset")).toBe(false);
    expect(imgs[1]!.getAttribute("src")).toBe("data:image/png;base64,AAAA");
    expect(d.querySelector("iframe")).toBeNull();
    expect(d.querySelector("[data-onepass-lab-iframe]")!.getAttribute("style")).toContain("width:300px");
    expect(html).not.toContain("https://x.com/i.png");
    expect(d.querySelector("video")!.hasAttribute("src")).toBe(false);
    expect(d.querySelector("source")).toBeNull();
  });

  it("strips session and personal values", () => {
    const token = "a8F3kd92LmQp0Zx7Yt5Rw1Vb6Nc4Hj";
    const { html } = cleanPage(
      `<html><head><meta name="csrf-token" content="${token}"><title>Hi jane.doe@mail.com</title></head><body>
       <form action="/login?next=/home&amp;sid=${token}"><input type="hidden" name="authenticity_token" value="${token}"><input type="email" value="jane.doe@mail.com"><input type="submit" value="Sign in"></form>
       <p>Signed in as jane.doe@mail.com, session ${token}</p><a href="/p?u=${token}#top">x</a><div data-state="${token}" data-x="ok" class="css-1a2b3c4d5e6f7g8h9i0jklmnopq"></div><!-- build ${token} --><textarea>draft</textarea></body></html>`,
      { url: URL_, kind: "login" },
    );
    expect(html).not.toContain(token);
    expect(html).not.toContain("jane.doe@mail.com");
    const d = doc(html);
    expect(d.querySelector("form")!.getAttribute("action")).toBe("https://www.example.com/login");
    expect(d.querySelector("input[type=submit]")!.getAttribute("value")).toBe("Sign in");
    expect(d.querySelector("a")!.getAttribute("href")).toBe("https://www.example.com/p#top");
    expect(d.querySelector("div")!.getAttribute("data-x")).toBe("ok");
    expect(d.querySelector("div")!.className).toBe("css-1a2b3c4d5e6f7g8h9i0jklmnopq");
    expect(d.querySelector("textarea")!.textContent).toBe("");
    expect(d.querySelector('meta[name="onepass-lab-replica"]')!.getAttribute("content")).toBe("login");
  });

  it("redacts only addresses and opaque tokens in text", () => {
    expect(redactText("Prices from 2026, call 555 1234")).toBe("Prices from 2026, call 555 1234");
    expect(redactText("mail me: a.b@c.co")).toBe("mail me: [redacted]");
    expect(redactText("token eyJhbGciOiJIUzI1.eyJzdWIiOiIx.abc")).toBe("token [redacted]");
  });

  it("drops css imports", () => {
    expect(neutralizeCssUrls('@import url("x.css") screen; a{b:c}')).toBe(" a{b:c}");
  });
});
