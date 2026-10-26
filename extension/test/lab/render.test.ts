// HTML renderer of the autofill lab: field order per flow, DOM conventions the
// driver and the relying party rely on, trap traits (honeypot, decoy,
// lookalike), structural traits (iframe, shadow, rerender, delay), split OTP,
// passkey page, escaping and the mock identity provider pages.
import { JSDOM } from "jsdom";
import { describe, expect, it } from "vitest";
import patternsJson from "../../lab/corpus/patterns.json";
import type { Patterns } from "../../lab/corpus/types.ts";
import { generate } from "../../lab/gen/generate.ts";
import type { FieldSpec, HoneypotStyle, LoginStyle, Site } from "../../lab/gen/model.ts";
import { PAGE_PATH, renderIdpPage, renderSitePage } from "../../lab/gen/render.ts";

const FIXED = patternsJson as unknown as Patterns;
const world = generate("render", { sites: 10, patterns: FIXED });
const big = generate("render-big", { sites: 120, patterns: FIXED });

const parse = (html: string) => new JSDOM(html).window.document;

/** Where the form markup lives before scripts run: inline, or in the template a script mounts. */
function scope(doc: Document): ParentNode {
  const tpl = doc.querySelector<HTMLTemplateElement>("template#lab-tpl");
  return tpl ? tpl.content : doc;
}

/** Named, user-facing controls of the main form (no honeypot, no decoy, no relay, no hidden OTP carrier). */
function visibleNames(root: ParentNode): string[] {
  const form = root.querySelector("form#lab-form");
  if (!form) return [];
  return [...form.querySelectorAll<HTMLInputElement>("input[name], select[name]")]
    .filter((el) => !el.hasAttribute("data-lab-honeypot") && el.type !== "hidden")
    .map((el) => el.name);
}

function styleOf(site: Site): LoginStyle {
  if (site.flow === "login_username_first") return "username_first";
  if (site.flow === "login_email_then_password") return "email_then_password";
  return site.loginStyle ?? "single";
}

function expectedEntry(site: Site): FieldSpec[] {
  const nonOtp = site.fields.filter((f) => f.role !== "otp");
  if (site.flow === "login_passkey" && site.passkeyOnly) return [];
  if (styleOf(site) === "username_first" && site.fields.some((f) => f.role === "password")) {
    return nonOtp.filter((f) => f.role !== "password");
  }
  return nonOtp;
}

function withTraits(base: Site, over: Partial<Site>): Site {
  return { ...base, ...over, fields: (over.fields ?? base.fields).map((f) => ({ ...f })), buttons: { ...base.buttons } };
}

const loginSingle = world.sites.find((s) => s.flow === "login_single")!;
const plainLogin = withTraits(loginSingle, { traits: [], honeypot: undefined, lookalike: undefined });

describe("renderSitePage", () => {
  it("entry_has_fields_in_order", () => {
    expect(new Set(world.sites.map((s) => s.flow)).size).toBe(10);
    for (const site of [...world.sites, ...big.sites]) {
      const doc = parse(renderSitePage(site, "entry", {}));
      expect(doc.documentElement.lang).toBe(site.lang);
      const framed = site.traits.some((t) => t.startsWith("iframe_"));
      const formDoc = framed ? parse(renderSitePage(site, "frame", {})) : doc;
      const root = scope(formDoc);
      const want = expectedEntry(site);
      expect(visibleNames(root), `${site.index} ${site.flow}`).toEqual(want.map((f) => f.name));
      for (const f of want) {
        const el = root.querySelector(`[id="${f.id}"]`);
        expect(el, `${site.index} ${f.id}`).not.toBeNull();
        expect(root.querySelector(`label[for="${f.id}"]`)).not.toBeNull();
      }
      if (want.length > 0) {
        const form = root.querySelector<HTMLFormElement>("form#lab-form")!;
        expect(form.getAttribute("method")).toBe("post");
        expect(form.getAttribute("action")).toBe(framed ? `https://${site.frameHost ?? site.host}/frame` : "/");
        expect(root.querySelector("#lab-submit")).not.toBeNull();
      }
      expect(doc.querySelector("#lab-status")).not.toBeNull();
      if (site.flow === "sso") expect(doc.querySelector("#lab-sso")).not.toBeNull();
      if (site.flow === "login_passkey" && site.passkeyOnly) expect(doc.querySelector("#lab-passkey")).not.toBeNull();
      // Second step pages carry the rest of the login.
      if (styleOf(site) === "username_first" && !(site.flow === "login_passkey" && site.passkeyOnly)) {
        const pw = site.fields.find((f) => f.role === "password")!;
        const pdoc = parse(renderSitePage(site, "password", {}));
        expect(visibleNames(scope(pdoc))).toEqual([pw.name]);
        expect(scope(pdoc).querySelector("form#lab-form")!.getAttribute("action")).toBe(PAGE_PATH.password);
      }
      if (site.flow === "login_totp") {
        const otp = site.fields.find((f) => f.role === "otp")!;
        const odoc = scope(parse(renderSitePage(site, "otp", {})));
        expect(odoc.querySelector(`input[name="${otp.name}"]`)).not.toBeNull();
      }
    }
  });

  it("signup_new_password_labels_in_order", () => {
    const signups = [...world.sites, ...big.sites].filter((s) => s.flow === "signup");
    expect(signups.length).toBeGreaterThan(3);
    const confirm = /confirm|bestätig|wiederhol|repeat|again/i;
    for (const site of signups) {
      const framed = site.traits.some((t) => t.startsWith("iframe_"));
      const root = scope(parse(renderSitePage(site, framed ? "frame" : "entry", {})));
      const [a, b] = site.fields.filter((f) => f.role === "new_password");
      const la = root.querySelector(`label[for="${a!.id}"]`)!.textContent!;
      const lb = root.querySelector(`label[for="${b!.id}"]`)!.textContent!;
      expect(la, `${site.index}`).not.toMatch(confirm);
      expect(lb, `${site.index}`).toMatch(confirm);
    }
    // Site 6 of the render world drew the confirmation label first: it is swapped.
    const s6 = world.sites[6]!;
    const root = scope(parse(renderSitePage(s6, "entry", {})));
    expect(root.querySelector(`label[for="${s6.fields[1]!.id}"]`)!.textContent).toBe("Crea una contraseña");
    expect(root.querySelector(`label[for="${s6.fields[2]!.id}"]`)!.textContent).toBe("Confirmar contraseña");
  });

  it("honeypot_invisible_style", () => {
    const want: Record<HoneypotStyle, (el: HTMLInputElement) => void> = {
      display_none: (el) => expect(el.style.display).toBe("none"),
      offscreen: (el) => { expect(el.style.position).toBe("absolute"); expect(el.style.left).toBe("-10000px"); },
      opacity: (el) => expect(el.style.opacity).toBe("0"),
      one_pixel: (el) => { expect(el.style.width).toBe("1px"); expect(el.style.height).toBe("1px"); },
      aria_hidden: (el) => {
        expect(el.getAttribute("aria-hidden")).toBe("true");
        expect(el.getAttribute("tabindex")).toBe("-1");
        expect(el.getAttribute("style")).toContain("clip");
      },
    };
    for (const style of Object.keys(want) as HoneypotStyle[]) {
      const site = withTraits(plainLogin, { traits: ["honeypot"], honeypot: { role: "password", name: "pwd_hp", style } });
      const doc = parse(renderSitePage(site, "entry", {}));
      const hp = doc.querySelectorAll<HTMLInputElement>("[data-lab-honeypot]");
      expect(hp.length).toBe(1);
      expect(hp[0]!.name).toBe("pwd_hp");
      expect(hp[0]!.closest("form#lab-form")).not.toBeNull();
      want[style](hp[0]!);
    }
    // Every generated honeypot lands in exactly one page of its site.
    for (const site of big.sites.filter((s) => s.honeypot)) {
      const framed = site.traits.some((t) => t.startsWith("iframe_"));
      const used = [framed ? "frame" : "entry", ...(styleOf(site) === "username_first" ? ["password"] : [])] as const;
      const pages = used.map((p) => scope(parse(renderSitePage(site, p as "entry", {}))));
      const count = pages.filter((r) => r.querySelector("[data-lab-honeypot]")).length;
      expect(count, `${site.index}`).toBe(1);
    }
  });

  it("decoy_form_is_hidden_second_login_form", () => {
    const site = withTraits(plainLogin, { traits: ["decoy_form"] });
    const doc = parse(renderSitePage(site, "entry", {}));
    const decoy = doc.querySelector<HTMLFormElement>("form[data-lab-decoy]")!;
    expect(decoy.getAttribute("action")).toBe("/decoy");
    expect(decoy.querySelector("input[type=password]")).not.toBeNull();
    expect(decoy.getAttribute("style")).toContain("display:none");
    expect(doc.querySelectorAll("form#lab-form").length).toBe(1);
  });

  it("no_autocomplete_trait", () => {
    const sites = big.sites.filter((s) => s.traits.includes("no_autocomplete"));
    expect(sites.length).toBeGreaterThan(0);
    for (const site of sites) {
      for (const page of ["entry", "password", "otp", "frame"] as const) {
        expect(renderSitePage(site, page, {})).not.toMatch(/autocomplete=/);
      }
    }
    const withAuto = world.sites[0]!;
    const root = scope(parse(renderSitePage(withAuto, withAuto.traits.some((t) => t.startsWith("iframe_")) ? "frame" : "entry", {})));
    expect(root.querySelector(`[id="${withAuto.fields[0]!.id}"]`)!.getAttribute("autocomplete")).toBe(withAuto.fields[0]!.autocomplete);
  });

  it("cross_site_iframe_src", () => {
    const cross = withTraits(plainLogin, { traits: ["iframe_cross_site"], frameHost: "other-shop.test", index: 4 });
    const doc = parse(renderSitePage(cross, "entry", {}));
    expect(doc.querySelector("iframe")!.getAttribute("src")).toBe("https://other-shop.test/frame?site=4");
    expect(doc.querySelector("form#lab-form")).toBeNull();
    const frame = parse(renderSitePage(cross, "frame", {}));
    expect(frame.querySelector("form#lab-form")!.getAttribute("action")).toBe("https://other-shop.test/frame");
    const same = withTraits(plainLogin, { traits: ["iframe_same_origin"], index: 2 });
    expect(parse(renderSitePage(same, "entry", {})).querySelector("iframe")!.getAttribute("src"))
      .toBe(`https://${plainLogin.host}/frame?site=2`);
  });

  it("shadow_mode", () => {
    for (const mode of ["open", "closed"] as const) {
      const site = withTraits(plainLogin, { traits: [`shadow_${mode}`] });
      const modes: string[] = [];
      let shadow: ShadowRoot | undefined;
      const dom = new JSDOM(renderSitePage(site, "entry", {}), {
        runScripts: "dangerously",
        beforeParse(window) {
          const orig = window.Element.prototype.attachShadow;
          window.Element.prototype.attachShadow = function (init: ShadowRootInit) {
            modes.push(init.mode);
            shadow = orig.call(this, init);
            return shadow;
          };
        },
      });
      const doc = dom.window.document;
      expect(modes).toEqual([mode]);
      expect(doc.querySelector("lab-shell")).not.toBeNull();
      // Visible fields live in the shadow root, the light DOM only has the hidden relay form.
      const user = shadow!.querySelector<HTMLInputElement>(`input[name="${site.fields[0]!.name}"]`)!;
      const pass = shadow!.querySelector<HTMLInputElement>(`input[name="${site.fields[1]!.name}"]`)!;
      const relay = doc.querySelector<HTMLFormElement>("form#lab-form")!;
      expect([...relay.querySelectorAll("input")].every((i) => i.type === "hidden")).toBe(true);
      user.value = "alice";
      pass.value = "s3cret";
      let posted = false;
      relay.submit = () => { posted = true; };
      shadow!.querySelector("form")!.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
      expect(posted).toBe(true);
      expect((relay.elements.namedItem(site.fields[0]!.name) as HTMLInputElement).value).toBe("alice");
      expect((relay.elements.namedItem(site.fields[1]!.name) as HTMLInputElement).value).toBe("s3cret");
      // Page-level hooks for the driver: field box and fill state, and a submit through the shadow form's handler.
      const w = dom.window as unknown as { __labField(sel: string): { filled: boolean } | null; __labSubmit(): void };
      expect(w.__labField(`[id="${site.fields[0]!.id}"]`)).toMatchObject({ filled: true });
      expect(w.__labField('[id="missing"]')).toBeNull();
      pass.value = "s3cret-2";
      posted = false;
      w.__labSubmit();
      expect(posted).toBe(true);
      expect((relay.elements.namedItem(site.fields[1]!.name) as HTMLInputElement).value).toBe("s3cret-2");
    }
  });

  it("split_otp_six_cells", () => {
    const totp = big.sites.find((s) => s.flow === "login_totp" && s.totpCells
      && !s.traits.some((t) => t.startsWith("shadow_") || t === "delayed_fields"))!;
    expect(totp).toBeDefined();
    const otp = totp.fields.find((f) => f.role === "otp")!;
    const dom = new JSDOM(renderSitePage(totp, "otp", {}), { runScripts: "dangerously", pretendToBeVisual: true });
    const doc = dom.window.document;
    const form = doc.querySelector<HTMLFormElement>("form#lab-form")!;
    const cells = [...form.querySelectorAll<HTMLInputElement>("input[maxlength='1']")];
    expect(cells.length).toBe(6);
    expect(cells.every((c) => !c.name)).toBe(true);
    const carrier = form.querySelector<HTMLInputElement>(`input[type=hidden][name="${otp.name}"]`)!;
    expect(carrier).not.toBeNull();
    "123456".split("").forEach((d, k) => { cells[k]!.value = d; });
    form.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
    expect(carrier.value).toBe("123456");
    const single = withTraits(totp, { traits: [], totpCells: undefined });
    const sdoc = parse(renderSitePage(single, "otp", {}));
    expect(sdoc.querySelector<HTMLInputElement>(`input[name="${otp.name}"]`)!.type).toBe("text");
    expect(sdoc.querySelectorAll("input[maxlength='1']").length).toBe(0);
  });

  it("email_then_password_reveals_without_navigation", () => {
    const site = world.sites.find((s) => s.flow === "login_email_then_password")!;
    const clean = withTraits(site, { traits: [], lookalike: undefined });
    const dom = new JSDOM(renderSitePage(clean, "entry", {}), { runScripts: "dangerously" });
    const doc = dom.window.document;
    const pw = doc.querySelector<HTMLInputElement>(`input[name="${site.fields[1]!.name}"]`)!;
    const step = pw.closest<HTMLElement>("[hidden]");
    expect(step).not.toBeNull();
    expect(doc.querySelector<HTMLElement>("#lab-submit")!.hidden).toBe(true);
    doc.querySelector<HTMLButtonElement>("#lab-next")!.click();
    expect(pw.closest("[hidden]")).toBeNull();
    expect(doc.querySelector<HTMLElement>("#lab-submit")!.hidden).toBe(false);
  });

  it("spa_rerender_replaces_form_once", () => {
    const site = withTraits(plainLogin, { traits: ["spa_rerender"] });
    const dom = new JSDOM(renderSitePage(site, "entry", {}), { runScripts: "dangerously" });
    const doc = dom.window.document;
    const before = doc.querySelector("form#lab-form")!;
    const user = before.querySelector<HTMLInputElement>(`input[name="${site.fields[0]!.name}"]`)!;
    user.value = "bob";
    user.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
    const after = doc.querySelector("form#lab-form")!;
    expect(after).not.toBe(before);
    expect(after.getAttribute("action")).toBe(before.getAttribute("action"));
    expect(after.querySelector<HTMLInputElement>(`input[name="${site.fields[0]!.name}"]`)!.value).toBe("bob");
    after.querySelector("input")!.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
    expect(doc.querySelector("form#lab-form")).toBe(after);
  });

  it("delayed_fields_insert_form_later", async () => {
    const site = withTraits(plainLogin, { traits: ["delayed_fields"], delayMs: 20 });
    const dom = new JSDOM(renderSitePage(site, "entry", {}), { runScripts: "dangerously" });
    const doc = dom.window.document;
    expect(doc.querySelector("form#lab-form")).toBeNull();
    await new Promise((r) => setTimeout(r, 80));
    expect(doc.querySelector("form#lab-form")).not.toBeNull();
  });

  it("sso_button_links_to_idp", () => {
    const site = world.sites.find((s) => s.flow === "sso")!;
    const doc = parse(renderSitePage(site, "entry", {}));
    const hosts = { google: "accounts.google.com", apple: "appleid.apple.com", microsoft: "login.microsoftonline.com" };
    expect(doc.querySelector("#lab-sso")!.getAttribute("href")).toBe(
      `https://${hosts[site.sso!.provider]}/o/oauth2/auth?client=${site.host}&redirect_uri=https://${site.host}/oauth/callback`);
    expect(doc.querySelector("#lab-sso")!.textContent).toBe(site.buttons.sso);
  });

  it("sso_with_form_keeps_provider_button", () => {
    const site = [...world.sites, ...big.sites].find((s) => s.flow === "sso" && s.fields.length > 0)!;
    const doc = parse(renderSitePage(site, "entry", {}));
    expect(doc.querySelector("#lab-sso")).not.toBeNull();
    const form = doc.querySelector("form#lab-form")!;
    expect(form.getAttribute("action")).toBe("/");
    expect([...form.querySelectorAll("input")].map((i) => i.name)).toEqual(site.fields.map((f) => f.name));
  });

  it("passkey_page_calls_webauthn", () => {
    const site = world.sites.find((s) => s.flow === "login_passkey")!;
    const html = renderSitePage(site, "passkey", { challenge: "Y2hhbGxlbmdl" });
    expect(html).toContain('"Y2hhbGxlbmdl"');
    expect(html).toContain(JSON.stringify(site.account!.passkey!.credentialId));
    expect(html).toContain('"discouraged"');
    expect(html).toContain("Clé d'accès refusée".replace("'", "\\u0027"));
    const doc = parse(html);
    expect(doc.querySelector("#lab-passkey")).not.toBeNull();
    expect(doc.querySelector("#lab-status")).not.toBeNull();
  });

  it("lookalike_trap_is_same_form", () => {
    const site = world.sites.find((s) => s.lookalike)!;
    const entry = scope(parse(renderSitePage(site, site.traits.some((t) => t.startsWith("iframe_")) ? "frame" : "entry", {})));
    const trap = parse(renderSitePage(site, "trap", { asHost: site.lookalike!.host }));
    expect(visibleNames(scope(trap))).toEqual(visibleNames(entry));
    expect(scope(trap).querySelector("form#lab-form")!.getAttribute("action")).toBe("/");
    expect(trap.title).toContain(site.brand);
  });

  it("status_and_error", () => {
    const err = parse(renderSitePage(plainLogin, "entry", { error: "Mot de passe incorrect" }));
    expect(err.querySelector("#lab-status")!.textContent).toBe("Mot de passe incorrect");
    const home = parse(renderSitePage(plainLogin, "home", { status: "Connecté" }));
    expect(home.querySelector("#lab-status")!.textContent).toBe("Connecté");
  });

  it("escapes_values", () => {
    const evil = `<script>alert(1)</script>"'&`;
    const site = withTraits(plainLogin, {
      brand: evil, traits: ["delayed_fields"], delayMs: 5,
      fields: plainLogin.fields.map((f) => ({ ...f, label: `<img src=x onerror=alert(1)>${f.label}` })),
    });
    const html = renderSitePage(site, "entry", { error: evil });
    expect(html).not.toContain("<script>alert(1)");
    expect(html).not.toContain("<img src=x");
    const doc = parse(html);
    expect(doc.title).toContain(evil);
    expect(doc.querySelector("#lab-status")!.textContent).toBe(evil);
    expect(doc.querySelectorAll("img").length).toBe(0);
    // Script string literals cannot close the script element.
    const pk = world.sites.find((s) => s.flow === "login_passkey")!;
    const phtml = renderSitePage(pk, "passkey", { challenge: "</script><script>alert(2)</script>" });
    expect(phtml).not.toContain("</script><script>alert(2)");
    expect(parse(phtml).querySelectorAll("script").length).toBe(parse(renderSitePage(pk, "passkey", { challenge: "x" })).querySelectorAll("script").length);
  });
});

describe("renderIdpPage", () => {
  it("idp_chooser_lists_accounts", () => {
    const accounts = world.idp.google;
    const doc = parse(renderIdpPage("google", "chooser", { accounts, client: "shop.test" }));
    expect(doc.querySelector("h1")!.textContent).toBe("Choisir un compte");
    const items = [...doc.querySelectorAll<HTMLButtonElement>("form#lab-form [data-lab-account]")];
    expect(items.map((b) => b.value)).toEqual(accounts.map((a) => a.email));
    for (const [k, a] of accounts.entries()) expect(items[k]!.textContent).toContain(a.name);
    // Entries of a list, one email each (data-email), as real provider choosers.
    for (const [k, a] of accounts.entries()) {
      expect(items[k]!.closest("ul")).not.toBeNull();
      expect(items[k]!.getAttribute("data-email")).toBe(a.email);
    }
    expect(doc.querySelector<HTMLInputElement>("input[name=client]")!.value).toBe("shop.test");
    expect(doc.querySelector("#lab-status")).not.toBeNull();
  });

  it("idp_identifier_and_password_pages", () => {
    const g = parse(renderIdpPage("google", "identifier", { email: "a@b.test", client: "x.test" }));
    expect(g.querySelector("h1")!.textContent).toBe("Connexion");
    expect(g.querySelector<HTMLInputElement>("input[name=email]")!.value).toBe("a@b.test");
    expect(g.querySelector("input[name=password]")).not.toBeNull();
    const ms = parse(renderIdpPage("microsoft", "identifier", {}));
    expect(ms.querySelector("input[name=email]")).not.toBeNull();
    expect(ms.querySelector("input[name=password]")).toBeNull();
    const pw = parse(renderIdpPage("microsoft", "password", { email: "a@b.test", error: "<b>x</b>" }));
    expect(pw.querySelector("h1")!.textContent).toBe("Mot de passe");
    expect(pw.querySelector<HTMLInputElement>("input[name=password]")!.type).toBe("password");
    expect(pw.querySelector("#lab-status")!.textContent).toBe("<b>x</b>");
    expect(pw.querySelector("#lab-submit")).not.toBeNull();
  });
});
