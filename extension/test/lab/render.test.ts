// HTML renderer of the autofill lab: field order per flow, DOM conventions the
// driver and the relying party rely on, trap traits (honeypot, decoy,
// lookalike), structural traits (iframe, shadow, rerender, delay), split OTP,
// passkey page, escaping and the mock identity provider pages.
import { JSDOM } from "jsdom";
import { describe, expect, it } from "vitest";
import patternsJson from "../../lab/corpus/patterns.json";
import type { Patterns } from "../../lab/corpus/types.ts";
import { generate } from "../../lab/gen/generate.ts";
import { FORMS_FLOWS } from "../../lab/gen/forms-flows.ts";
import { blockWord, DEMONYMS, formsLabels, isFormsLang, monthNames, passengerLegends } from "../../lab/gen/forms-lexicon.ts";
import type { FieldSpec, HoneypotStyle, LoginStyle, Site } from "../../lab/gen/model.ts";
import { PAGE_PATH, renderIdpPage, renderSitePage } from "../../lab/gen/render.ts";
import type { PageContext, PageId } from "../../lab/gen/render.ts";

const FIXED = patternsJson as unknown as Patterns;
const world = generate("render", { sites: 10, patterns: FIXED });
const big = generate("render-big", { sites: 120, patterns: FIXED });

const parse = (html: string) => new JSDOM(html).window.document;

/** Where the form markup lives before scripts run: inline, or in the template a script mounts. */
function scope(doc: Document): ParentNode {
  const tpl = doc.querySelector<HTMLTemplateElement>("template#lab-tpl");
  return tpl ? tpl.content : doc;
}

/**
 * Named, user-facing controls of the main form (no honeypot, no decoy, no relay, no hidden OTP carrier, no
 * "same as billing" checkbox), a radio group once.
 */
function visibleNames(root: ParentNode): string[] {
  const form = root.querySelector("form#lab-form");
  if (!form) return [];
  const names = [...form.querySelectorAll<HTMLInputElement>("input[name], select[name]")]
    .filter((el) => !el.hasAttribute("data-lab-honeypot") && el.type !== "hidden" && el.name !== "same_as_billing")
    .map((el) => (el.type === "radio" ? `radio:${el.name}` : el.name));
  return names.filter((n, k) => !n.startsWith("radio:") || names.indexOf(n) === k).map((n) => n.replace(/^radio:/, ""));
}

function styleOf(site: Site): LoginStyle {
  if (site.flow === "login_username_first") return "username_first";
  if (site.flow === "login_email_then_password") return "email_then_password";
  return site.loginStyle ?? "single";
}

/** The text naming a field in its layout: its <label for>, the text before it (inline), or its placeholder. */
function shownLabel(root: ParentNode, f: FieldSpec): string | undefined {
  const label = root.querySelector(`label[for="${f.id}"]`)?.textContent;
  if (label) return label;
  const el = root.querySelector(`[id="${f.id}"]`);
  const before = el?.previousElementSibling;
  if (before?.classList.contains("lab-text")) return before.textContent ?? undefined;
  // A radio group: the legend of its fieldset.
  if (el?.tagName === "FIELDSET") return el.querySelector("legend")?.textContent ?? undefined;
  return el?.getAttribute("placeholder") ?? el?.getAttribute("aria-label") ?? undefined;
}

/** Pages a site's fields are spread over (the entry-like page first). */
function sitePages(site: Site, entry: "entry" | "frame"): [PageId, PageContext][] {
  if (site.steps) return site.steps.map((_, k): [PageId, PageContext] => (k === 0 ? [entry, {}] : ["step", { step: k }]));
  return [[entry, {}], ...(styleOf(site) === "username_first" ? [["password", {}] as [PageId, PageContext]] : [])];
}

function expectedEntry(site: Site): FieldSpec[] {
  if (site.steps) return site.steps[0]!;
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
        expect(shownLabel(root, f), `${site.index} ${site.layout} ${f.id}`).toBeTruthy();
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
      // A multi_step site shows one step per page, posting to its own path, "next" until the last.
      for (const [k, step] of (site.steps ?? []).entries()) {
        if (k === 0) continue;
        const sdoc = scope(parse(renderSitePage(site, "step", { step: k })));
        expect(visibleNames(sdoc)).toEqual(step.map((f) => f.name));
        expect(sdoc.querySelector("form#lab-form")!.getAttribute("action")).toBe(`/step/${k}`);
        const last = k === site.steps!.length - 1;
        expect(sdoc.querySelector("#lab-submit")!.textContent).toBe(last ? site.buttons.submit : site.buttons.next);
      }
    }
    expect(big.sites.some((s) => s.steps)).toBe(true);
  });

  it("signup_new_password_labels_in_order", () => {
    const signups = [...world.sites, ...big.sites].filter((s) => s.flow === "signup");
    expect(signups.length).toBeGreaterThan(3);
    const confirm = /confirm|bestätig|wiederhol|repeat|retype|again|conferm|ripet|herhaal|bevestig/i;
    for (const drawn of signups) {
      // Labels are read from <label for>: the stacked layout (other layouts: generate.test.ts).
      const site = { ...drawn, layout: "stacked" as const };
      const framed = site.traits.some((t) => t.startsWith("iframe_"));
      const root = scope(parse(renderSitePage(site, framed ? "frame" : "entry", {})));
      const [a, b] = site.fields.filter((f) => f.role === "new_password");
      const la = root.querySelector(`label[for="${a!.id}"]`)!.textContent!;
      const lb = root.querySelector(`label[for="${b!.id}"]`)!.textContent!;
      expect(la, `${site.index}`).not.toMatch(confirm);
      expect(lb, `${site.index}`).toMatch(confirm);
    }
    // A site that drew the confirmation label first: the labels are swapped.
    const drawn = signups.find((x) => !x.traits.some((t) => t.startsWith("iframe_") || t.startsWith("shadow_")) && !x.delayMs)!;
    const [p1, p2] = drawn.fields.filter((f) => f.role === "new_password");
    const swapped = withTraits(drawn, { layout: "stacked", fields: drawn.fields.map((f) =>
      f === p1 ? { ...f, label: "Confirmar contraseña" } : f === p2 ? { ...f, label: "Crea una contraseña" } : f) });
    const root = scope(parse(renderSitePage(swapped, "entry", {})));
    expect(root.querySelector(`label[for="${p1!.id}"]`)!.textContent).toBe("Crea una contraseña");
    expect(root.querySelector(`label[for="${p2!.id}"]`)!.textContent).toBe("Confirmar contraseña");
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
      const pages = sitePages(site, framed ? "frame" : "entry").map(([p, ctx]) => scope(parse(renderSitePage(site, p, ctx))));
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

  it("framework_controlled_inputs", async () => {
    const [u, p] = plainLogin.fields as [FieldSpec, FieldSpec];
    const run = (framework: Site["framework"]) => {
      const dom = new JSDOM(renderSitePage({ ...plainLogin, framework }, "entry", {}), { runScripts: "dangerously" });
      const doc = dom.window.document;
      const input = (f: FieldSpec) => doc.querySelector<HTMLInputElement>(`[id="${f.id}"]`)!;
      return { dom, doc, input, fire: (f: FieldSpec) => input(f).dispatchEvent(new dom.window.Event("input", { bubbles: true })) };
    };
    for (const fw of ["react", "vue"] as const) {
      const { input, fire } = run(fw);
      // A value written with its input event survives the rerender; one written silently is set back to its state.
      input(u).value = "bob";
      fire(u);
      input(p).value = "silent";
      input(u).value = "bobby";
      fire(u);
      await Promise.resolve();
      expect(input(u).value, fw).toBe("bobby");
      expect(input(p).value, fw).toBe("");
    }
    const ng = run("angular");
    ng.input(p).value = "kept";
    ng.input(u).value = "bob";
    ng.fire(u);
    await Promise.resolve();
    expect(ng.input(p).value).toBe("kept");
    expect(ng.input(u).classList.contains("ng-dirty")).toBe(true);
    // Static pages carry no framework runtime.
    expect(run("static").doc.querySelectorAll("script").length).toBe(0);
  });

  it("framework rerender keeps the values of radio buttons and checkboxes", async () => {
    // A controlled radio group keeps its option values: a rerender after another field's input never blanks them.
    const radio = big.sites.find((s) => s.fields.some((f) => f.render?.choice?.kind === "radio") && !s.traits.some((t) => t.startsWith("iframe_") || t.startsWith("shadow_") || t === "delayed_fields" || t === "spa_rerender"));
    expect(radio).toBeDefined();
    for (const fw of ["react", "vue"] as const) {
      const site = { ...radio!, framework: fw };
      const dom = new JSDOM(renderSitePage(site, "entry", {}), { runScripts: "dangerously" });
      const doc = dom.window.document;
      const text = site.fields.find((f) => f.type !== "radio" && f.type !== "select")!;
      const group = site.fields.find((f) => f.render?.choice?.kind === "radio")!;
      const before = [...doc.querySelectorAll<HTMLInputElement>(`input[name="${group.name}"]`)].map((r) => r.value);
      const t = doc.querySelector<HTMLInputElement>(`[id="${text.id}"]`)!;
      t.value = "x";
      t.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
      await Promise.resolve();
      const first = doc.querySelector<HTMLInputElement>(`[id="${group.id}-1"]`)!;
      first.checked = true;
      first.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
      await Promise.resolve();
      expect([...doc.querySelectorAll<HTMLInputElement>(`input[name="${group.name}"]`)].map((r) => r.value), fw).toEqual(before);
      expect(before.every((v) => v !== ""), fw).toBe(true);
    }
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

describe("forms pages (generator version 4)", () => {
  const formsWorld = generate("render-forms", { sites: 400, patterns: FIXED });
  const forms = formsWorld.sites.filter((s) => FORMS_FLOWS.includes(s.flow));
  const framed = (s: Site) => s.traits.some((t) => t.startsWith("iframe_"));
  const rootOf = (s: Site) => scope(parse(renderSitePage(s, framed(s) ? "frame" : "entry", {})));
  const L = (s: Site) => (isFormsLang(s.labelLang) ? s.labelLang : "en");

  it("renders every field of a forms site in order with its label", () => {
    expect(forms.length).toBeGreaterThan(60);
    for (const s of forms) {
      const root = rootOf(s);
      expect(visibleNames(root), `${s.index} ${s.flow}`).toEqual(s.fields.map((f) => f.name));
      for (const f of s.fields) expect(shownLabel(root, f), `${s.index} ${f.id}`).toBeTruthy();
    }
  });

  it("passengers 2 and 3 sit in fieldsets whose legend gives their rank", () => {
    const multi = forms.filter((s) => s.fields.some((f) => (f.person ?? 0) > 0));
    expect(multi.length).toBeGreaterThan(2);
    for (const s of multi) {
      const root = rootOf(s);
      for (const f of s.fields.filter((x) => (x.person ?? 0) > 0)) {
        const legend = root.querySelector(`[id="${f.id}"]`)!.closest("fieldset.lab-block")!.querySelector(":scope > legend")!.textContent!;
        expect(passengerLegends(L(s)).map((w) => w(f.person! + 1)), `${s.index} ${f.id}`).toContain(legend);
      }
    }
  });

  it("the shipping block is hidden behind a checked same-as-billing box, shown otherwise", () => {
    const shipping = forms.filter((s) => s.fields.some((f) => f.block === "shipping"));
    expect(shipping.some((s) => s.forms?.shippingSame)).toBe(true);
    expect(shipping.some((s) => !s.forms?.shippingSame)).toBe(true);
    for (const s of shipping) {
      const root = rootOf(s);
      const box = root.querySelector<HTMLInputElement>("#lab-same")!;
      expect(box.checked).toBe(s.forms?.shippingSame === true);
      expect(box.parentElement!.textContent).toContain(blockWord(L(s), "sameAsBilling"));
      const block = root.querySelector("#lab-ship")!;
      expect(block.hasAttribute("hidden")).toBe(s.forms?.shippingSame === true);
      for (const f of s.fields.filter((x) => x.block === "shipping")) expect(block.querySelector(`[id="${f.id}"]`)).not.toBeNull();
    }
  });

  it("dates render as date inputs, placeholder text, bare text or three parts, month names in the label language", () => {
    const kinds = new Set<string>();
    for (const s of forms) {
      const root = rootOf(s);
      for (const f of s.fields) {
        const d = f.render?.date;
        if (!d) continue;
        const el = root.querySelector<HTMLInputElement>(`[id="${f.id}"]`)!;
        if (d.kind === "input") {
          kinds.add("input");
          expect(el.type).toBe("date");
        } else if (d.kind === "text") {
          kinds.add(d.placeholder ? "text_hint" : "text_bare");
          expect(el.type).toBe("text");
          const shown = `${el.getAttribute("placeholder") ?? ""} ${shownLabel(root, f) ?? ""}`;
          if (d.placeholder) expect(shown, `${s.index} ${f.id}`).toMatch(/[A-Za-z]{2}[./-][A-Za-z]{2}[./-][A-Za-z]{4}/);
          // A floating label's blank placeholder, or the placeholder that is the label, is not a format.
          else expect(["", f.label]).toContain((el.getAttribute("placeholder") ?? "").trim());
        } else {
          kinds.add("parts");
          expect(el.closest("fieldset.lab-date")!.querySelector("legend")!.textContent).toBe(d.group);
          if (d.part === "month" && d.select && d.months === "name") {
            kinds.add("month_names");
            const texts = [...(el as unknown as HTMLSelectElement).options].slice(1).map((o) => o.textContent);
            expect(texts).toEqual(monthNames(s.labelLang).full);
          }
        }
      }
    }
    expect([...kinds].sort()).toEqual(["input", "month_names", "parts", "text_bare", "text_hint"]);
  });

  it("civility and sex render as lists or radio groups; nationality as country names, demonyms or text", () => {
    const seen = new Set<string>();
    for (const s of forms) {
      const root = rootOf(s);
      for (const f of s.fields) {
        const c = f.render?.choice;
        if (!c) continue;
        if (f.role === "honorific" || f.role === "sex") {
          seen.add(`${f.role}:${c.kind}`);
          if (c.kind === "radio") {
            const radios = [...root.querySelectorAll<HTMLInputElement>(`input[type=radio][name="${f.name}"]`)];
            expect(radios.map((r) => r.value)).toEqual(c.options.map((o) => o.value));
          } else expect(root.querySelector(`[id="${f.id}"]`)!.tagName).toBe("SELECT");
        }
        if (f.role === "nationality" && c.kind === "select") {
          const demonyms = Object.values(DEMONYMS[L(s) === s.lang ? L(s) : isFormsLang(s.lang) ? s.lang : "en"]).flat();
          seen.add(c.options.every((o) => demonyms.includes(o.label)) ? "nationality:demonyms" : "nationality:names");
        }
        if (f.role === "nationality" && c.kind === "text") seen.add("nationality:text");
      }
    }
    for (const k of ["honorific:select", "honorific:radio", "sex:select", "sex:radio", "nationality:names", "nationality:demonyms", "nationality:text"]) {
      expect(seen.has(k), k).toBe(true);
    }
  });

  it("forms roles carry labels of the forms lexicon in the label language", () => {
    for (const s of forms.filter((x) => !x.traits.includes("mixed_language"))) {
      for (const f of s.fields) {
        const d = f.render?.date;
        if (d?.kind === "part") expect(formsLabels(`bday_${d.part}`, s.labelLang)).toContain(f.label);
        else if (["honorific", "passport_number", "license_number", "vat_number", "birth_name", "job_title"].includes(f.role)) {
          expect(formsLabels(f.role as "vat_number", s.labelLang), `${s.index} ${f.role}`).toContain(f.label);
        }
      }
    }
  });
});
