// Form building blocks of the autofill lab renderer: escaping, the shared
// stylesheet, field / honeypot / decoy / relay markup and the two inline
// runtimes (form behaviours and the passkey ceremony). Layouts and simulated
// frameworks (generator version 2) live in layouts.ts and frameworks.ts.
// Pure string builders: no DOM, no clock, no randomness.
import { frameworkAttrs, frameworkRoot, hashOf } from "./frameworks.ts";
import { datePartOptions } from "./forms-flows.ts";
import { datePlaceholder } from "./forms-lexicon.ts";
import { layoutCss, layoutField, layoutGroup } from "./layouts.ts";
import type { ChoiceOption, FieldSpec, FrameworkId, Honeypot, Lang, LayoutId, PasswordPolicy, Role } from "./model.ts";
import { policyAttrs, policyHint } from "./policy.ts";

/** Roles a step of a multi-step form can hold: identifier, password, one-time code. */
export const STEP_ROLES: readonly Role[] = ["username", "email", "password", "otp"];

/** Escapes a value for HTML text and double- or single-quoted attributes. */
export function esc(value: string): string {
  return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** JSON for an inline script: no character of the result can close the script or open markup. */
export function scriptJson(value: unknown): string {
  return JSON.stringify(value).replace(/[<>&'\u2028\u2029]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

export const CSS = `*{box-sizing:border-box}
body{margin:0;font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1d1d1f;background:#f5f5f7}
.top{padding:14px 24px;background:#fff;border-bottom:1px solid #e3e3e8}
.brand{font-weight:700;font-size:18px;color:#1d1d1f;text-decoration:none}
main{max-width:440px;margin:40px auto;padding:28px;background:#fff;border:1px solid #e3e3e8;border-radius:10px}
h1{font-size:22px;margin:0 0 18px}
.field{margin:0 0 14px}
label{display:block;margin:0 0 4px;font-size:13px;font-weight:600}
input,select{width:100%;padding:9px 10px;font:inherit;color:inherit;background:#fff;border:1px solid #c7c7cc;border-radius:6px}
button,.btn{display:inline-block;width:100%;margin:4px 0 0;padding:10px 14px;font:inherit;font-weight:600;color:#fff;background:#2f5bea;border:0;border-radius:6px;text-align:center;text-decoration:none;cursor:pointer}
.status{min-height:1.2em;margin:0 0 12px;color:#3a3a3c}
.status.error{color:#c62828}
.otp-cells{display:flex;gap:8px}
.otp-cell{width:44px;text-align:center}
.account{display:block;margin:0 0 8px;color:#1d1d1f;background:#fff;border:1px solid #c7c7cc;text-align:left}
.account small{display:block;font-weight:400;color:#6e6e73}
.accounts{list-style:none;margin:0;padding:0}
.muted{color:#6e6e73}
iframe{display:block;width:100%;height:1000px;border:0}
lab-shell{display:block}
footer{margin:24px 0;color:#86868b;font-size:12px;text-align:center}
.hint{display:block;margin:4px 0 0;color:#6e6e73;font-size:12px}
fieldset{margin:0 0 14px;padding:10px 12px;border:1px solid #e3e3e8;border-radius:8px}
legend{padding:0 4px;font-size:13px;font-weight:700}
.lab-date .field{display:inline-block;width:32%;margin-right:1%}
.lab-radio label,.lab-same{display:inline-flex;gap:6px;align-items:center;margin:0 12px 0 0;font-weight:400}
.lab-radio input,.lab-same input{width:auto}
[hidden]{display:none!important}`;

const MONTHS = Array.from({ length: 12 }, (_, k) => String(k + 1).padStart(2, "0"));
// Fixed range (rendering is clock-free): covers every expiry the generator draws (2028..2033).
const YEARS = Array.from({ length: 16 }, (_, k) => String(2025 + k));
const NUMERIC = new Set<string>(["otp", "cc_number", "cc_csc", "postal_code"]);

const HONEYPOT_CSS: Record<Honeypot["style"], string> = {
  display_none: "display:none",
  offscreen: "position:absolute;left:-10000px",
  opacity: "opacity:0",
  one_pixel: "width:1px;height:1px;padding:0;border:0",
  aria_hidden: "position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);clip-path:inset(50%);white-space:nowrap",
};

const attr = (name: string, value: string | undefined) => (value === undefined ? "" : ` ${name}="${esc(value)}"`);

function control(f: FieldSpec, autocomplete: string | undefined, extra = ""): string {
  const common = `id="${esc(f.id)}" name="${esc(f.name)}"${attr("autocomplete", autocomplete)}${extra}`;
  if (f.type === "select") {
    const values = f.role === "cc_exp_month" ? MONTHS : YEARS;
    const options = values.map((v) => `<option value="${v}">${v}</option>`).join("");
    return `<select ${common}><option value="">--</option>${options}</select>`;
  }
  return `<input type="${esc(f.type)}" ${common}${NUMERIC.has(f.role) ? ' inputmode="numeric"' : ""}>`;
}

function otpCells(f: FieldSpec, autocomplete: string | undefined, extra = ""): string {
  const cells = Array.from({ length: 6 }, (_, k) => `<input type="text" class="otp-cell" id="${esc(f.id)}-${k + 1}"`
    + ` inputmode="numeric" maxlength="1" aria-label="${k + 1}/6"${k === 0 ? attr("autocomplete", autocomplete) : ""}${extra}>`).join("");
  return `<div class="field"><label for="${esc(f.id)}-1">${esc(f.label)}</label><div class="otp-cells">${cells}</div>`
    + `<input type="hidden" id="${esc(f.id)}" name="${esc(f.name)}" data-lab-otp></div>`;
}

export function honeypotHtml(hp: Honeypot): string {
  const type = hp.role === "password" || hp.role === "new_password" ? "password" : hp.role === "email" ? "email" : "text";
  const aria = hp.style === "aria_hidden" ? ' aria-hidden="true" tabindex="-1"' : "";
  return `<input type="${type}" name="${esc(hp.name)}" data-lab-honeypot style="${HONEYPOT_CSS[hp.style]}"${aria}>`;
}

/** The blocks of a forms page (generator version 4): legends by "<person>|<block>", the shipping toggle, the page language. */
export interface FormsBlocks {
  legends: Record<string, string>;
  /** Label of the "same as billing" checkbox, and whether it is checked (shipping block hidden). */
  sameLabel: string;
  shippingSame?: boolean;
  /** Site language: placeholder letters of text dates. */
  lang: Lang;
  /** Label language: month names of date lists. */
  labelLang: Lang;
}

export interface FormSpec {
  action: string;
  fields: FieldSpec[];             // visible fields of this page, in order
  labels?: Map<FieldSpec, string>; // label overrides (signup password order)
  honeypot?: Honeypot;             // already filtered to this page
  noAutocomplete: boolean;
  /** Signup only: the rules the new-password fields state, and the site language of the hint sentence. */
  passwordPolicy?: { policy: PasswordPolicy; lang: string };
  splitOtp: boolean;
  reveal: boolean;                 // email then password: password step hidden until "next"
  submit: string;
  next?: string;                   // label of the reveal button, or of the submit of a first step
  forms?: FormsBlocks;             // forms flows: fields grouped in blocks, dates and choices rendered
}

export interface FormLook {
  layout?: LayoutId;                 // default "stacked": the version 1 markup
  framework?: FrameworkId;           // default "static": no framework markers
  labelMarks?: boolean;              // data-lab-field="<index>" on each control (dataset only, Task 9)
}

const options = (xs: ChoiceOption[]) => xs.map((o) => `<option value="${esc(o.value)}">${esc(o.label)}</option>`).join("");

/** The control of a forms field: choice and date-part lists, date-part text boxes, plain inputs. */
function formsControl(f: FieldSpec, autocomplete: string | undefined, extra: string, monthLang: Lang): string {
  const common = `id="${esc(f.id)}" name="${esc(f.name)}"${attr("autocomplete", autocomplete)}${extra}`;
  const choice = f.render?.choice;
  const date = f.render?.date;
  if (choice && choice.kind === "select") return `<select ${common}><option value="">--</option>${options(choice.options)}</select>`;
  if (date?.kind === "part") {
    if (date.select) return `<select ${common}><option value="">--</option>${options(datePartOptions(f.role, date, monthLang))}</select>`;
    return `<input type="text" ${common} inputmode="numeric" maxlength="${date.part === "year" ? 4 : 2}">`;
  }
  return `<input type="${esc(f.type)}" ${common}${NUMERIC.has(f.role) ? ' inputmode="numeric"' : ""}>`;
}

/** A radio group: one fieldset whose legend is the question, one radio per option (ids "<id>-<k>"). */
function radioGroup(f: FieldSpec, extra: string): string {
  const choice = f.render?.choice;
  const opts = choice && choice.kind === "radio" ? choice.options : [];
  const radios = opts.map((o, k) => `<label><input type="radio" id="${esc(f.id)}-${k + 1}" name="${esc(f.name)}" value="${esc(o.value)}"${extra}> ${esc(o.label)}</label>`).join("");
  return `<fieldset class="field lab-radio" id="${esc(f.id)}"><legend>${esc(f.label)}</legend>${radios}</fieldset>`;
}

/**
 * The fields of a forms page: one fieldset per block (person and block), with its legend; the shipping block after
 * its "same as billing" checkbox (hidden when checked); the three parts of a split date in a fieldset whose legend
 * is the date's label; radio groups; a text date's format as a placeholder (in the label where the layout uses the
 * placeholder for something else).
 */
function formsFieldParts(spec: FormSpec, blocks: FormsBlocks, layout: LayoutId, fw: FrameworkId, hash: string, marks: boolean,
  placeHoneypot: (role: string) => string): string[] {
  const out: string[] = [];
  let open: string | undefined;
  const close = () => {
    if (open !== undefined) out.push("</fieldset>");
    open = undefined;
  };
  const fields = spec.fields;
  for (let i = 0; i < fields.length; i++) {
    const f = fields[i]!;
    const key = `${f.person ?? 0}|${f.block ?? ""}`;
    if (key !== open) {
      close();
      if (f.block === "shipping") {
        const checked = blocks.shippingSame === true;
        out.push(`<label class="lab-same"><input type="checkbox" id="lab-same" name="same_as_billing"${checked ? " checked" : ""}`
          + ` onchange="this.closest('form').querySelector('#lab-ship').hidden=this.checked"> ${esc(blocks.sameLabel)}</label>`);
        out.push(`<fieldset class="lab-block" id="lab-ship"${checked ? " hidden" : ""}>`);
      } else {
        out.push(`<fieldset class="lab-block">`);
      }
      const legend = blocks.legends[key] ?? "";
      if (legend) out.push(`<legend>${esc(legend)}</legend>`);
      open = key;
    }
    out.push(placeHoneypot(f.role));
    const auto = spec.noAutocomplete ? undefined : f.autocomplete;
    const mark = (k: number) => (marks ? ` data-lab-field="${k}"` : "");
    const date = f.render?.date;
    if (date?.kind === "part") {
      // The parts of one date: consecutive fields of the same role, person and group.
      const group: number[] = [i];
      while (i + 1 < fields.length) {
        const g = fields[i + 1]!;
        const d = g.render?.date;
        if (d?.kind !== "part" || d.group !== date.group || g.role !== f.role && !(g.role.startsWith("bday_") && f.role.startsWith("bday_"))
          || (g.person ?? 0) !== (f.person ?? 0)) break;
        group.push(++i);
      }
      const inner = group.map((k) => {
        const p = fields[k]!;
        const pauto = spec.noAutocomplete ? undefined : p.autocomplete;
        return `<div class="field"><label for="${esc(p.id)}">${esc(p.label)}</label>`
          + `${formsControl(p, pauto, `${frameworkAttrs(fw, hash, p.name)}${mark(k)}`, blocks.labelLang)}</div>`;
      }).join("");
      out.push(`<fieldset class="lab-date"><legend>${esc(date.group)}</legend>${inner}</fieldset>`);
      continue;
    }
    if (f.render?.choice?.kind === "radio") {
      out.push(radioGroup(f, `${frameworkAttrs(fw, hash, f.name)}${mark(i)}`));
      continue;
    }
    const format = date?.kind === "text" && date.placeholder ? datePlaceholder(date.format, blocks.lang) : undefined;
    const inLabel = format !== undefined && (layout === "floating" || layout === "placeholder_only");
    const label = inLabel ? `${f.label} (${format})` : f.label;
    out.push(layoutField(layout, {
      id: esc(f.id), label: esc(label), select: f.type === "select",
      control: (extra) => formsControl(f, auto, `${extra}${format !== undefined && !inLabel ? ` placeholder="${esc(format)}"` : ""}`
        + `${frameworkAttrs(fw, hash, f.name)}${mark(i)}`, blocks.labelLang),
    }));
  }
  close();
  return out;
}

/** The main `form#lab-form`, fields in order, honeypot right before the field of its role. */
export function formHtml(spec: FormSpec, opts: FormLook = {}): string {
  const layout = opts.layout ?? "stacked";
  const fw = opts.framework ?? "static";
  const hash = hashOf(`${spec.action}|${spec.fields.map((f) => f.id).join("|")}`);
  const parts: string[] = [];
  const fieldParts: string[] = [];
  if (spec.forms) {
    let placed = false;
    const hp = (role: string) => {
      if (!spec.honeypot || placed || spec.honeypot.role !== role) return "";
      placed = true;
      return honeypotHtml(spec.honeypot);
    };
    fieldParts.push(...formsFieldParts(spec, spec.forms, layout, fw, hash, opts.labelMarks === true, hp));
    if (spec.honeypot && !placed) fieldParts.push(honeypotHtml(spec.honeypot));
    parts.push(layoutGroup(layout, fieldParts.join("")));
    parts.push(`<button type="submit" id="lab-submit">${esc(spec.submit)}</button>`);
    const css = layoutCss(layout);
    const form = `<form id="lab-form" method="post" action="${esc(spec.action)}">${parts.join("")}</form>`;
    return (css ? `<style>${css}</style>` : "") + frameworkRoot(fw, hash, form);
  }
  let hpPlaced = false;
  const placeHoneypot = () => {
    if (spec.honeypot && !hpPlaced) { fieldParts.push(honeypotHtml(spec.honeypot)); hpPlaced = true; }
  };
  const policy = spec.passwordPolicy;
  const hint = policy ? policyHint(policy.policy, policy.lang) : undefined;
  let hintPlaced = false;
  spec.fields.forEach((f, index) => {
    if (spec.honeypot?.role === f.role) placeHoneypot();
    const auto = spec.noAutocomplete ? undefined : f.autocomplete;
    const label = spec.labels?.get(f) ?? f.label;
    const mark = opts.labelMarks ? ` data-lab-field="${index}"` : "";
    let html = f.role === "otp" && spec.splitOtp
      ? otpCells({ ...f, label }, auto, mark)
      : layoutField(layout, {
        id: esc(f.id), label: esc(label), select: f.type === "select",
        control: (extra) => {
          const stated = policy && f.role === "new_password" ? policyAttrs(policy.policy, esc) : "";
          let html = control(f, auto, `${extra}${frameworkAttrs(fw, hash, f.name)}${mark}${stated}`);
          // The written hint follows the first new-password field, where a real page puts it.
          if (hint !== undefined && f.role === "new_password" && !hintPlaced) {
            hintPlaced = true;
            html += `<small class="hint">${esc(hint)}</small>`;
          }
          return html;
        },
      });
    if (spec.reveal && f.role === "password") html = `<div id="lab-pw-step" hidden>${html}</div>`;
    fieldParts.push(html);
  });
  placeHoneypot();
  parts.push(layoutGroup(layout, fieldParts.join("")));
  if (spec.reveal) {
    parts.push(`<button type="button" id="lab-next">${esc(spec.next ?? spec.submit)}</button>`);
    parts.push(`<button type="submit" id="lab-submit" hidden>${esc(spec.submit)}</button>`);
  } else {
    parts.push(`<button type="submit" id="lab-submit">${esc(spec.submit)}</button>`);
  }
  const css = layoutCss(layout);
  const form = `<form id="lab-form" method="post" action="${esc(spec.action)}">${parts.join("")}</form>`;
  return (css ? `<style>${css}</style>` : "") + frameworkRoot(fw, hash, form);
}

/** Hidden light-DOM form that carries the values of a form living in a shadow root. */
export function relayHtml(action: string, names: string[]): string {
  const inputs = [...new Set(names)].map((n) => `<input type="hidden" name="${esc(n)}">`).join("");
  return `<form id="lab-form" method="post" action="${esc(action)}" hidden>${inputs}</form>`;
}

/** Names a form posts: visible fields (the OTP carrier for split cells) and the honeypot. */
export function postedNames(spec: FormSpec): string[] {
  return [...spec.fields.map((f) => f.name), ...(spec.honeypot ? [spec.honeypot.name] : [])];
}

/** A second, invisible login form (decoy_form trait), placed before the real one. */
export function decoyHtml(identifier: FieldSpec | undefined, password: FieldSpec | undefined, submit: string): string {
  const field = (f: FieldSpec, type: string) => `<div class="field"><label for="${esc(f.id)}-alt">${esc(f.label)}</label>`
    + `<input type="${type}" id="${esc(f.id)}-alt" name="${esc(f.name)}"></div>`;
  const inner = [identifier ? field(identifier, identifier.type) : "", password ? field(password, "password") : ""].join("");
  return `<form data-lab-decoy method="post" action="/decoy" style="display:none">${inner}<button type="submit">${esc(submit)}</button></form>`;
}

export interface RuntimeConfig {
  shadow?: "open" | "closed";
  delayMs?: number;
  spa: boolean;
  reveal: boolean;
  split: boolean;
}

// Form behaviours. Listeners are delegated on the root (document or shadow
// root) so they survive the spa_rerender clone. Shadow pages also expose the
// two page-level test hooks the lab driver uses (no randomness, no clock).
const RUNTIME_JS = `(function () {
  var cfg = __CFG__;
  function wire(root) {
    var spaDone = false;
    function q(sel) { return root.querySelector(sel); }
    function reveal() {
      var step = q("#lab-pw-step");
      if (!step || !step.hidden) return false;
      step.hidden = false;
      var next = q("#lab-next"), submit = q("#lab-submit");
      if (next) next.hidden = true;
      if (submit) submit.hidden = false;
      var input = step.querySelector("input");
      if (input) input.focus();
      return true;
    }
    root.addEventListener("click", function (e) {
      var t = e.target;
      if (t && t.closest && t.closest("#lab-next")) { e.preventDefault(); reveal(); }
    });
    root.addEventListener("submit", function (e) {
      var form = e.target;
      if (cfg.reveal && reveal()) { e.preventDefault(); return; }
      var carrier = form.querySelector("input[data-lab-otp]");
      if (carrier) {
        var code = "";
        form.querySelectorAll(".otp-cell").forEach(function (c) { code += c.value; });
        carrier.value = code;
      }
      if (cfg.shadow) {
        e.preventDefault();
        var relay = document.getElementById("lab-form");
        Array.prototype.forEach.call(form.elements, function (el) {
          if (!el.name) return;
          if ((el.type === "radio" || el.type === "checkbox") && !el.checked) return;
          var target = relay.elements.namedItem(el.name);
          if (target) target.value = el.value;
        });
        relay.submit();
      }
    });
    if (cfg.split) {
      var cellsOf = function (t) { return Array.prototype.slice.call(t.form.querySelectorAll(".otp-cell")); };
      var spread = function (t, digits) {
        var cells = cellsOf(t), k = cells.indexOf(t);
        for (var i = 0; i < digits.length && k + i < cells.length; i++) cells[k + i].value = digits[i];
        cells[Math.min(k + digits.length, cells.length - 1)].focus();
      };
      root.addEventListener("input", function (e) {
        var t = e.target;
        if (!t.classList || !t.classList.contains("otp-cell")) return;
        var digits = t.value.replace(/\\D/g, "");
        if (digits.length > 1) { spread(t, digits); return; }
        t.value = digits;
        var cells = cellsOf(t), k = cells.indexOf(t);
        if (digits && k + 1 < cells.length) cells[k + 1].focus();
      });
      root.addEventListener("keydown", function (e) {
        var t = e.target;
        if (e.key !== "Backspace" || !t.classList || !t.classList.contains("otp-cell") || t.value) return;
        var cells = cellsOf(t), k = cells.indexOf(t);
        if (k > 0) cells[k - 1].focus();
      });
      root.addEventListener("paste", function (e) {
        var t = e.target;
        if (!t.classList || !t.classList.contains("otp-cell") || !e.clipboardData) return;
        var digits = e.clipboardData.getData("text").replace(/\\D/g, "");
        if (digits.length > 1) { e.preventDefault(); spread(t, digits); }
      });
    }
    if (cfg.shadow) {
      // Lab driver hooks: a closed shadow root is out of reach of locators, not of a
      // user. __labField gives a field's box (to click it) and whether it holds a
      // value; __labSubmit sends the form as its submit button would.
      window.__labField = function (sel) {
        var el = root.querySelector(sel);
        if (!el) return null;
        var r = el.getBoundingClientRect();
        return { x: r.left, y: r.top, width: r.width, height: r.height, filled: "value" in el && el.value !== "" };
      };
      window.__labSubmit = function () {
        reveal();
        var form = q("#lab-form");
        if (form) form.requestSubmit();
      };
    }
    if (cfg.spa) {
      root.addEventListener("input", function () {
        if (spaDone) return;
        spaDone = true;
        var old = q("#lab-form");
        if (!old) return;
        var fresh = old.cloneNode(true);
        var from = old.querySelectorAll("input, select"), to = fresh.querySelectorAll("input, select");
        for (var i = 0; i < from.length; i++) to[i].value = from[i].value;
        var focused = Array.prototype.indexOf.call(from, root.activeElement);
        old.replaceWith(fresh);
        if (focused >= 0) to[focused].focus();
      });
    }
  }
  function mount() {
    var tpl = document.getElementById("lab-tpl"), root = document;
    if (tpl) {
      var node = tpl.content.cloneNode(true);
      if (cfg.shadow) {
        root = document.querySelector("lab-shell").attachShadow({ mode: cfg.shadow });
        root.appendChild(node);
      } else {
        document.getElementById("lab-mount").replaceWith(node);
      }
    }
    wire(root);
  }
  if (cfg.delayMs) setTimeout(mount, cfg.delayMs); else mount();
})();`;

export function runtimeScript(cfg: RuntimeConfig): string {
  return `<script>${RUNTIME_JS.replace("__CFG__", () => scriptJson(cfg))}</script>`;
}

export interface PasskeyConfig { challenge: string; rpId: string; credentialId: string; endpoint: string; next: string; refused: string }

// WebAuthn assertion, posted as JSON with base64url members.
const PASSKEY_JS = `(function () {
  var cfg = __CFG__;
  function bytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var b = atob(s), out = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
    return out;
  }
  function b64u(buf) {
    var a = new Uint8Array(buf), s = "";
    for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  }
  function refused() {
    var status = document.getElementById("lab-status");
    status.textContent = cfg.refused;
    status.className = "status error";
  }
  document.getElementById("lab-passkey").addEventListener("click", function (e) {
    e.preventDefault();
    Promise.resolve().then(function () {
      return navigator.credentials.get({ publicKey: {
        challenge: bytes(cfg.challenge), rpId: cfg.rpId,
        allowCredentials: [{ type: "public-key", id: bytes(cfg.credentialId) }],
        timeout: 8000, userVerification: "discouraged"
      } });
    }).then(function (cred) {
      if (!cred) throw new Error("no credential");
      var r = cred.response;
      return fetch(cfg.endpoint, {
        method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" },
        body: JSON.stringify({ credentialId: b64u(cred.rawId), clientDataJSON: b64u(r.clientDataJSON),
          authenticatorData: b64u(r.authenticatorData), signature: b64u(r.signature) })
      });
    }).then(function (res) {
      if (!res.ok) throw new Error("refused");
      location.assign(res.redirected ? res.url : cfg.next);
    }).catch(refused);
  });
})();`;

export function passkeyScript(cfg: PasskeyConfig): string {
  return `<script>${PASSKEY_JS.replace("__CFG__", () => scriptJson(cfg))}</script>`;
}
