// Simulated front-end frameworks of the autofill lab forms (generator version
// 2), in plain HTML and script, no framework dependency: the markers a page
// built with React, Vue or Angular carries (root attribute, generated
// attribute names, state classes) and their controlled inputs. React and Vue
// keep each value in a state object and rerender on every input event: the
// DOM value of every control is set back to its state, so a value written
// without an input event is lost at the next rerender, as on a real page.
// Angular's reactive forms do not rewrite siblings; only their state classes
// change. Markup is a pure function of its inputs (no clock, no randomness).
import { esc, scriptJson } from "./render-forms.ts";
import type { FrameworkId } from "./model.ts";

/** FNV-1a of `key` as 8 hex digits: the generated part of attribute names, stable for a form. */
export function hashOf(key: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) h = Math.imul(h ^ key.charCodeAt(i), 0x01000193);
  return (h >>> 0).toString(16).padStart(8, "0");
}

/** Attributes a framework puts on a control named `name` of the form hashed `hash`. */
export function frameworkAttrs(fw: FrameworkId, hash: string, name: string): string {
  switch (fw) {
    case "react": return ` class="css-${hash.slice(0, 6)}"`;
    case "vue": return ` data-v-${hash}=""`;
    case "angular": return ` _ngcontent-ng-c${parseInt(hash.slice(0, 7), 16)}="" ng-reflect-name="${esc(name)}" class="ng-untouched ng-pristine ng-valid"`;
    default: return "";
  }
}

/** The form inside the root element the framework mounts into. */
export function frameworkRoot(fw: FrameworkId, hash: string, form: string): string {
  switch (fw) {
    case "react": return `<div id="root"><div data-reactroot="">${form}</div></div>`;
    case "vue": return `<div id="app" data-v-app="">${form}</div>`;
    case "angular": return `<app-root ng-version="17.3.12" _nghost-ng-c${parseInt(hash.slice(0, 7), 16)}="">${form}</app-root>`;
    default: return form;
  }
}

// Delegated on the document (capture), so it outlives delayed mounts and
// spa_rerender clones; composedPath()[0] reaches into open shadow roots.
const FRAMEWORK_JS = `(function () {
  var fw = __FW__;
  var state = {};
  function controls(form) {
    return form.querySelectorAll("input[name]:not([type=hidden]):not([data-lab-honeypot]), select[name]");
  }
  function rerender(form) {
    Array.prototype.forEach.call(controls(form), function (el) {
      // A controlled radio or checkbox holds its checked state, never its option value.
      if (el.type === "radio" || el.type === "checkbox") return;
      var v = state[el.name] === undefined ? "" : state[el.name];
      if (el.value !== v) el.value = v;
    });
  }
  document.addEventListener("input", function (e) {
    var t = e.composedPath ? e.composedPath()[0] : e.target;
    if (!t || !t.name || !t.form || t.form.id !== "lab-form" || t.hasAttribute("data-lab-honeypot")) return;
    state[t.name] = t.value;
    if (fw === "angular") {
      t.classList.remove("ng-pristine", "ng-untouched");
      t.classList.add("ng-dirty", "ng-touched");
      return;
    }
    var form = t.form;
    Promise.resolve().then(function () { rerender(form); });
  }, true);
})();`;

/** The controlled-input runtime of `fw` ("" for a static page). */
export function frameworkScript(fw: FrameworkId): string {
  if (fw === "static") return "";
  return `<script>${FRAMEWORK_JS.replace("__FW__", () => scriptJson(fw))}</script>`;
}
