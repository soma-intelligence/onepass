// Fake password manager for the OnePass real-site bench ("Machine polluée").
// The same file ships in fake/1password, fake/lastpass and fake/dashlane; the
// manifest's short_name ("fake-1password", ...) picks which manager it
// imitates, so the active fakes are exactly the extensions loaded.
//
// What it imitates, in the page DOM:
//   1password: a `com-1password-button` custom element at the right of the
//     username and password fields; on focus, a dropdown
//     (`com-1password-menu`) whose content lives in a closed shadow root.
//   lastpass: a `div[data-lastpass-icon-root]` icon at the right of the
//     fields; on icon click or focus, a `div[data-lastpass-root]` dropdown.
//   dashlane: `data-dashlane-rid` (and label) attributes on the fields, an
//     icon at the right, a small dropdown on focus.
//
// Safety: it only fills fictional values, only when its own dropdown row gets
// a trusted click; it reads no field value, stores nothing and sends nothing
// (no network API is used anywhere in this file).
(() => {
  "use strict";

  const short = (chrome.runtime.getManifest().short_name || "").replace(/^fake-/, "");
  const KINDS = {
    "1password": { label: "1Password", color: "#0572EC", inset: 6, openOn: "focus" },
    lastpass: { label: "LastPass", color: "#D32D27", inset: 30, openOn: "focus-or-icon" },
    dashlane: { label: "Dashlane", color: "#0E353D", inset: 54, openOn: "focus" },
  };
  const kind = KINDS[short] ? short : null;
  if (!kind || window.top !== window) return;
  const cfg = KINDS[kind];
  const ICON = 20;
  const FICTIONAL = { username: `fake-${kind}@example.test`, password: `Fake-${cfg.label}-Pass-0000` };
  const MARK = `data-fake-${kind}`;
  /** Set on every icon and menu of every fake, so no fake reacts to the fakes' own DOM churn. */
  const OURS = "data-fake-manager";

  /** field -> { role, icon } */
  const tracked = new Map();
  let menu = null; // { host, field }

  const isVisible = (el) => {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== "hidden";
  };

  const USERISH = /user|login|email|e-mail|mail|account|ident|phone/i;

  /** Username and password fields of the page, as a manager's heuristics would see them. */
  function findFields() {
    const out = [];
    const inputs = [...document.querySelectorAll("input")];
    const passwords = inputs.filter((i) => i.type === "password");
    for (const p of passwords) out.push([p, "password"]);
    for (const i of inputs) {
      if (i.type === "email") { out.push([i, "username"]); continue; }
      if (i.type !== "text" && i.type !== "tel" && i.type !== "") continue;
      const ac = (i.getAttribute("autocomplete") || "").toLowerCase();
      const hint = `${i.name} ${i.id} ${i.placeholder} ${i.getAttribute("aria-label") || ""}`;
      if (ac.includes("username") || ac.includes("email") || (USERISH.test(hint) && (passwords.length > 0 || /log ?in|sign ?in/i.test(document.title + location.pathname)))) {
        out.push([i, "username"]);
      }
    }
    return out.filter(([el]) => isVisible(el) && !el.disabled && !el.readOnly);
  }

  function makeIcon() {
    let icon;
    if (kind === "1password") {
      icon = document.createElement("com-1password-button");
    } else if (kind === "lastpass") {
      icon = document.createElement("div");
      icon.setAttribute("data-lastpass-icon-root", "");
    } else {
      icon = document.createElement("div");
      icon.setAttribute("data-dashlanecreated", "true");
      icon.setAttribute("data-dashlane-icon", "");
    }
    icon.setAttribute(MARK, "icon");
    icon.setAttribute(OURS, kind);
    icon.title = `${cfg.label} (lab fake)`;
    icon.style.cssText =
      `all:initial;position:absolute;display:block;box-sizing:border-box;width:${ICON}px;height:${ICON}px;` +
      `border-radius:${kind === "dashlane" ? "4px" : "50%"};background:${cfg.color};cursor:pointer;z-index:2147483645;` +
      "color:#fff;font:bold 11px/20px -apple-system,system-ui,sans-serif;text-align:center";
    icon.textContent = cfg.label[0];
    icon.addEventListener("mousedown", (e) => e.preventDefault());
    icon.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      const entry = [...tracked].find(([, t]) => t.icon === icon);
      if (entry) openMenu(entry[0]);
    });
    document.documentElement.appendChild(icon);
    return icon;
  }

  function place(field, icon) {
    if (!field.isConnected || !isVisible(field)) { icon.style.display = "none"; return; }
    const r = field.getBoundingClientRect();
    icon.style.display = "block";
    icon.style.left = `${Math.round(r.right + scrollX - cfg.inset - ICON)}px`;
    icon.style.top = `${Math.round(r.top + scrollY + (r.height - ICON) / 2)}px`;
  }

  function scan() {
    for (const [field, role] of findFields()) {
      if (tracked.has(field)) continue;
      if (kind === "dashlane") {
        field.setAttribute("data-dashlane-rid", Math.random().toString(16).slice(2, 18).padEnd(16, "0"));
        field.setAttribute("data-dashlane-label", "true");
        field.setAttribute("data-form-type", role === "password" ? "password" : "email");
      }
      field.setAttribute(MARK, role);
      const icon = makeIcon();
      tracked.set(field, { role, icon });
      field.addEventListener("focus", (e) => { if (e.isTrusted && cfg.openOn !== "icon") openMenu(field); });
    }
    for (const [field, t] of tracked) {
      if (!field.isConnected) { t.icon.remove(); tracked.delete(field); continue; }
      place(field, t.icon);
    }
    if (menu) placeMenu();
  }

  function closeMenu() {
    if (!menu) return;
    menu.host.remove();
    menu = null;
  }

  function placeMenu() {
    const r = menu.field.getBoundingClientRect();
    menu.host.style.left = `${Math.round(r.left + scrollX)}px`;
    menu.host.style.top = `${Math.round(r.bottom + scrollY + 4)}px`;
    menu.host.style.width = `${Math.max(220, Math.min(320, Math.round(r.width)))}px`;
  }

  function openMenu(field) {
    if (menu && menu.field === field) return;
    closeMenu();
    let host;
    if (kind === "1password") {
      host = document.createElement("com-1password-menu");
    } else if (kind === "lastpass") {
      host = document.createElement("div");
      host.setAttribute("data-lastpass-root", "");
    } else {
      host = document.createElement("div");
      host.setAttribute("data-dashlane-dropdown", "");
    }
    host.setAttribute(MARK, "menu");
    host.setAttribute(OURS, kind);
    host.style.cssText = "all:initial;position:absolute;display:block;z-index:2147483646";
    // 1Password keeps its menu in a closed shadow root; the others use an open one.
    const root = host.attachShadow({ mode: kind === "1password" ? "closed" : "open" });
    const small = kind === "dashlane";
    root.innerHTML =
      `<div style="box-sizing:border-box;margin:0;padding:${small ? 4 : 6}px;border-radius:8px;background:#fff;color:#1F2933;` +
      `font:${small ? 12 : 13}px/1.35 -apple-system,system-ui,sans-serif;box-shadow:0 6px 20px rgba(0,0,0,.22);border:1px solid #D9DEE3">` +
      `<div style="padding:2px 6px 4px;font-weight:600;color:${cfg.color}">${cfg.label}</div>` +
      `<button type="button" data-row style="all:unset;box-sizing:border-box;display:block;width:100%;padding:${small ? 4 : 6}px 8px;border-radius:6px;cursor:pointer">` +
      `<b>Lab account</b><br><span style="color:#616E7C">${FICTIONAL.username}</span></button></div>`;
    root.querySelector("[data-row]").addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      fill(field);
      closeMenu();
    });
    host.addEventListener("mousedown", (e) => e.preventDefault());
    document.documentElement.appendChild(host);
    menu = { host, field };
    placeMenu();
  }

  function setValue(field, value) {
    const proto = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    proto.set.call(field, value);
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
  }

  /** Fills the fictional pair into the clicked field's form (or the page). */
  function fill(field) {
    const scope = field.form || document;
    for (const [f, t] of tracked) {
      if (!scope.contains(f)) continue;
      setValue(f, t.role === "password" ? FICTIONAL.password : FICTIONAL.username);
    }
  }

  document.addEventListener("mousedown", (e) => {
    if (!menu) return;
    const path = e.composedPath();
    if (path.includes(menu.host) || path.includes(menu.field)) return;
    if ([...tracked.values()].some((t) => path.includes(t.icon))) return;
    closeMenu();
  }, true);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeMenu(); }, true);
  document.addEventListener("focusout", (e) => {
    if (menu && e.target === menu.field) setTimeout(() => { if (menu && document.activeElement !== menu.field) closeMenu(); }, 150);
  }, true);

  let pending = false;
  const schedule = () => {
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => { pending = false; scan(); });
  };
  const isOurs = (n) => n.nodeType === 1 && n.hasAttribute(OURS);
  const relevant = (r) =>
    r.type === "attributes" ? !isOurs(r.target) : [...r.addedNodes, ...r.removedNodes].some((n) => !isOurs(n));
  new MutationObserver((records) => { if (records.some(relevant)) schedule(); }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["type", "style", "class", "hidden"] });
  addEventListener("scroll", schedule, true);
  addEventListener("resize", schedule);
  scan();
})();
