// A fictional other password manager, as an extension injects its UI: a save
// notification in the top right corner (a custom element at the top of the
// document, open shadow root, fixed, very high z-index) and an in-field button
// at the right edge of the identifier field. Used by the stacking test and its
// capture; nothing here talks to anything.
(() => {
  const corner = document.createElement("com-1password-notification");
  corner.id = "other-manager-notification";
  corner.style.cssText = "all:initial;position:fixed;top:12px;right:12px;width:330px;height:132px;z-index:2147483646;display:block";
  corner.attachShadow({ mode: "open" }).innerHTML =
    '<div style="box-sizing:border-box;width:100%;height:100%;padding:16px;border-radius:12px;background:#1F2933;color:#F5F7FA;font:13px/1.4 -apple-system,system-ui,sans-serif;box-shadow:0 8px 24px rgba(0,0,0,.3)">' +
    '<b style="font-size:14px">Other Manager</b><br>Save this login to Other Manager?<br><br>' +
    '<span style="display:inline-block;padding:4px 10px;border-radius:6px;background:#3E4C59">Save</span></div>';
  document.documentElement.appendChild(corner);

  const field = document.getElementById("email");
  if (field) {
    const r = field.getBoundingClientRect();
    const b = document.createElement("com-1password-button");
    b.id = "other-manager-button";
    b.style.cssText =
      "all:initial;position:absolute;display:block;width:20px;height:20px;border-radius:5px;background:#3E4C59;z-index:2147483646;" +
      `left:${Math.round(r.right + scrollX - 26)}px;top:${Math.round(r.top + scrollY + (r.height - 20) / 2)}px`;
    document.body.appendChild(b);
  }
})();
