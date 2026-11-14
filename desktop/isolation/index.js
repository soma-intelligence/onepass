// Tauri isolation pattern (spec 2026-10-30 section 3.2): every IPC message
// of the web view passes here, in a sandboxed iframe, before Tauri encrypts
// it for the backend. Only the app's own commands and event listening go
// through; anything else (a plugin command injected by a compromised page)
// is dropped.
const ALLOWED = new Set([
  "status",
  "create_account",
  "unlock",
  "lock",
  "vaults",
  "items",
  "item",
  "item_types",
  "new_item",
  "save_item",
  "trash_item",
  "set_favorite",
  "reveal_field",
  "copy_field",
  "totp",
  "generate_password",
  "plugin:event|listen",
  "plugin:event|unlisten",
]);

window.__TAURI_ISOLATION_HOOK__ = (payload) => {
  if (payload && typeof payload.cmd === "string" && ALLOWED.has(payload.cmd)) {
    return payload;
  }
  return null;
};
