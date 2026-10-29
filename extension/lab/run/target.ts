// The field whose OnePass icon the smart_fill driver clicks, chosen with the
// content script's own icon roles (content/icon.ts) so the lab never clicks
// a field that carries no icon. Lab roles map to extension roles by name,
// except the sign-in password (current_password).
import { ICON_ROLES } from "../../src/content/icon.ts";
import type { FieldRole } from "../../src/shared/messages.ts";
import type { FieldSpec, Role, Site } from "../gen/model.ts";

/** The extension role of a lab role. */
const extensionRole = (r: Role): FieldRole => (r === "password" ? "current_password" : (r as FieldRole));

/** The new password on signup (the user typed the email), else the form's first field with an icon. */
export function smartTarget(site: Site): FieldSpec | undefined {
  if (site.flow === "signup") return site.fields.find((f) => f.role === "new_password");
  return site.fields.find((f) => ICON_ROLES.has(extensionRole(f.role)));
}
