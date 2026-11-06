// Sign-up username fields (MS-06): does a candidate identifier fit the field
// as the page declares it (type, `maxlength`, `minlength`, `pattern`)? Read
// here, in the page's tab, from the field's own attributes; the candidate (an
// e-mail or a handle OnePass made) is neither kept nor logged.
import { patternMatches } from "./password-context";

export interface UsernameFit {
  matches: boolean;
  /** The field's `maxlength`, when it sets one. */
  maxLength?: number;
}

export function usernameFits(el: Element, candidate: string): UsernameFit {
  if (!(el instanceof HTMLInputElement)) return { matches: true };
  const out: UsernameFit = { matches: true };
  const max = el.maxLength;
  if (max > 0) out.maxLength = max;
  const len = [...candidate].length;
  if (max > 0 && len > max) out.matches = false;
  if (el.minLength > 0 && len < el.minLength) out.matches = false;
  const type = el.type.toLowerCase();
  // An e-mail field wants an address; any other text field may refuse one by its pattern.
  if (type === "email" && !/^[^@\s]+@[^@\s]+$/.test(candidate)) out.matches = false;
  const textual = type === "text" || type === "email" || type === "search" || type === "tel" || type === "url" || type === "";
  if (textual && !patternMatches(el.getAttribute("pattern"), candidate)) out.matches = false;
  return out;
}
