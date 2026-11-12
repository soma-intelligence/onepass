// Gesture accounting of the autofill lab: every human-equivalent gesture a
// driver makes while it plays a scenario, toward OnePass (its icon, a row,
// the shortcut, an unlock button, a picker) and toward the site (its submit
// or next button, its passkey button, a field typed by hand). The unlock
// approval (Touch ID, played by the lab's stand-in) is recorded too but
// counted apart: the headline metric reads "one gesture, +1 biometric".
// Pure data and counting, no browser: the drivers record, the oracle and the
// report count.
import type { DriverId, FlowId, StartState, Trigger } from "../gen/model.ts";

export type GestureKind =
  /** A trusted click on the OnePass icon of a field. */
  | "field_icon"
  /** The toolbar Fill (a page without a field to click). */
  | "toolbar"
  /** The fill-smart keyboard command. */
  | "shortcut"
  /** "Se connecter" on the overlay's account. */
  | "overlay_row"
  /** ArrowDown in a field: the in-field menu asked from the keyboard. */
  | "menu_key"
  /** A row of the in-field menu. */
  | "menu_row"
  /** "Other logins" of the overlay: the list opened. */
  | "picker_open"
  /** An account chosen in a list OnePass shows (other logins, passkey window). */
  | "picker"
  /** "Unlock in OnePass" in a locked menu. */
  | "unlock_button"
  /** The unlock approved by the Touch ID stand-in: biometric, counted apart. */
  | "unlock_approval"
  /** The site's own submit or next button. */
  | "site_submit"
  /** Another button of the site (its passkey button). */
  | "site_button"
  /** A field the user typed or edited herself. */
  | "site_type"
  /** Tab or Enter in a field under the ghost suggestion, or a click on its "Use" pill. */
  | "ghost_accept";

/** One gesture: what, on what (a field name, a row kind: never a value), when (ms). */
export interface Gesture { kind: GestureKind; target?: string; at: number }

export const GESTURE_KINDS: readonly GestureKind[] = ["field_icon", "toolbar", "shortcut", "overlay_row", "menu_key", "menu_row",
  "picker_open", "picker", "unlock_button", "unlock_approval", "site_submit", "site_button", "site_type", "ghost_accept"];

/** Gestures that are a biometric approval, not a deliberate click or key. */
const BIOMETRIC = new Set<GestureKind>(["unlock_approval"]);

/** Records the gestures of one scenario attempt, in order. */
export class Gestures {
  readonly list: Gesture[] = [];
  private readonly now: () => number;
  // No parameter property: report.ts loads this module under node's type stripping.
  constructor(now: () => number = Date.now) {
    this.now = now;
  }
  add(kind: GestureKind, target?: string): void {
    this.list.push({ kind, ...(target !== undefined ? { target } : {}), at: this.now() });
  }
}

/** Gestures that start OnePass: the one an unlock approval answers when the user pressed no unlock button. */
const STARTS = new Set<GestureKind>(["field_icon", "toolbar", "shortcut", "overlay_row", "menu_key"]);

/**
 * Adds `approvals` unlock approvals to `list` where they happened: after the
 * unlock button when the user pressed one, else after the gesture that
 * started OnePass (at the front when there is none: an unlock nobody asked).
 */
export function insertApprovals(list: Gesture[], approvals: number, at: number): void {
  const kinds = list.map((g) => g.kind);
  const button = kinds.lastIndexOf("unlock_button");
  const started = kinds.findIndex((k) => STARTS.has(k));
  const index = button >= 0 ? button + 1 : started + 1;
  for (let k = 0; k < approvals; k++) list.splice(index, 0, { kind: "unlock_approval", at });
}

/** Deliberate gestures (clicks, keys, typed fields): everything but the biometric approvals. */
export function gestureCount(list: readonly Gesture[]): number {
  return list.filter((g) => !BIOMETRIC.has(g.kind)).length;
}

/** Biometric approvals (Touch ID stand-in) among `list`. */
export function biometricCount(list: readonly Gesture[]): number {
  return list.filter((g) => BIOMETRIC.has(g.kind)).length;
}

/** The kinds of `list`, in order (what results.jsonl stores: no target, no time). */
export function gestureKinds(list: readonly Gesture[]): GestureKind[] {
  return list.map((g) => g.kind);
}

/** How a driver starts OnePass (its first gesture toward it), whatever the scenario then does. */
export function triggerOf(driver: DriverId, opts: { shortcut?: boolean; hasField?: boolean } = {}): Trigger | undefined {
  switch (driver) {
    case "one_click": return "overlay_row";
    case "menu_fill": return "menu_key";
    case "smart_fill": return opts.shortcut ? "shortcut" : opts.hasField === false ? "toolbar" : "field_icon";
    default: return undefined;
  }
}

/** Flow families of the "one gesture, signed in" table: the flows whose goal is a session. */
export type FlowFamily = "password" | "totp" | "passkey" | "sso" | "multi_step" | "signup";

const FAMILY: Partial<Record<FlowId, FlowFamily>> = {
  login_single: "password", login_username_first: "password", login_email_then_password: "password",
  login_totp: "totp", login_passkey: "passkey", sso: "sso", multi_step: "multi_step", signup: "signup",
};

/** The family of a flow whose goal is a session; undefined for the form flows (nothing signs in). */
export function flowFamily(flow: FlowId): FlowFamily | undefined {
  return FAMILY[flow];
}

/** What a Result stores of an attempt's gestures. */
export interface GestureFields {
  /** Deliberate gestures of the attempt the verdict stands on (biometric approvals apart). */
  gestures: number;
  /** Their kinds, in order, the biometric approvals included. */
  gestureList: GestureKind[];
  /** Unlock approvals by the Touch ID stand-in. */
  biometric: number;
  /** The oracle saw the scenario's session on the site (only for the flows whose goal is a session). */
  signedIn?: boolean;
  /** The headline: signed in, and exactly one deliberate gesture. */
  oneGesture?: boolean;
  startState: StartState;
  trigger?: Trigger;
}

/**
 * The gesture fields of a result. `signedIn` is the oracle's reading of the
 * server events (undefined where the flow has no session to see, or the
 * scenario no goal); `oneGesture` is then signedIn with exactly one
 * deliberate gesture: the user's own press on the site's submit button, a
 * picker choice or an unlock button each make it two.
 */
export function gestureFields(list: readonly Gesture[], signedIn: boolean | undefined, startState: StartState,
  trigger: Trigger | undefined): GestureFields {
  const gestures = gestureCount(list);
  return {
    gestures, gestureList: gestureKinds(list), biometric: biometricCount(list),
    ...(signedIn !== undefined ? { signedIn, oneGesture: signedIn && gestures === 1 } : {}),
    startState, ...(trigger !== undefined ? { trigger } : {}),
  };
}
