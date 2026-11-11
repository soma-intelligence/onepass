// Start states of a scenario (model.ts StartState), set up on one lab profile:
// - unlocked_warm: nothing is touched (the historical start);
// - cold: the native host is stopped when the user arrives on the page, and
//   again right before her gesture if anything started it since (the page
//   load, the extension reconnecting by itself), so the gesture meets a host
//   that was stopped a moment before;
// - locked: the host is restarted locked (config `unlocked: false`) and its
//   session opened again without unlocking, so the user arrives on a locked
//   vault with a running host. The unlock is approved by the lab's stand-in
//   for Touch ID: through the approval file when the host can defer an unlock
//   ("deferred", host-control.ts), else by the host itself at once
//   ("instant"); either way each approval is one biometric in the result.
// A state the host cannot be put in gives a skip cause ("host lacks control
// ..."), never a played scenario. Pure sequencing over `StartHost`, which the
// lab profile implements (and a fake in the unit tests).
import type { StartState } from "../gen/model.ts";
import { lacks } from "./host-control.ts";

/** What the start states ask of one lab profile's host. */
export interface StartHost {
  /** Whether a host process of this profile runs; undefined when processes cannot be listed. */
  running(): boolean | undefined;
  /** Stops the host; false when it could not. */
  stop(): Promise<boolean>;
  /** The next host process starts locked (or unlocked), with a deferred unlock when asked. */
  configure(opts: { locked: boolean; deferred: boolean }): void;
  /** The vault's lock state through the extension; opens the session, never unlocks. Undefined: no answer. */
  status(): Promise<{ locked: boolean } | undefined>;
  /** Whether the host can defer an unlock to an approval file. */
  deferredUnlock: boolean;
  /** Starts and stops the stand-in on the approval file (deferred hosts); stop gives its approvals. */
  standIn: { start(): void; stop(): number };
}

/** What a driver asks before and after its gesture. */
export interface StartControl {
  /** When the user arrives (before the page opens). A string is the reason the state cannot be set up. */
  arrive(start: StartState): Promise<string | undefined>;
  /** Right before the user's gesture. A string is the reason the state no longer holds and cannot be restored. */
  beforeGesture(start: StartState): Promise<string | undefined>;
  /** After the scenario: the unlock approvals the stand-in gave, and how. */
  finish(start: StartState): Promise<{ approvals: number; unlock?: "instant" | "deferred" }>;
  /** Back to an unlocked, running host (before a priming sign-in in a locked or cold batch). False when it could not. */
  reset(): Promise<boolean>;
}

export function startControl(host: StartHost): StartControl {
  /** Checked once per profile: the host process can be seen while it runs. */
  let seen: boolean | undefined;
  const visible = async (): Promise<boolean> => {
    if (seen !== undefined) return seen;
    // The session must be open for a process to exist.
    await host.status();
    seen = host.running() === true;
    return seen;
  };
  // Stopped means the processes that ran are gone. The extension may start a new one by itself
  // right after (a request it retries): that is its doing, and beforeGesture stops that one too.
  const stop = async (): Promise<string | undefined> => {
    if (!(await visible())) return lacks("stop", "no host process of this profile can be listed");
    if (!(await host.stop())) return lacks("stop", "the host process did not stop");
    return undefined;
  };
  return {
    async arrive(start) {
      if (start === "unlocked_warm") return undefined;
      if (start === "cold") {
        host.configure({ locked: false, deferred: false });
        return stop();
      }
      host.configure({ locked: true, deferred: host.deferredUnlock });
      const failed = await stop();
      if (failed !== undefined) return failed;
      // The session again, on a host that starts locked.
      const s = await host.status();
      if (s === undefined) return lacks("stop", "the host did not start again after its stop");
      if (!s.locked) return lacks("stop", "the host did not start locked");
      if (host.deferredUnlock) host.standIn.start();
      return undefined;
    },
    async beforeGesture(start) {
      if (start !== "cold" || host.running() === false) return undefined;
      // Something started the host again: the gesture must still meet a stopped one.
      return stop();
    },
    async reset() {
      host.configure({ locked: false, deferred: false });
      const s = await host.status();
      if (s !== undefined && !s.locked) return true;
      // Locked by an earlier scenario: a new process reads the unlocked config.
      if (!(await host.stop())) return false;
      const again = await host.status();
      return again !== undefined && !again.locked;
    },
    async finish(start) {
      if (start !== "locked") return { approvals: 0 };
      if (host.deferredUnlock) return { approvals: host.standIn.stop(), unlock: "deferred" };
      // The host approved by itself: an open vault now is one approval.
      const s = await host.status();
      return { approvals: s !== undefined && !s.locked ? 1 : 0, unlock: "instant" };
    },
  };
}
