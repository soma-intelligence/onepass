// @vitest-environment node
// Start states of the lab (locked vault, stopped host): the sequencing over a
// fake host, the skip causes when a control is missing, and the Touch ID
// stand-in on the approval file of a host that defers its unlock.
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { approvePendingUnlock, hostSupports, lacks, patchHostConfig, pidsIn, UNLOCK_APPROVED, UNLOCK_PENDING, unlockDelayMs, UnlockStandIn } from "../../lab/run/host-control.ts";
import { type StartHost, startControl } from "../../lab/run/start-state.ts";

interface Fake extends StartHost { log: string[]; up: boolean; locked: boolean; startsLocked: boolean; visible: boolean; stoppable: boolean; approvals: number }

/** A host that restarts on a status request, locked or not as last configured. */
function fake(over: Partial<Fake> = {}): Fake {
  const h: Fake = {
    log: [], up: true, locked: false, startsLocked: false, visible: true, stoppable: true, approvals: 0, deferredUnlock: false,
    running() {
      return h.visible ? h.up : undefined;
    },
    async stop() {
      h.log.push("stop");
      if (h.stoppable) h.up = false;
      return h.stoppable;
    },
    configure(o) {
      h.log.push(`configure locked=${o.locked} deferred=${o.deferred}`);
      h.startsLocked = o.locked;
    },
    async status() {
      h.log.push("status");
      if (!h.up) {
        h.up = true;
        h.locked = h.startsLocked;
      }
      return { locked: h.locked };
    },
    standIn: {
      start: () => void h.log.push("standin start"),
      stop: () => {
        h.log.push("standin stop");
        return h.approvals;
      },
    },
    ...over,
  };
  return h;
}

describe("start states", () => {
  it("unlocked_warm_touches_nothing", async () => {
    const h = fake();
    const c = startControl(h);
    expect(await c.arrive("unlocked_warm")).toBeUndefined();
    expect(await c.beforeGesture("unlocked_warm")).toBeUndefined();
    expect(await c.finish("unlocked_warm")).toEqual({ approvals: 0 });
    expect(h.log).toEqual([]);
  });

  it("cold_stops_the_host_on_arrival_and_again_before_the_gesture", async () => {
    const h = fake();
    const c = startControl(h);
    expect(await c.arrive("cold")).toBeUndefined();
    expect(h.up).toBe(false);
    // The page load started it again.
    h.up = true;
    expect(await c.beforeGesture("cold")).toBeUndefined();
    expect(h.up).toBe(false);
    expect(h.log.filter((l) => l === "stop")).toHaveLength(2);
    // Already stopped: nothing more to do.
    expect(await c.beforeGesture("cold")).toBeUndefined();
    expect(h.log.filter((l) => l === "stop")).toHaveLength(2);
    expect(await c.finish("cold")).toEqual({ approvals: 0 });
  });

  it("locked_restarts_the_host_locked_and_warm", async () => {
    const h = fake();
    const c = startControl(h);
    expect(await c.arrive("locked")).toBeUndefined();
    expect(h.up).toBe(true);
    expect(h.locked).toBe(true);
    expect(h.log).toContain("configure locked=true deferred=false");
    expect(await c.beforeGesture("locked")).toBeUndefined();
    // Nothing unlocked: no approval.
    expect(await c.finish("locked")).toEqual({ approvals: 0, unlock: "instant" });
    // The host approved an unlock by itself: one biometric.
    h.locked = false;
    expect(await c.finish("locked")).toEqual({ approvals: 1, unlock: "instant" });
  });

  it("a_deferring_host_is_approved_by_the_stand_in", async () => {
    const h = fake({ deferredUnlock: true, approvals: 1 });
    const c = startControl(h);
    expect(await c.arrive("locked")).toBeUndefined();
    expect(h.log).toContain("configure locked=true deferred=true");
    expect(h.log.at(-1)).toBe("standin start");
    expect(await c.finish("locked")).toEqual({ approvals: 1, unlock: "deferred" });
  });

  it("reset_brings_back_an_unlocked_running_host", async () => {
    const h = fake();
    const c = startControl(h);
    await c.arrive("locked");
    expect(h.locked).toBe(true);
    expect(await c.reset()).toBe(true);
    expect(h.up && !h.locked).toBe(true);
    // From a stopped host too (after a cold scenario).
    await c.arrive("cold");
    expect(await c.reset()).toBe(true);
    expect(h.up && !h.locked).toBe(true);
    expect(await startControl(fake({ locked: true, stoppable: false })).reset()).toBe(false);
  });

  it("a_host_the_extension_restarts_by_itself_is_still_stopped_before_the_gesture", async () => {
    const h = fake();
    const c = startControl(h);
    const stop = h.stop.bind(h);
    // The extension reconnects right after each stop.
    h.stop = async () => {
      const ok = await stop();
      h.up = true;
      return ok;
    };
    expect(await c.arrive("cold")).toBeUndefined();
    expect(await c.beforeGesture("cold")).toBeUndefined();
    expect(h.log.filter((l) => l === "stop")).toHaveLength(2);
  });

  it("a_missing_control_is_a_skip_cause", async () => {
    expect(await startControl(fake({ visible: false })).arrive("cold")).toBe(lacks("stop", "no host process of this profile can be listed"));
    expect(await startControl(fake({ stoppable: false })).arrive("locked")).toBe(lacks("stop", "the host process did not stop"));
    const stuck = fake();
    stuck.configure = () => undefined; // a host that ignores the locked start
    expect(await startControl(stuck).arrive("locked")).toBe("host lacks control stop (the host did not start locked)");
  });
});

describe("host control", () => {
  const dirs: string[] = [];
  const temp = () => {
    const d = mkdtempSync(join(tmpdir(), "onepass-lab-test-"));
    dirs.push(d);
    return d;
  };
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("finds_the_host_by_its_own_config_path", () => {
    const ps = ["  101 /tmp/a/onepass-native-host --config /tmp/a/native-host.json chrome-extension://x/", "  102 /tmp/b/onepass-native-host --config /tmp/b/native-host.json chrome-extension://x/",
      "  103 /Applications/Chromium --load-extension=/x", ""].join("\n");
    expect(pidsIn(ps, "--config /tmp/a/native-host.json")).toEqual([101]);
    expect(pidsIn(ps, "--config /tmp/c/native-host.json")).toEqual([]);
  });

  it("patches_the_config_keys_it_is_given_only", () => {
    const file = join(temp(), "native-host.json");
    writeFileSync(file, JSON.stringify({ data_dir: "/d", approval: "auto", unlocked: true }));
    patchHostConfig(file, { unlocked: false, unlock: "file" });
    expect(JSON.parse(readFileSync(file, "utf8"))).toEqual({ data_dir: "/d", approval: "auto", unlocked: false, unlock: "file" });
    // An undefined value removes its key: the host refuses a key it does not know.
    patchHostConfig(file, { unlocked: true, unlock: undefined });
    expect(JSON.parse(readFileSync(file, "utf8"))).toEqual({ data_dir: "/d", approval: "auto", unlocked: true });
  });

  it("the_stand_in_approves_a_pending_unlock_once", () => {
    const dir = temp();
    expect(approvePendingUnlock(dir)).toBe(false);
    writeFileSync(join(dir, UNLOCK_PENDING), "");
    expect(approvePendingUnlock(dir)).toBe(true);
    expect(existsSync(join(dir, UNLOCK_APPROVED))).toBe(true);
    // Until the host consumed it, no second approval.
    expect(approvePendingUnlock(dir)).toBe(false);
  });

  it("the_stand_in_counts_its_approvals", async () => {
    const dir = temp();
    const s = new UnlockStandIn(dir);
    s.start(5);
    writeFileSync(join(dir, UNLOCK_PENDING), "");
    await new Promise((r) => setTimeout(r, 60));
    expect(s.stop()).toBe(1);
    expect(s.stop()).toBe(1);
  });

  it("the_stand_in_takes_its_time_like_a_finger_on_touch_id", async () => {
    const dir = temp();
    const s = new UnlockStandIn(dir, 120);
    s.start(5);
    writeFileSync(join(dir, UNLOCK_PENDING), "");
    await new Promise((r) => setTimeout(r, 50));
    // Seen, not approved yet: the request stays pending for the delay.
    expect(existsSync(join(dir, UNLOCK_APPROVED))).toBe(false);
    await new Promise((r) => setTimeout(r, 150));
    expect(existsSync(join(dir, UNLOCK_APPROVED))).toBe(true);
    expect(s.stop()).toBe(1);
    expect(unlockDelayMs({})).toBe(800);
    expect(unlockDelayMs({ LAB_UNLOCK_DELAY_MS: "0" })).toBe(0);
    expect(unlockDelayMs({ LAB_UNLOCK_DELAY_MS: "2500" })).toBe(2500);
    expect(() => unlockDelayMs({ LAB_UNLOCK_DELAY_MS: "soon" })).toThrow();
  });

  it("an_approved_unlock_holds_for_every_host_process_of_the_profile_until_the_scenario_ends", async () => {
    // The profile has two host processes (the main session, the agent channel's own): the one that
    // asks first takes the approval files away. The vault is one: the other must open as well.
    const dir = temp();
    const s = new UnlockStandIn(dir);
    s.start(5);
    // Nothing is approved before a host asked.
    await new Promise((r) => setTimeout(r, 30));
    expect(existsSync(join(dir, UNLOCK_APPROVED))).toBe(false);
    writeFileSync(join(dir, UNLOCK_PENDING), "");
    await new Promise((r) => setTimeout(r, 40));
    expect(existsSync(join(dir, UNLOCK_APPROVED))).toBe(true);
    // A host process took the approval (it removes both files, as the host does).
    rmSync(join(dir, UNLOCK_PENDING));
    rmSync(join(dir, UNLOCK_APPROVED));
    await new Promise((r) => setTimeout(r, 40));
    expect(existsSync(join(dir, UNLOCK_PENDING)) && existsSync(join(dir, UNLOCK_APPROVED))).toBe(true);
    // One approval all the same, and nothing left behind for the next scenario.
    expect(s.stop()).toBe(1);
    expect(existsSync(join(dir, UNLOCK_PENDING)) || existsSync(join(dir, UNLOCK_APPROVED))).toBe(false);
    // A new scenario starts from nothing: a stale file of an earlier one approves nothing.
    writeFileSync(join(dir, UNLOCK_APPROVED), "");
    s.start(5);
    await new Promise((r) => setTimeout(r, 30));
    expect(existsSync(join(dir, UNLOCK_APPROVED))).toBe(false);
    expect(s.stop()).toBe(0);
  });

  it("a_binary_that_cannot_run_supports_nothing", () => {
    expect(hostSupports(join(temp(), "no-such-host"), "unlock", "file")).toBe(false);
  });
});
