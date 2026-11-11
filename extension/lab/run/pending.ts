// Stand-in for the drivers of task 12b (`ghost` and `saveTyped` of drive.ts) until the UI they drive exists:
// the scenario is `skipped` with the cause below, out of every rate, so the lab still runs. 12b deletes this
// file and points the two cases of lab.spec.ts at the real drivers.
import type { DriverId } from "../gen/model.ts";
import type { Observation } from "./oracle.ts";

export const DRIVER_PENDING_12B = "driver_pending_12b";

export function pendingDriver12b(driver: DriverId): Observation {
  return { driver, overlayShown: false, itemOffered: false, events: [], filled: {}, durationMs: 0, skipped: DRIVER_PENDING_12B };
}
