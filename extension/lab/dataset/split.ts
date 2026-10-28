// Train / validation / test split of the field dataset. Decided per origin, never
// per row or per site, so every row of one real host (and every synthetic site
// derived from it) lands in the same part and nothing leaks across the split.
import { cyrb128 } from "../gen/rng.ts";

export type Split = "train" | "val" | "test";

/** 80 / 10 / 10 by the hash of the origin and the seed (second word of cyrb128: the first is the weakest on sequential names). A pure function: no clock, no randomness. */
export function splitOf(origin: string, seed: string): Split {
  const u = cyrb128(origin + seed)[1] / 4294967296;
  return u < 0.8 ? "train" : u < 0.9 ? "val" : "test";
}
