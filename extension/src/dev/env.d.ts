/** Set by build.mjs (ONEPASS_LAB_RECORDER=1) and by vitest. false in every release build. */
declare const __LAB_RECORDER__: boolean;
/** Set by build.mjs from ONEPASS_CLASSIFIER (default "heuristic") and by vitest. */
declare const __CLASSIFIER__: "heuristic" | "gbm" | "encoder";
/** true in `node build.mjs --dev` builds only (dev-only logging). */
declare const __DEV__: boolean;
