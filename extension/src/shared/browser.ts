// The only module allowed to touch the `chrome` / `browser` globals.
// Safari and Firefox expose `browser`; Chromium exposes `chrome`.
const g = globalThis as unknown as { browser?: typeof chrome; chrome?: typeof chrome };

export const ext: typeof chrome = (g.browser ?? g.chrome) as typeof chrome;
