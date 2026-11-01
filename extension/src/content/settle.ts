// Bounded wait for the page to change (spec 2026-10-31, section 3.3): a
// state list the shop reloads after the country, a combobox's options that
// render after a keystroke. `attempt` runs at once, then after each batch of
// mutations under `root` (or any of several roots: a shadow root and the
// document its combobox portals its list into; grouped, one try per GROUP_MS at most), until it
// returns true or `ms` have passed; its argument is true for the last try
// only. Never longer: the observer is always disconnected.

const GROUP_MS = 25;

export function settle(root: Node | readonly Node[], attempt: (final: boolean) => boolean, ms: number): Promise<boolean> {
  if (attempt(false)) return Promise.resolve(true);
  if (typeof MutationObserver !== "function" || ms <= 0) return Promise.resolve(false);
  return new Promise((resolve) => {
    let done = false;
    let queued: ReturnType<typeof setTimeout> | undefined;
    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      observer.disconnect();
      clearTimeout(deadline);
      if (queued !== undefined) clearTimeout(queued);
      resolve(ok);
    };
    const observer = new MutationObserver(() => {
      if (done || queued !== undefined) return;
      queued = setTimeout(() => {
        queued = undefined;
        if (done) return;
        let ok = false;
        try {
          ok = attempt(false);
        } catch {
          ok = false;
        }
        if (ok) finish(true);
      }, GROUP_MS);
    });
    for (const r of Array.isArray(root) ? root : [root]) observer.observe(r, { childList: true, subtree: true, attributes: true, characterData: true });
    const deadline = setTimeout(() => {
      // One last look: the change may have landed within the group delay.
      let ok = false;
      try {
        ok = !done && attempt(true);
      } catch {
        ok = false;
      }
      finish(ok);
    }, ms);
  });
}
