// The one deadline of an unlock asked from the browser (menu, overlay, chain), shared by the
// pages that wait and the service worker that resumes.

/**
 * After a trusted gesture asked the app to unlock (Touch ID on its lock screen, a launch first
 * when it was not running): how long the pages wait, and how long the worker may still resume
 * the fill or the sign-in that asked. The Mac app keeps its own request as long.
 */
export const UNLOCK_WAIT_MS = 90_000;
