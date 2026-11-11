# One-gesture login

Date: 2026-11-10. Status: built on main, reviewed, not yet run on real devices.

## Goal

From any sign-in surface, one deliberate gesture ends with the user signed in. When the vault is
locked, the floor is that gesture plus one biometric approval. Nothing here fills or submits
without a trusted gesture, and the master password is still required after a reboot, every 14
days and on a biometry change.

## Where it stood

An audit of the extension, the Apple AutoFill provider, the lock state machine, the fill engine
and the lab found that one click worked only on the Mac, vault unlocked, on a site already used.

| Surface | State | Gestures before |
|---|---|---|
| Mac extension | locked | click, click "Unlock in OnePass", Touch ID |
| Mac extension | app not running | dead end |
| Mac extension | in-field icon path | 42 of 74 login flows in one click (overlay: 72 of 74) |
| iPhone QuickType | every page | tap, Face ID, then the site's own button |
| iPhone native app, no associated domain | every time | search, pick, never remembered |

The lab always started unlocked and warm, with one account per site, and did not count the
user's own press on the site's submit button.

## Owner rulings (2026-11-10)

These reverse or amend earlier rulings. Each was accepted with its cost stated.

1. AutoFill provider unlock reuse (reverses X2, "fresh session per request"). After a biometric
   unlock in the provider, the session is kept in memory for 90 seconds, for the same site
   (registrable domain) or app and the same account. Passwords and one-time codes are then
   answered without interface. Never for passkeys, `reprompt` items, a master-password unlock,
   shared mode, or when Apple Watch unlock is enabled. A setting, on by default, turns it off.
2. `reprompt` item on a locked vault: the biometric that unlocks for a browser click also counts
   as the item's presence check. One credit, 10 seconds, one use, bound to the requesting browser
   and site.
3. Associated domains from Apple's shared-credentials list, as a tier below `Domain`. First use
   on the other domain is a pick from the menu or popup, never an automatic fill or submit.
4. Several accounts, first visit: a sole exact-host match is filled and submitted, only when that
   item lives in a vault that is not shared.
5. Closing the Mac window no longer locks (unless auto-lock is "Immediately"). Idle delay, sleep,
   screen lock, fast user switching and quit still lock, and lock every account.
6. Added accounts are reachable from the Mac browser bridge (reverses P7), each behind its own
   "Available in browsers" switch, off by default.

Android, Windows, Linux and borrowed computers are out of scope here and get their own specs.

## Design

### Unlock carries the fill (extension, Mac app)

- A trusted click or command that meets `locked` or `host_missing` asks for `open_app` and
  `unlock` at once. The menu, the sign-in card and the chain wait, then resume by themselves.
- The resume is bound to tab, frame, document id, origin and a single-use token, 90 seconds on
  every side. The pending record is mirrored in `storage.session` (no secret) so a worker restart
  does not lose it. A redrawn copy of the same form is accepted; the plan is recomputed.
- `unlock` carries the top-frame origin. The app names that site in the Touch ID prompt and binds
  the `reprompt` credit to it. An older app answers `invalid`; the extension retries once without.
- Unlock requests are capped at 3 per minute per tab, active tab of a focused window only.
- A locked arrival shows a generic card with no vault data. Its click is the gesture.

### One decision path (core, extension)

- One URL matcher in `fill_plan::origin`, used by the bridge, the AutoFill FFI and the MCP.
  Ports and exact URLs are respected everywhere. Loopback http is accepted on `localhost`,
  `127.0.0.1` and `[::1]` only, with ports compared.
- The in-field icon, the shortcut and the overlay start the same chain. The planner no longer
  submits by itself.
- A child frame whose origin equals the top origin is decided like the top frame. Every other
  child frame stays held.
- The bridge enforces the associated-domain rule itself: an unpromoted match is served only for a
  pick; promotion is per exact host and needs a served fill in the session.
- Chain limits: two password-bearing fills, then `repeat`. A captcha stops the chain only when a
  challenge is shown, and a captcha stop after a submit sets the penalty.

### Apple AutoFill

- The identity store carries "behind" marks per account. The provider publishes and waits (2 s at
  most) when behind; a sync applied while locked sets the mark.
- The unlock window ends on any OnePass lock (a per-account stamp in the app group) and on a
  device lock (a Darwin notify counter read on use; registration failure means no window).
- Onboarding asks the system to enable the provider. Picking an item for an app with no
  associated domain offers "Always use for this app", showing the App ID.

### Idle and lock (Mac)

- A secret served to the browser restarts that account's idle delay through a bridge callback,
  capped at 12 hours after the last unlock or the last time the app was in front.

## Evidence

Lab run `extension/lab/out/pass5-2026-11-11-evidence`: 20 sites, 293 scenarios, three start
states (unlocked, locked with deferred unlock, host stopped).

| Start | Pass | Fail | Flaky |
|---|---|---|---|
| Unlocked | 106 | 3 | 0 |
| Locked | 90 | 3 | 0 |
| Host stopped | 90 | 3 | 0 |

Login flows signed in: 90 of 90. In one gesture: 67 of 90. Password, one-time code, SSO and
multi-step are at 100 % in every start state. The 9 failures are one site, a tall identity form
under the "fill visible fields only" rule, not a login. No leak, no wrong item, no submit outside
login.

The lab now counts every gesture, including the site's own submit, and has start states and
account profiles p0 to p3.

## Known limits

- The provider cannot see or submit the page: native apps keep "fill, then the app's button".
- Whether iOS keeps the provider process alive between two requests decides if the 90 second
  window ever applies. Only a device shows it.
- The device-lock signal uses an undocumented system notification name, kept in one constant.
- The site named in the Touch ID prompt is what the paired extension reports.
- More than one gesture remains for: signup (by design), a password followed by a passkey in an
  iframe, a passkey-only page from the card on an open vault, two accounts with no site memory.
- The bridge has no context value for "automatic fill from a plan"; the extension sends `chain`.
- Not verified: Firefox and Safari in a real browser, iOS, real sites; SSO popup following,
  associated domains and the captcha rule have unit tests only.

## To measure on a device

- Peak memory of the AutoFill extension during a master-password unlock (Argon2id) against the
  jetsam limit.
- `bootMatch == .unknown` inside the extension sandbox.
- Touch ID rising by itself on a cold launch, and focus going back to the browser.
