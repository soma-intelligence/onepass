# Fill anywhere on the Mac

Date: 2026-11-23. Status: built on branch feat/fill-anywhere, hand checks pending.

## Goal

On the Mac, OnePass fills a login in any app, not only in browsers that carry the extension:
native apps with custom fields, Electron and Java apps, in-app web views, browsers without the
extension, remote desktop clients and virtual machines. One deliberate gesture picks the account;
the fill follows.

## Where it stands

| Surface | Today |
|---|---|
| Safari, Chrome, Firefox and others with the extension | covered by the bridge (`bridge.sock`) |
| Native Mac apps with standard `NSSecureTextField` | system AutoFill shows the OnePass provider |
| Electron, Java, custom fields, web views | nothing |
| Browsers without the extension | nothing |
| Remote desktop, VM, screen sharing | nothing |

The Mac app is sandboxed, so it cannot read other apps' fields or post keystrokes to them.

## Owner rulings (2026-11-23)

1. Order: the Mac first (this spec), then a USB keyboard key for machines where nothing can be
   installed (own spec), then Android (own spec).
2. Trigger: a global shortcut and a pill that appears by itself next to every password field, in
   every app.
3. Confirmation: the same as the browser. Touch ID only when the vault is locked or the item asks
   for `reprompt`. The account choice is always an explicit gesture; nothing fills silently.

## Out of scope

- The USB keyboard key, Android, Windows and Linux.
- The App Store build. The helper ships only in the personal build and in the Developer ID build;
  the App Store build keeps system AutoFill only.
- Submitting the form. The user presses the app's own button, as in the browser.

## Design

### Approach

A separate helper, `OnePass Fill.app`, ships inside `OnePass.app/Contents/Library/LoginItems/`.
It is not sandboxed and is registered as a login item with `SMAppService.loginItem`. It is a
client of the existing bridge, like the browsers: it connects to `bridge.sock` in the App Group
container, the Rust `BridgeServer` checks its code signature (same team, its own bundle ID), and
every request goes through the same policy (`onepass_bridge::policy`) and audit. The helper keeps
no secret and no vault cache: it receives one value at the moment of a fill and drops it right
after (`Zeroizing` on the Rust side, overwritten buffer on the Swift side).

Rejected:

- Removing the sandbox from the main app: exposes the whole app and cannot apply to the App Store
  build.
- AppleScript through System Events: slow, fragile, blocked by many apps.

### Units

Each unit has one job and can be tested alone.

| Unit | Job | Depends on |
|---|---|---|
| `FocusWatcher` | Follows the focused element of the frontmost app through `AXObserver` (`kAXFocusedUIElementChangedNotification`). Emits a `FieldContext` when the focused element is a password field, or a text field right above one. | Accessibility |
| `FieldClassifier` | Decides whether an element is a password, username or one-time code field: `AXSecureTextField` role, subrole, placeholder, title, label of the element above, `AXDOMIdentifier` and `AXDOMClassList` in web views. Pure function over a snapshot of attributes. | none |
| `TargetResolver` | Turns a `FieldContext` into a match target: page URL when the app exposes `AXURL` or `AXDocument` (web areas), else the app's bundle ID, else nothing (free search). | none |
| `Pill` | A small borderless `NSPanel` glued to the field's frame (`AXFrame`), follows moves and scrolls, hides when the field loses focus. A click opens the picker. | `FocusWatcher` |
| `Picker` | The account list, opened by the pill or the shortcut. Same rows and order as the extension's popup (`plan_candidates`). Search field. "Remember for this app" is on by default. | bridge |
| `Filler` | Fills one value with the first strategy that works (see below) and checks the target before each step. | Accessibility, `CGEvent` |
| `BridgeClient` | Pairing, session and the encrypted channel, reused from the browser relay through `onepass-ffi`. New request context `Ctx::Desktop`. | `onepass-bridge` |
| `HotKey` | Global shortcut, default ⌥⌘\\, through `RegisterEventHotKey` (no Input Monitoring needed). | Carbon |

### Matching

1. URL from the accessibility tree, matched exactly like a browser page (`item_match`).
2. Else the bundle ID, matched against app entries on the item.
3. Else free search, with the window title as the first query.

An app entry is an `ItemUrl` with `url = "macapp://<bundle-id>"` and `rule = ExactHost`. This uses
the existing model, so older apps sync it without a schema change; they show it as a URL they
cannot open. App entries are matched in `core/onepass-core/src/fill_plan/app_entry.rs`, not by
teaching `origin.rs` a new scheme. The first account picked for an app is saved this way when
"Remember for this app" is on; the entry is visible and editable in the item.

A URL target is filled through the bridge's `fill_login` in the desktop context, with the same
origin check and Touch ID as the browser. Free search uses the bridge `search`, which returns
logins only.

Known apps that are browsers without the extension (Arc, Orion, Tor Browser, DuckDuckGo) are
matched by URL first. When the URL cannot be read, the picker says so and searches by window title.

### Fill strategies

In this order, per field:

1. **Accessibility set**: `AXUIElementSetAttributeValue(kAXValueAttribute)`, then read back the
   value length (a secure field gives its length, not its value) to confirm.
2. **Typing**: `CGEvent` key events posted to the target process (`CGEvent.postToPid`), one
   character at a time with the right keyboard layout (`UCKeyTranslate`), Unicode string events
   for characters the layout cannot type. This path works in remote desktop clients, virtual
   machines and Java apps. A short delay between keys (8 ms default) for clients that drop fast
   input.
3. **Clipboard**: the value goes on the pasteboard marked `org.nspasteboard.ConcealedType` and
   `TransientType`, cleared after 30 s or at the first paste, whichever comes first. The pill
   says "Copied, paste with ⌘V".

The flow for a login: username, Tab (or focus the password field when it is known), password,
then the one-time code when the next field asks for one (the current code only, never the TOTP
secret, as in `policy`).

### Focus guard

Before each strategy step and before each key event batch, `Filler` checks that the frontmost
app's PID and the focused element are still the ones the user picked for. If either changed, the
fill stops at once, nothing more is typed, and the pill shows "Fill stopped: window changed".
Typing never starts while a secure input session belongs to another process
(`IsSecureEventInputEnabled` with a different owner), since keystrokes would go nowhere.

### Security

- Confirmation as in the browser: Touch ID when the vault is locked or the item asks for
  `reprompt`; the account pick is always explicit.
- The helper asks for a value only after the pick, and only the field it is filling.
- Excluded apps: a list in Settings where the pill never shows (default: Terminal, iTerm, OnePass
  itself). The shortcut still works there.
- Every fill is written to the existing key usage log (`key_use.rs`) with the app name, bundle ID
  and the strategy used.
- A lock in the app locks the helper (it is a bridge client, so this is already true).
- The helper's own window is excluded from screen capture (`NSWindow.sharingType = .none`).

### Permissions and first run

- Accessibility is required. A setup screen in Settings explains why, opens the right pane of
  System Settings and detects the grant (`AXIsProcessTrusted`), then turns the helper on.
- Input Monitoring is not needed: the shortcut uses `RegisterEventHotKey` and posting events
  needs only Accessibility.
- Settings: pill on or off, shortcut on or off and its keys, excluded apps, typing delay.

### Errors

| Case | What the user sees |
|---|---|
| Accessibility not granted | Pill never shows; shortcut opens the setup screen |
| App not running or bridge down | Picker says "Open OnePass" with a button that opens it |
| No match | Picker opens on search |
| All strategies failed | "Could not fill this field" with Copy as the last resort |
| Focus changed during a fill | Fill stops, message as above |

## Testing

- Unit tests: `FieldClassifier` on recorded attribute snapshots, `TargetResolver`, matching of
  `macapp` entries in `fill_plan/app_entry.rs` and `policy`, the flow builder, the focus guard against a fake
  clock and fake focus.
- A local test app (`apple/FillLab`) with hostile fields: a custom-drawn field that refuses
  `kAXValueAttribute`, a fake password field (plain text field labelled "Password"), a field that
  clears itself on set, a web view login page.
- UI test: the helper fills each FillLab field and the right strategy is logged.
- By hand before calling it done: Slack, Discord, a Java app, a macOS VM in UTM, Microsoft Remote
  Desktop, Arc without the extension.

## Known limits

- Apps that draw their own text without an accessibility tree (some games, some Qt builds) give no
  field to detect: the pill cannot show, the shortcut still opens the picker and typing still works
  once the user clicks in the field.
- A remote desktop window exposes no inner field: the pill shows on the window only when the user
  presses the shortcut, and matching falls back to search.

## Evidence

FillLab (`apple/FillLab`, Debug only) has six sections, each with a stable accessibility
identifier:

| Section | Field | Expected |
|---|---|---|
| 1 | Standard `NSSecureTextField` | `accessibility` |
| 2 | Custom `NSView` that refuses a `kAXValueAttribute` set but takes typed keys | `typing` |
| 3 | Plain `NSTextField` titled "Password hint", no label | not a password: no pill, nothing offered |
| 4 | Plain `NSTextField` whose accessibility label is exactly "Password" | a password, `accessibility` |
| 5 | `WKWebView` login page from the bundled `login.html` | `accessibility` |
| 6 | Secure field that clears itself on set | falls back to `typing` |

The UI test `FillAnywhereUITests.testFillsEveryLabField` (target `OnePassMacUITests`) drives the
helper against these fields and reads the strategy from the helper's Debug test log
(`-OnePassFillTestLog <path>`). It skips when the helper has no Accessibility grant or when the
bridge refuses it (`appClosed`). Both are the case for an ad hoc Debug build, so the test needs a
signed build with the grant.

Every check below needs Accessibility and a signed build. None has run yet.

| Check | Status |
|---|---|
| `FillAnywhereUITests` passes on a signed build with the grant | not run |
| Slack | not run |
| Discord | not run |
| A Java app | not run |
| A macOS VM in UTM | not run |
| Microsoft Remote Desktop | not run |
| Arc without the extension | not run |
| In a remote desktop client and a UTM VM, a password with capitals and symbols such as `@`, `#` and `{` types correctly (Shift and Option key events) | not run |
| A character the layout cannot type (an emoji, or `é` on a US layout) arrives correctly in a native app and in a remote desktop client (Unicode events on virtual key 0) | not run |
| Username with a known password field: the focus moves to the password by Accessibility, with no Tab | not run |
| Username with no known password field, where Tab lands on a control that is not a password: the fill stops and the picker offers Copy | not run |
| ⌥⌘\ on a remote desktop or VM canvas: the picker opens at the screen centre, typing reaches the canvas, no Accessibility set is tried | not run |
| A fill on a `reprompt` item, with a switch to another window of the same app while Touch ID shows: the fill stops with "Fill stopped: window changed" | not run |
| The Mac UI test `SettingsUITests.testFillAnywherePageShowsAccessibilityStep` runs green | not run |
| Turning the helper on registers the login item | not run |
| Turning it off unregisters the login item and ends the helper | not run |
| `.requiresApproval` shows the approval row and keeps the helper on | not run |
| `fill.trusted` and the settings are shared between the app and the helper | not run |
| The first signed build registers the App ID `<prefix>.fill` with the App Group | not run |
