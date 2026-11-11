# Fill UI, inline password suggestion and save on first sign-in

Date: 2026-11-11. Status: design approved in conversation, not built.

Sub-project 1 of 5 from the owner's request "improve the design, add SSO, one-click sign-in,
first-pass save and new password suggestion inline". The others, in order: 2 complete SSO,
3 one-click sign-in everywhere (lab failures, real sites, Safari and Firefox), 4 extension
popup redesign, 5 iOS and Mac apps (design pass, system AutoFill save and suggestion). Each gets
its own spec.

## Goal

On any site, in the browser extension:

- a new-password field shows a strong password right in the field, accepted with one key or one
  click, and the site sees nothing until the user accepts;
- a first sign-in with credentials OnePass does not hold ends with the login saved, with no
  question to answer;
- a password change on a known account asks once and never vanishes unanswered;
- every fill surface (field glyph, menu, one-click card, save card, toast) draws from one set of
  tokens, in light and dark.

## Where it stood (audit 2026-11-11)

- Suggestion: only a menu row "Generate a password" (`ui/menu.ts:592-608`, label
  `shared/l10n/en.json:66`), no preview, no strength. The menu opens on a mouse click into an
  empty field only, never on focus or Tab, never on touch (`content/index.ts:695-707`).
- Save: card "Save login for {site}?" after a detected success (`background/chain/save-flow.ts`),
  closes itself after `AUTO_DISMISS_MS = 20_000` (`ui/save.ts:53`). Gaps: a submission with no
  identifier is dropped unless the password was generated; a generated password on a
  change-password form is only remembered, not saved; a sign-in that keeps its form on screen
  never counts as a success. The lab has no save scenario.
- Design: `--space-*` tokens defined (`ui/theme.css:45-51`) and used 0 times, 15 font sizes,
  radii 12, 16, 17 and 18 px mixed, field glyph and frame colours hard-coded in
  `content/frames.ts:48-96` and blind to the page theme, a solid indigo tile in every field,
  `passkey.html` carries its own `<style>`, dead copy keys `save.saveLogin`, `save.newItem`,
  `save.update1`.

## Owner rulings (2026-11-11)

Taken one by one on mockups in the brainstorm companion.

- R1. Suggestion = ghost text in the field (mockup C), with the preview menu (mockup B) one key
  or one click away. The ghost falls back to that menu when it cannot sit in the field.
- R2. Field glyph = grey Lattice glyph at rest, indigo in the focused field (mockup A). No solid
  tile, no talking capsule.
- R3. New login = saved automatically on a detected success, toast with Undo and Edit
  (mockup C). Changed password on an existing login = compact card that folds into a pill
  (mockup A). This reverses the founder rule of 2026-11-04 ("every time": each new credential
  gets a card) for new logins only.
- R4. Ghost text is drawn in an extension iframe laid over the field (approach 1). Not in the
  page's shadow root, never through the field's `placeholder`.

## 1. Design foundation

- `ui/theme.css` is the only source of spacing, radius, type and colour for the menu, the
  one-click card, the save card, the passkey page, the ghost frame and the toast.
- Spacing: `--space-xxs` to `--space-xxl` (2, 4, 8, 12, 16, 24, 32 px). The common 10 px gaps
  become 8 or 12.
- Type scale, five steps: `--type-caption` 11 px, `--type-footnote` 12 px, `--type-body` 13 px,
  `--type-headline` 15 px, `--type-title` 17 px. The 11.5, 12.5 and 13.5 px sizes go.
- Radius: `--r-chip` 8, `--r-control` 12, `--r-card` 18, `--r-sheet` 26. The 16 px frame corner
  and the 17 px overlay buttons move to the scale (card and control).
- Glyph and frame colours leave `content/frames.ts` for tokens with a light and a dark value
  (`--glyph-rest`, `--glyph-focus`, `--glyph-focus-bg`, `--frame-shadow`). The content script
  cannot read the extension stylesheet, so `frames.ts` imports the same values from one
  generated module (`shared/design-tokens.ts`, written from `theme.css` by `scripts/gen-design-tokens.mjs`; `shared/tokens.ts` already exists for random tokens) rather than
  repeating hex.
- `passkey.html` drops its inline `<style>` for `theme.css`.
- Dead keys `save.saveLogin`, `save.newItem`, `save.update1` are deleted from every locale.
- Guard test: no `px` literal outside the token scale and no hex colour in `ui/*.ts`,
  `ui/*.html` and `content/frames.ts`; `theme.css` and `shared/design-tokens.ts` are the only
  files allowed to hold them.

## 2. Field glyph

- The Lattice mark (2 x 3 dots and one bar) drawn in `--glyph-rest` (neutral grey), no tile.
- In the focused field: `--glyph-focus` (indigo) on a 12 % accent background, radius
  `--r-chip`.
- Theme: the glyph picks light or dark tokens from the luminance of the field's computed
  background, so a dark field on a light page still gets a visible glyph; `prefers-color-scheme`
  only when the background is transparent all the way up.
- Hit area stays 22 x 22 px. What a click does is unchanged (the one chain of the one-gesture
  login spec).
- Field kinds that get a glyph are unchanged.

## 3. Ghost text for a new password

### 3.1 When

- A trusted focus (click, Tab, or tap on touch screens) into an empty field that the detector
  classes as a new password, on a signup or change-password form.
- Not when the vault holds a login for this site and the form is a sign-in form (that is the
  menu's job).
- Once dismissed on a field (typing, Escape), it does not come back on that field until the page
  navigates or the field is replaced.

### 3.2 What

- New frame kind `ghost` in `FrameKind` (`shared/messages.ts:407`), page `ui/ghost.html`, an
  extension iframe inside the existing closed shadow root (`content/frames.ts`), laid over the
  field's text box.
- It shows the password from `generate.ts` (site rules, narrower retry when refused) in
  `--text3` grey, with the field's computed font size, line height, left padding and
  `text-align`. Font family: the field's own when it is a local font, else the system font. A
  different face is acceptable for a grey preview.
- At the field's right edge, inside the frame, a pill "Use" with a "Tab" keycap and a chevron.
- The frame lets pointer events through except on the pill, so a click in the field still
  places the caret.

### 3.3 Keys and clicks

- Tab, Enter, or a click on the pill: accept. The fill runs as today (password and confirmation
  fields, pending save of the generated password, spec 8.8 of save-flow).
- Any printable key: the ghost goes, the key reaches the field as typed.
- Escape: the ghost goes.
- Arrow Down or a click on the chevron: the ghost goes and the menu opens on its suggestion row,
  redesigned as the preview of mockup B: the password in `--mono` with digits in `--digit` and
  symbols in `--symbol`, a four-segment strength bar, "Strong, 16 characters, site rules
  respected", a "Use" button, then "Other suggestion" and "Length and characters".
- "Length and characters" opens a panel inside the menu: a length stepper within
  `CUSTOM_MIN_LENGTH` and `CUSTOM_MAX_LENGTH` (`shared/ui.ts`) and a "Symbols" switch. A change
  writes the custom generator profile the popup edits (`GENERATOR_PROFILE_KEY` in
  `storage.local`, `{ kind: "custom", length, symbols }`) and redraws the preview at once.
- Tab acceptance only while the ghost is shown; without a ghost Tab moves focus as usual.

### 3.4 Fallback to the menu

The menu with its preview row opens instead of the ghost when any of these holds:

- the field is under 120 px wide;
- the field or an ancestor has a CSS transform other than translation, or a non-zero
  `text-indent`;
- the field is partly covered (the existing occlusion check, `content/occlusion.ts`);
- the field is in a cross-origin child frame;
- the narrow touch layout (bottom sheet, `SHEET_MAX_VIEWPORT`) is active.

### 3.5 Security

- The password exists only in the extension iframe and the worker until accepted (rule S1 of
  `content/frames.ts`). The page sees neither the ghost nor the pill text.
- The ghost needs a trusted focus. A focus moved by page script (`isTrusted === false`, or a
  focus with no user gesture in the last second) gets nothing.
- Acceptance keys are read by the content script only while the ghost frame is shown, from
  trusted keyboard events on the anchored field.
- The pill obeys the existing clickjacking guard of frames (occlusion and the one-gesture
  transform guard).

## 4. Save after sign-in

### 4.1 New login: automatic

- A detected success (current rule of `save-flow.ts`: the password form is gone from the next
  page or the same document for `SETTLE_MS`) with credentials the vault does not hold
  (`check_credentials` answers `new`) saves the login at once: site, identifier, password, in
  the default vault for the site.
- Same for a second account on a known site.
- A toast in the top frame, 8 s: "Login for github.com saved", with Undo and Edit. It stays
  while hovered or focused.
- Undo deletes the new item for good (not to the trash: it existed for seconds) through a new
  bridge op `undo_save { item_id, origin }`. The bridge accepts it only for an item it saved
  itself through `save_login` in the last 60 s, for the same registrable domain, and not edited
  since; anything else is `not_found`. The extension then marks that site, identifier and
  password as refused for the session, so the same submission gets nothing again.
- Edit opens the save card in edit mode: name, identifier, vault, "Never on this site".

### 4.2 Changed password: card

- `check_credentials` answers `update`: compact card "Update password for github.com?", the
  identifier, the password masked, "Later" and "Update". Update moves the old password to the
  item's history (existing behaviour).
- After `AUTO_DISMISS_MS` (20 s) the card folds into a pill in the same corner, "1 login to
  update". A click reopens the card. The pill goes when the tab leaves the site's registrable
  domain or after 10 min.
- "Later" folds the card into the pill at once.

### 4.3 Guards: card instead of automatic

The card (in its "new" form, "Save login for github.com?", "Later" and "Save") replaces the
automatic save when:

- the vault is locked (Save unlocks first, as today);
- the window is private (`tab.incognito`, Safari private window);
- the success is uncertain (section 5.3);
- the target vault for the site is a shared vault;
- the submission had no identifier (section 5.1).

Nothing at all (no save, no card) on a site in "Never on this site". (A public-computer
delegated session is a separate client that never runs the extension's save flow.)

To tell a shared vault, the bridge's `vaults` answer gains `shared: true` on shared vaults
(`VaultEntry`, omitted when false).

### 4.4 Unchanged

- A generated password is still saved pending before the form is sent (`onepass:pending`) and
  confirmed on submission. After the success the toast says "saved", with Edit only.
- Cards and identities typed by hand keep their card (MS-04 rules).
- The extension never saves from a fill it did itself with a held login.

## 5. Save gaps closed

### 5.1 Submission without an identifier

When no identifier step was sent before in this tab and site: the card shows an empty
identifier field to fill, the Save button enabled once it is not empty. Never automatic.

### 5.2 Generated password on a change-password form

The generated password is written at once to the existing login as a pending update
(`update_password`, old password to history, tag `onepass:pending`), not only kept in memory.
The form's submission confirms it. If the user has several logins on the site and none was
filled in this tab, the card asks which one, still with the password already safe in a pending
item.

### 5.3 Success while the form stays on screen

A single-page app that keeps a password form after sign-in counts as an uncertain success when,
within 1.5 s of the submission: the URL changed (path or hash), the password field was emptied
or removed from the form, and no `role="alert"` or `aria-invalid="true"` appeared in the form.
Uncertain success gives the card (4.3), never an automatic save.

Also uncertain: a success by navigation (the next page of the site has no password form) where
that page shows a `role="alert"` element within 1.5 s of its load (an error or captcha page).

## 6. Out of scope

- Apple system AutoFill save and suggestion (iOS 26.2+, already wired): sub-project 5.
- SSO capture and display: sub-project 2.
- Extension toolbar popup: sub-project 4.
- Firefox and real-site runs: sub-project 3 (this work keeps the lab green and adds scenarios).

## 7. Tests and evidence

### 7.1 Unit (extension, vitest)

- Ghost placement from computed styles, each fallback of 3.4, each key of 3.3, untrusted focus
  ignored.
- Save: each guard of 4.3, automatic save on `new`, card on `update`, Undo deletes and refuses,
  pill fold and expiry, sections 5.1, 5.2, 5.3.
- Token guard test of section 1.

### 7.2 Lab (extension/lab)

New scenario family, each in unlocked, locked and cold start:

- `save_new_auto`, `save_second_account`, `save_update_card`, `save_no_username`,
  `save_spa_stays`, `save_failed_login`, `save_private_window`;
- `ghost_accept_tab`, `ghost_accept_click`, `ghost_ignore_typing`, `ghost_menu_arrow`,
  `ghost_fallback_narrow`, `ghost_fallback_transform`.

Required:

- zero generated password in the page DOM before acceptance (lab leak probe on every ghost
  scenario);
- zero automatic save on a failed sign-in;
- no regression on the 293 scenarios of pass5-2026-11-11.

### 7.3 Screenshots

`extension/e2e/save-shots.spec.ts` extended: glyph at rest and focused, ghost with pill, preview
menu, toast, update card, pill, each in light and dark, on a light and a dark test page.

## 8. Files

- New: `extension/src/ui/ghost.html`, `extension/src/ui/ghost.ts`,
  `extension/src/shared/design-tokens.ts` (generated), `extension/scripts/gen-design-tokens.mjs`, `extension/src/ui/toast` part of `save.ts` or a
  new `toast.ts` page if `save.ts` would pass 900 lines.
- Changed: `ui/theme.css`, `ui/menu.ts`, `ui/save.ts`, `ui/overlay.ts`, `ui/passkey.html`,
  `content/frames.ts`, `content/icon.ts`, `content/index.ts`, `shared/messages.ts`,
  `background/chain/save-flow.ts`, `background/save.ts`, `background/generate.ts`,
  `shared/l10n/*.json`, `e2e/save-shots.spec.ts`, lab scenario files.
- Core (`core/onepass-bridge`): new op `undo_save`, `VaultEntry.shared`. Nothing else;
  `check_credentials`, `save_login` and `update_password` already exist.
