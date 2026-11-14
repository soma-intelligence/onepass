# Item editor in cards: reorderable websites and free sections, icon menu, OTP scan

Date: 2026-11-13. Status: design agreed section by section with the owner, not built.

## Goal

The edit screen of an item, on the Mac and on the iPhone, takes the structure of a card editor:
a header with the item's icon and its title, one main card without a section label, a websites
card, one card per free section, an "add more" card, then the notes. Rows are removed with the red
(−) button, cards and rows that may move carry a ☰ handle, each card adds its own rows at its
foot. The look stays OnePass: DesignKit tokens, the existing editor primitives, black or
secondary SF Symbols, no glow.

Success: on a login with a username, a password, a sign-in provider, a TOTP, a website and an
imported section, the owner can rename and move the imported section, move the websites card,
reorder the websites and the free fields, remove the provider without losing the username, scan
a TOTP QR code on the iPhone (camera) and on the Mac (image), pick the icon, save, and find the
item exactly as edited on the other device. Existing tests stay green.

## Where it stood (exploration 2026-11-13)

- One editor for the 26 types on both platforms: `apple/App/Item/ItemEditorView.swift` (956
  lines), state in `ItemEditorModel.swift`, draft rules in
  `apple/VaultKit/Sources/VaultKit/Editing/ItemDraft.swift`.
- Already there: icon and big title field, cards (`EditorCard`, `CardDivider`, `EditorLabel`),
  (−) buttons (`RemoveRowButton`), "+" rows (`AddRowButton`), websites with a match rule menu
  (`UrlListEditor`), the "ajouter plus" popover (`AddFieldPopover`), notes, places, tags, options.
- A section label shows on every card as soon as an item has two sections, so a login with an
  imported section reads "Login" then "Imported".
- A sign-in provider replaces the username row (`LoginUsernameRow` in
  `FieldEditors/ItemLinkPicker.swift`).
- The TOTP row shows the live code and its ring while editing.
- The first three fields of the first section always show, so an empty email row sits in the
  login card.
- Only the `custom` section's fields are removable (`ItemDraft.isRemovable`); an importer's
  `imported` section is neither renamable nor removable.
- Nothing can be reordered.
- `FfiItem.color: Option<String>` exists and is unused by the apps. The core also has
  `Item.custom_icon` (an image), not exposed through the FFI.
- The QR scanner exists on the iPhone only (`App/Onboarding/SecretKeyScanner.swift`, VisionKit).
- `onepass_ffi::template(item_type)` gives the template sections of a type.

## Owner decisions (2026-11-13)

1. Handles: websites reorder among themselves, free fields reorder within their section, and
   the websites card and the free section cards reorder among themselves. Template fields and
   template sections do not move.
2. The icon's chevron opens a menu: site icon (favicon), category icon, and a badge color. No
   custom image.
3. Username and "sign in with" are two separate rows.
4. The one-time password row shows the masked secret with a QR scan button, on the iPhone
   (camera) and on the Mac (image).
5. A free section is its own card with an editable name, a (−) for the whole section and
   "+ ajouter un champ" at its foot.
6. Built as separate card views (approach 1), not by growing `ItemEditorView`.

## Terms

- Template section: a section whose id is in `template(item.itemType)`.
- Free section: any other section (`custom`, `imported`, and sections added in the editor).
- Main card: the item's first template section.
- Free field: a field of a free section.

## Layout, top to bottom

1. Header (`EditorHeader`). The item's icon at 64 pt with a small chevron badge at its bottom
   right; a tap opens the icon menu (below). The title field as today. On the Mac the small
   uppercase "MODIFICATION" line goes: the window title already says it.
2. Main card (`MainCard`), no section label, fixed (no handle). For a login, in this order:
   username, password, sign in with, one-time password, passkeys, then "+ ajouter une passkey".
   A row shows when it is required, filled at opening, added during this edit, or has a
   validation error. Username and password always show on a login. An emptied row stays until
   the editor closes. Other types keep the current rule minus the "first three fields" one:
   required, filled, added, or in error.
3. Other template sections, each in a card with its label, fixed, as today.
4. Movable cards, in the item's order: the websites card (`WebsitesCard`) and one card per free
   section (`FreeSectionCard`). Each has a ☰ handle outside the card on its leading side.
5. "+ ajouter plus" in a card of its own (`AddMoreCard`), the current popover, which also offers
   "Se connecter avec" (when no provider is set), "Code à usage unique" (when the main card has
   no TOTP row shown) and "Nouvelle section".
6. Notes, then places, tags, the vault and options card and the travel card, unchanged.

### Rows

- Sign in with: label "se connecter avec", the provider's logo, name and account e-mail
  (`SignInAccountLine`), a chevron that opens the current menu (change account), and a (−) that
  calls `setSignInProvider(nil, accountItemID: nil)`. The username row stays as typed. The core
  already waives the username requirement when a provider is set; the "*" follows that.
- One-time password: label, masked secret with the eye (`SecretFieldEditor`), a QR scan button
  (`OtpScanButton`), and a (−) that empties the field and hides the row. No live code, no ring:
  they stay on the item's page.
- Website: as today (field, match rule menu, (−)), plus a row handle when there are two
  websites or more. "+ ajouter un autre site" at the foot.
- Free section header: the section name as a text field styled as a card title, and a (−).
  Removing a section with at least one filled field asks "Supprimer la section ?" first. An
  empty name gets the default "Nouvelle section" back at save.
- Free field: label field, value editor and (−) as today for custom fields, plus a row handle
  when the section has two fields or more. "+ ajouter un champ" at the card's foot opens the
  custom kinds grid of the popover and adds the field to this section.

## Icon menu

- "Icône du site": the favicon of the primary website (current behavior). Default.
- "Icône de la catégorie": the item type's artwork (`ItemIcon` without a site icon).
- "Couleur": a row of the existing account colors plus "Aucune"; stored in `FfiItem.color` by
  its name, drawn as the tile's background behind the category glyph and as a thin ring around a
  favicon.
- Storage of the icon choice: a reserved tag `onepass:icon-category`, built like
  `onepass:travel-hidden`: never listed in `tags`, exposed as `FfiItem.icon_category: bool` with
  `#[uniffi(default = false)]`. An older client sees a plain tag and keeps it, so nothing is lost
  through sync. The list, the item page, AutoFill and the Watch read the same choice through
  `ItemIcon`.

## Data operations

In `ItemDraft` (VaultKit), each with a unit test, then wrapped by `ItemEditorModel` which keeps
the stable row keys (`fieldKeys`, `urlKeys`) in step:

- `moveURL(from:to:)`: order of `item.urls`; the primary flag stays on its website.
- `moveField(sectionID:from:to:)`: free sections only; refused elsewhere.
- `moveSection(from:to:)` over the movable slots: the free sections keep their relative order in
  `item.sections`, after every template section. The websites card's slot is a display
  preference stored per device in `UserDefaults` (`onepass.editor.websitesSlot`, an index among
  the movable cards), so the item's data never carries layout. The item page follows the same
  order.
- `addSection(label:)`: a free section with id `section_<n>` (never reused within the item, like
  `custom_<n>`) and label "Nouvelle section".
- `renameSection(id:label:)`, `removeSection(id:)`: free sections only.
- `isRemovable` grows to every free field; `addCustomField` takes an optional section id.
- `preparedForSave` keeps the order, restores blank section labels, and drops a section left
  with no field.

The core already keeps `sections` and `urls` in the order given; a Rust test pins that a save
then a read returns the same order.

## OTP scan

`OtpScanButton` (in `App/Item/Editor/`):

- iPhone: the VisionKit data scanner of `SecretKeyScanner`, filtered to QR codes, in a sheet.
- Mac: a small sheet that takes a pasted image, a dropped image or a chosen file, decodes it
  with Vision (`VNDetectBarcodesRequest`, QR only). A screen scan comes later with the two-factor
  setup work.
- The payload goes through the existing `otpauth://` parsing (`OtpLinkAccount`). A Google
  Authenticator export with one account is accepted; with several, the row says to use "Ajouter
  un code" instead. Any other content shows "Ce QR code ne contient pas de code à usage unique."
  under the row. Nothing is sent over the network, nothing is kept after the sheet closes.
- On success the secret replaces the field's value (the replaced seed goes to the item's history
  as the core does since `ad96d2237`).

## Reordering

`ReorderHandle` and a `ReorderableStack` container (in `App/Item/Editor/`): the ☰ handle starts
a vertical `DragGesture`; the stack reads its children's frames through a `PreferenceKey`,
computes the target slot from the drag's location, shows the moving card lifted (offset only,
no shadow glow) and the others sliding, and commits the move on release. Animation uses
`FoldMotion`, none when Reduce Motion is on. Each handle has VoiceOver actions "Monter" and
"Descendre" and an accessibility label naming what it moves. On the Mac the pointer becomes the
open hand over the handle. One code path for both platforms.

## Files

New, under `apple/App/Item/Editor/`: `EditorHeader.swift`, `IconMenu.swift`, `MainCard.swift`,
`SignInRow.swift`, `OtpRow.swift`, `OtpScanButton.swift`, `WebsitesCard.swift` (from
`UrlListEditor`), `FreeSectionCard.swift`, `AddMoreCard.swift` (with `AddFieldPopover`),
`ReorderableStack.swift`.

Changed: `ItemEditorView.swift` (orchestration only, under 400 lines), `ItemEditorModel.swift`,
`ItemDraft.swift`, `LoginUsernameRow` (provider no longer replaces the username), `ItemIcon`
(color and category choice), `Localizable.xcstrings` (new keys inserted in place, en, es, fr,
it), `project.yml` if the new folder needs listing. Core: `model/item.rs` (reserved tag
helpers), `onepass-ffi/src/types.rs` and `convert.rs` (`icon_category`), with tests.

## Testing

- Rust: the reserved tag round trip and its absence from `tags`; section and URL order kept
  through save and read. `make -C apple core-test`, then `make -C apple core`.
- VaultKit unit tests for every operation above, stable keys included.
- Existing UI tests keep their identifiers (`editor.*`). New identifiers: `editor.icon`,
  `editor.icon.category`, `editor.signIn.remove`, `editor.otp.scan`, `editor.section.<id>`,
  `editor.section.<id>.name`, `editor.section.<id>.remove`, `editor.section.<id>.addField`,
  `editor.reorder.<slot>`.
- Screenshots on a QA bundle id with fictitious data, Mac and iPhone, light and dark. Never the
  owner's vault.

## Out of scope

- A custom image icon (`custom_icon`).
- Moving template fields or template sections.
- A screen scan for QR codes on the Mac.
- The item page's own layout, beyond following the card order.
