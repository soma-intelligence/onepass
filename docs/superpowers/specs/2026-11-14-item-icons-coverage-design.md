# Item icons: fewer monograms, a bigger pack, a gap list and an icon library

Date: 2026-11-14. Status: design agreed with the owner in chat, not built.

## Goal

The owner finds too many monogram tiles in the item list. Most logins should show their brand's
logo, the tiles that remain should look designed, and the owner should be able to pick an icon
for any item from a library.

Four parts, all agreed (owner, 2026-11-14, "A + B + C + D"):

- B. Show the small site icons the app already fetches, and redraw the monogram tile.
- D. An icon library in the editor's icon menu: pack logos, house icons, an image.
- C. A Debug-only list of the domains that still end on a monogram.
- A. A bigger icon pack, built ahead of time from a list of popular domains.

Delivery order: B, D, C, A. B shows at once, A is the longest and is fed by C.

Success: on the owner's iPhone, the share of logins drawn as a monogram drops visibly after B,
and again after A; any item can carry a chosen icon that shows on every device.

## What exists (read 2026-11-14)

- Resolver order (`VaultKit/Support/ItemIconResolver.swift`): chosen icon (never set), pack by
  host, pack by title, the site's own icon, then nothing (monogram or category artwork).
- The site's own icon is kept only when its source is at least `2 * minSitePixels` = 128 px on
  its longest side (`sharpEnough`). Most sites serve 32 or 64 px favicons, so they are dropped and
  the item falls to a monogram. This is the main cause of the monograms.
- `ItemIcon` (DesignKit) already has a branch for a small favicon (`isLowResolution`): drawn bare
  at one point per source pixel, at most 85% of the square. The 128 px gate means it is
  almost never reached for site icons.
- Pack `apple/IconPack/onepass-icons.bin`, version 2026110401: 4,212 icons, 5,024 domains, 4,112
  brand names, 255 monochrome, 256 px lossless WebP, about 11 MB. Built by `scripts/icon_pack.py`
  from Simple Icons, gilbarbara/logos, 2FA Directory and the curated list, whose `site` entries
  are fetched at build time (`fetch_sites`: manifest, apple-touch-icon, favicon, Google's copy).
- Weekly signed pack updates need `IconPackStore.publicKey`, which is not set: only the pack
  shipped in the app is used.
- `Item.custom_icon: Option<AttachmentRef>` exists in the core, is kept by duplicates merge and
  re-import, cleared by Send, and is not exposed through the FFI.
- The item editor redesign (`2026-11-13-item-editor-cards-design.md`, being built on main by
  another session) adds an icon menu on the editor header: site icon, category icon, badge color
  (`FfiItem.color`, drawn behind the category glyph or a login's title letter). That spec says
  "No custom image" (owner, 2026-11-13).

## Owner rulings this spec relies on

1. All four parts, in the order B, D, C, A (2026-11-14).
2. The library includes an "Image" source (photo or file). This reverses the 2026-11-13 ruling
   "No custom image" for the icon menu. To confirm with the owner when D starts.
3. Android and the browser extension are out of scope; they read the same `custom_icon` later.

## B. Fewer monograms, better monograms

Changes, Apple only:

1. `ItemIconResolver.sharpEnough`: keep a site icon whose source is at least 32 px on its longest
   side (was 128). Rename the constant to `minSitePixels = 32` and drop the `2 *`. A 32 to 127 px
   icon goes through `ItemIcon`'s existing small-favicon branch: bare, never stretched.
2. Below 32 px, or no icon at all: the monogram tile, redrawn.
   - Tile color: when the item has a badge color (`FfiItem.color`, from the editor spec), that
     color. Otherwise a color picked from a fixed palette of 12 by a stable hash (FNV-1a) of the
     item's registrable domain, or of its title when it has no website. Same domain, same color,
     on every device.
   - Letter: first letter of the title; when the title is empty, first letter of the registrable
     domain. SF Pro Rounded semibold, centered on its optical box (cap height), white on the tile
     with contrast checked against the palette (each palette color passes 3:1 for white text).
3. The 12 colors live in DesignKit next to the account colors, light and dark values.

Coordination: the editor-cards session is changing `ItemIcon.swift` (tint and monogram). B's
monogram work starts after that wave is committed and reuses its `monogram` and `tint` code
rather than adding a second path.

Tests (DesignKitTests, VaultKitTests): the 32 px gate (31 px refused, 32 px kept, 128 px kept),
the hash gives the same color for the same domain and spreads over the palette for a fixed list of
100 domains, empty title falls back to the domain letter, palette contrast. Screenshots of the
list in light and dark, before and after, on the iPhone.

## D. Icon library in the editor

Built on the editor spec's icon menu, after that wave lands. The menu gains one entry,
"Choisir une icône…", which opens a sheet with three tabs:

1. Logos: search the installed pack by brand name or domain (the pack's `names` and `domains`
   index), grid of results, a tap picks the icon. New `IconPack` API:
   `search(_ query: String, limit: Int) -> [IconPack.Entry]` (name, domain, icon number),
   prefix match first, then substring, lowercase and accent-free like `squash`.
2. Icônes: about 40 house icons for things that have no brand (banque, boutique, mail, routeur,
   wifi, école, santé, pharmacie, assurance, impôts, mairie, travail, jeu, musique, vidéo, cloud,
   serveur, base de données, clé, maison, voiture, voyage, sport, crypto...). Each is an SF Symbol
   on a tile from the B palette; the owner picks symbol and tile color in the sheet. Rendered to
   a 256 px PNG when chosen.
3. Image: a photo (PhotosPicker on iOS, file picker on the Mac), cropped to a centered square,
   scaled to 256 px, encoded PNG.

Storage: the chosen icon is stored as bytes in `Item.custom_icon` (at most 64 KB after encoding;
larger is refused with a message). Storing bytes, not a pack reference, keeps the icon the same on
every device whatever pack version it holds.

Core and FFI:

- Expose `custom_icon` on `FfiItem` as `custom_icon_id: Option<String>` (`#[uniffi(default = None)]`).
- `set_custom_icon(vault_id, item_id, bytes: Vec<u8>, mime: String) -> FfiItem` and
  `clear_custom_icon(vault_id, item_id) -> FfiItem`, built on the attachment store; the old icon's
  blob is removed when replaced or cleared. MIME limited to `image/png` and `image/webp`, size
  checked in the core too.
- `custom_icon_data(vault_id, item_id) -> Vec<u8>`.
- Send keeps clearing it (unchanged). Export and import: carried like an attachment.

Apple:

- `ItemIconResolver` gets the chosen bytes from a small cache keyed by item id and icon id
  (loaded once per item, invalidated when the id changes) and passes them as `chosen`, so the list,
  the item page, AutoFill and the Watch all show it.
- The icon menu shows "Réinitialiser l'icône" when a custom icon is set; it clears it.
- A custom icon takes priority over the menu's "Icône de la catégorie" choice.

Tests: core unit tests (set, replace removes old blob, clear, size and MIME refused, merge and
re-import keep it, Send clears it), FFI round trip, `IconPack.search` ranking, resolver uses
`chosen` first, editor UI test picks a pack logo and sees it in the list.

## C. Gap list (Debug only)

- A screen under Réglages > Debug (Debug builds only, like the rPPG capture rule): "Icônes
  manquantes". It walks the unlocked vaults and lists the registrable domains of logins whose
  resolved icon is nothing (monogram), with the item count per domain, sorted by count.
- A Copy button puts the list on the clipboard as plain text, one domain per line. Nothing is
  sent anywhere; the owner pastes it to whoever updates the pack.
- The owner's list feeds `scripts/icon-pack-curated.json` (new entries with source `site` or a
  set icon), then a pack rebuild.

Tests: the walker on a fixture vault returns the expected domains and counts and skips items with
a pack, site or chosen icon.

## A. Bigger pack, built ahead of time

- `icon_pack.py sites` gains `--domains FILE`: a plain list of domains beyond the curated list.
  Each goes through the existing `fetch_sites` path (build time only, never from the app). An icon
  is kept only from 128 px source and when it passes the existing checks (not near empty, safe SVG).
- Domain list: the top 20,000 registrable domains of a public popularity ranking (Tranco, list id
  and date recorded in the manifest) plus a hand list of French services (banques, énergie,
  opérateurs, administrations, transports), plus the domains C reports. Adult, gambling and
  malware categories are dropped by a blocklist kept next to the curated list.
- Size: icons from this source are stored at 128 px; the current 4,212 stay at 256 px. The index
  already carries `size` per pack, so format 1 needs a per-icon size: add flag bit 2 "128 px"
  (format stays 1; an older reader would draw it at 256 px, which only blurs it). Target under
  40 MB (limit 64 MB). The app grows by about 25 MB; to confirm with the owner when A starts.
- Licensing: these icons are the sites' own, like the existing `site` entries; same NOTICE text,
  same removal path (exclusion in `icon_pack.py`).
- The new pack reaches users only with an app version (no signing key set). Setting
  `IconPackStore.publicKey` for weekly updates is a separate owner decision, not in this spec.

Tests: `tests/test_icon_pack.py` for `--domains` (fixture HTTP server), the 128 px flag, the
blocklist, and that the pack parses in VaultKit with mixed sizes.

## Out of scope

- Android, the browser extension, the Watch editor.
- Generating icons with an image model.
- Turning on signed weekly pack updates.
