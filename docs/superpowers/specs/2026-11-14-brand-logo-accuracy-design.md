# Brand logo accuracy: the right logo, automatically

Date: 2026-11-14. Status: agreed with the owner in chat ("fais le mieux, le plus optimal"), not built.
Extends `2026-11-14-item-icons-coverage-design.md`; replaces its part A domain list build (task 13 of
that plan) as the way to grow the pack.

## Goal

The owner's real need, stated after the first spec: every login shows its brand's right, current logo
(bare marks are fine), and derived sites never show someone else's logo. Example: signing in to Bay Club
Connect shows a logo that is not Bay Club's, because Bay Club is not in the pack and the portal serves
its hosting platform's favicon.

Success:

- Bay Club Connect shows the Bay Club logo.
- A portal hosted on a platform (gym software, Salesforce sites, Okta, Shopify, Wix...) never shows the
  platform's icon as the brand's.
- The pack covers far more brands with vector logos, refreshed by the weekly build.
- Nothing in the app asks a third party which sites the person uses (unchanged rule).

## Three mechanisms

### 1. Wikidata + Wikimedia Commons as a build source

- `icon_pack.py wikidata` queries the Wikidata SPARQL endpoint (build time only) for items with an
  official website (P856) and a logo image (P154), paged so no query times out. Output: domain to
  Commons file name, item id, label.
- For each file, the Commons API gives the file URL, SHA-1 and license (`extmetadata.LicenseShortName`).
  Kept: public domain (PD, PD-textlogo, PD-ineligible, PD-shape and similar) and CC0 only. A logo under
  CC BY, CC BY-SA or anything else is dropped (no per-icon attribution: same rule as today).
- SVG goes through the existing safety checks and rendering; raster files through the existing raster path.
- Priority in the build: curated list, then Wikidata/Commons, then the existing sets (logos, 2FA
  Directory, Simple Icons), then fetched site icons. A Wikidata logo that is a wide wordmark (aspect over
  2.6) is dropped unless curated, as today.
- The item label goes into `names` (squashed), so title lookup finds the brand.
- `report.json` records counts per license and drops per reason. The manifest records the query date.

### 2. Platform icon rejection

- Build: compute a 64-bit difference hash (dHash: 9x8 grayscale, alpha composited on white) of every
  fetched site icon. A hash shared by 3 or more unrelated registrable domains (different brands) is a
  platform icon. Also hash the icons of a curated list of platform domains
  (`scripts/icon-pack-platforms.txt`: daxko.com, clubautomation.com, force.com, salesforce.com, okta.com,
  shopify.com, wix.com, squarespace.com, wordpress.com, zendesk.com, ...).
- Pack index gains optional `rejects`: list of dHashes as 16-digit lowercase hex. Format byte stays 1;
  an older reader ignores the key.
- App: `SiteIconLoader` computes the same dHash on a fetched icon; within Hamming distance 6 of any
  reject, the icon is refused and the next candidate is tried; if all are refused the site has no icon.
  Python and Swift share test vectors so both compute the same hash.

### 3. Parent brand from the site itself

- When the pack has no icon for the host, `SiteIconLoader` already reads the home page for icon links.
  From the same page (no extra request) it also reads the site name: `og:site_name`, then
  `application-name`, then the manifest `name` / `short_name`, then `<title>` up to the first separator
  (` | `, ` - `, ` : `).
- The name is squashed and looked up in the pack's `names`. Exact match, or the name minus a trailing
  generic word (connect, portal, online, app, login, account, members, my, client, mobile) matching
  exactly, gives that brand's pack icon. "Bay Club Connect" gives "bayclub".
- If no name matches: the registrable domains the page links to (`<a href>`, canonical, `og:url`), most
  frequent first, at most 5, excluding social networks, CDNs, app stores and analytics hosts (fixed list),
  are looked up in the pack's `domains`. A match is used only when the site's own icon is missing or was
  rejected by mechanism 2.
- The result is remembered per host like site icons (an alias host to pack icon number, in the same
  cache, refreshed on the same schedule).
- Order in `ItemIconResolver` becomes: chosen, pack by host, pack by title, parent brand by site name,
  site icon (not rejected), parent brand by linked domain, monogram.

## Supporting pieces

- Bay Club enters the curated list with its domains (bayclubs.com, bayclubconnect.com and any others
  the build finds) and the best source available.
- Debug page "Icônes à vérifier" (replaces the gap list of the first spec's part C): every login with
  the source of its icon (choisie, pack, marque mère, site, monogramme), filters by source, copy as
  text. The owner flags wrong ones; each becomes a curated entry.
- The 32 px site icon gate of the first spec stays: mechanisms 2 and 3 remove the wrong-logo risk it
  raised.
- Signed weekly pack updates stay off until the owner creates the signing key; the weekly CI build still
  refreshes the pack shipped with each app version.

## Owner steps

- Approve the first real network build (Wikidata query, Commons downloads, platform icon fetches)
  before it runs, with its expected size.
- Optional: create the Ed25519 key so the weekly pack reaches installed apps.

## Out of scope

Logo APIs (Brandfetch, logo.dev, Clearbit) at run time or build time, generated logos, Android,
the browser extension.
