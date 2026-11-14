# Two-factor and passkey setup: QR capture, prompts and guided journey

Date: 2026-11-13. Status: design agreed section by section with the owner, not built.

## Goal

From a login that has no second factor, one click on "Enable" ends with two-factor
authentication set up on the site and its secret saved on the item. The same for passkeys.

Three linked features:

1. In the browser extension, a button that finds the TOTP setup QR code on the current page,
   decodes it locally, saves the secret on the matching login and fills the first code.
2. In the apps, a prompt "Enable two-factor authentication" on every login whose site offers it
   and whose item holds no TOTP. One click opens the site, signs in if needed, lands on the
   site's settings page and drives the site's own buttons up to the QR code.
3. The same prompt and journey for passkeys.

Success is one loop: item without 2FA, click "Enable", the browser opens the site, signs in,
reaches the settings, the QR appears, OnePass reads it, saves it, fills the code, and the owner
presses the site's last "Verify" button.

## Where it stood (exploration 2026-11-13)

- Core parses `otpauth://` (`core/onepass-core/src/totp.rs:195`, TOTP only, SHA1/256/512, 6 to 8
  digits, Steam). A login holds one usable TOTP (`model/templates.rs:242`); two non-empty Otp
  fields are "ambiguous" and the bridge then reports `has_totp = false`.
- A replaced seed is kept as `previous_otp_<n>`, but only by the Swift `attachOtp`
  (`apple/VaultKit/Sources/VaultKit/Support/OtpLink.swift:163`).
- The extension has no QR decoder, no `captureVisibleTab`, no image library. No bridge op writes
  a TOTP: `save_login` takes none, `update_password` changes the password only. The policy is
  "the current TOTP code, never the TOTP secret" (`core/onepass-bridge/src/policy.rs:5`).
- The extension fills a code through `fill_login` with `fields:["totp"]`, split cells included,
  and the sign-in chain has an `otp` step (`extension/src/background/chain/machine.ts`).
- The QR scanner in the apps is iOS only (VisionKit, `apple/App/Onboarding/SecretKeyScanner.swift`).
- Watchtower already raises `missing_2fa` (Low) and `passkey_available` (Info)
  (`core/onepass-core/src/watchtower/sites.rs:300`). The site's link is dropped at the FFI
  boundary (`core/onepass-ffi/src/watchtower.rs:83`).
- The catalogs are not bundled. The app downloads `api.2fa.directory/v4/all.json` and
  `passkeys-api.2fa.directory/v1/all.json` whole, cached 7 days, only when "Check for breaches"
  is on (`apple/VaultKit/Sources/VaultKit/Session/VaultSession+Watchtower.swift:56`). Neither
  feed is in `NOTICE`.
- "Ignore" on a finding writes `Item.watchtower_exclusions`, inside the encrypted item, synced.
- Item detail has a passkey banner that opens `https://<host>` (`ItemDetailView.swift:1445`) and
  a row that reads the site's `/.well-known/passkey-endpoints` (`AddPasskeyRow.swift:65`). There
  is no 2FA banner.
- The signed icon pack (`scripts/icon_pack.py`, `IconPack.swift:170`) is the model for a signed
  data pack. Its updates are off today (`IconPackStore.publicKey = ""`).
- Only the extension sends bridge requests. The one app-to-extension path is the `agent_wait`
  long poll, Chromium only. No job opens a URL, the extension never calls `tabs.create`, and the
  apps open sites with the system `openURL`.
- Open data: 2fa.directory (MIT, 3,371 domains) and 2factorauth/passkeys (CC-BY-4.0, 1,075
  domains) say which sites support a method and link to help articles. No source gives the
  settings pages. `/.well-known/passkey-endpoints` is live on a few sites and absent from
  Google, GitHub, Microsoft and Apple. No well-known URL exists for 2FA setup.

## Owner rulings (2026-11-13)

1. OnePass clicks the site's own buttons on the way to the QR code or the passkey prompt, from
   per-site recipes. A site without a recipe gets the guided mode: OnePass opens, signs in and
   lands on the settings, the owner clicks, OnePass takes over at the QR.
2. The last step is the owner's. OnePass saves the secret, fills the 6-digit code and never
   submits it. When the site then shows recovery codes, OnePass offers to save them on the item.
3. A QR secret is written only after a confirmation card that names the target item.
4. Site data ships as a signed pack inside the app, refreshed weekly by a whole-pack download
   from the OnePass GitHub release. The app stops calling 2fa.directory.
5. Recipes for twenty sites at first delivery: Google, GitHub, Microsoft, Amazon, Discord, Apple,
   Facebook, Instagram, X, LinkedIn, PayPal, Dropbox, Stripe, Cloudflare, AWS, Reddit, Twitch,
   Slack, Notion, OpenAI. Each gets only the methods the site offers.
6. Prompts show on the item detail and in Watchtower. No prompt in the extension popup and no
   card in the page after sign-in.
7. Every platform: Mac with Chromium browsers, Firefox and Safari, then iPhone and iPad.
8. The journey extends the extension's existing sign-in chain. The app serves recipes from the
   pack; the extension holds no pack.
9. New trusted gesture: the click on "Enable" in the unlocked app counts as the trusted gesture
   for one sign-in, in the journey's tab, on the item's own domain, for the life of the
   journey. Every other fill rule stays as it is.
10. One spec, one implementation plan per wave.

## Design

### 1. QR capture and save (extension, bridge, core)

Entry points: the button "Scan 2FA QR code" in the popup's current-site part, and the
`expect_qr` step of a journey. A page can never start a scan.

Search order:

1. In the page, top document and same-origin frames: `<img>`, `<canvas>`, inline SVG, CSS
   background images, `otpauth://` links. Candidates are visible, roughly square, at least 80 px
   wide, twelve at most. A cross-origin image or a tainted canvas cannot be read there and is
   left to step 2. The scan sends no network request.
2. Nothing decoded: one capture of the visible tab (`tabs.captureVisibleTab`), which also covers
   cross-origin images and frames and tainted canvases. The QR must be on screen.
3. Still nothing: the card offers a field to paste the setup key.

Decoding is local, by a decoder bundled in the extension and loaded on demand only, never in
the always-on content script. No network request. Only `otpauth://totp/` with a secret passes
the extension's shallow check; `otpauth-migration://` is refused here. The full parse stays in
core (`parse_otpauth`), on the app side.

Path of the secret: extension memory, encrypted bridge, app. It is never written to any
`storage` area, never logged, never sent back to the page, and dropped from memory once the
bridge answers. The extension still cannot read a stored secret.

Bridge additions (`core/onepass-bridge/src/api.rs`, `service.rs`, `policy.rs`):

- `save_totp { item_id | new login, uri, origin, replace }`. Write only. Answers `saved`,
  `same`, `exists` or `replaced`, or an error (`locked`, `origin_mismatch`, `invalid`,
  `not_allowed`, `reprompt_required`). With `replace = false` on an item that holds another
  secret it answers `exists` and writes nothing.
- `save_recovery_codes { item_id, codes, origin }`.
- `ctx = setup`, accepted by these two ops, by `list_for_origin`, by `fill_login` limited to
  the `totp` field, and by the journey ops of section 3.
- The host recomputes the origin match and takes a secret-request slot. The card's token is
  the extension's own frame token, as for the save card: bound to tab, document and origin,
  single use, kept in memory only because its record holds the secret.

Core additions:

- `attach_otp(item, uri, replace)` moves from Swift into `core/onepass-core/src/totp.rs`, so the
  bridge and the apps keep the old seed as `previous_otp_<n>` the same way.
- Recovery codes live in one concealed field `recovery_codes` on the login, one code per line.

Confirmation card (extension frame, same family as the save card):

- Shows the issuer and account read from the QR and the target item.
- Target: the item whose username equals the QR account; otherwise the item last used on this
  site; a list when several items match; "New login" when none.
- The item must match the page origin as `ExactHost` or `Domain`. An `Associated` match is
  never preselected. A look-alike domain never matches. The QR issuer is page-controlled and
  never picks the item.
- QR account different from the item's username: the card says so and the default button is
  Cancel.
- The item already holds a code. Same secret: nothing is written, go on to the fill. Different
  secret: "Replace?", default button Cancel; on replace the old seed is kept.

App side: the vault must be unlocked; a `reprompt` item asks for Touch ID through the existing
`approve_reprompt`.

After the app confirms the write, and only then, the extension fills the code with the existing
`fill_login fields:["totp"]` and does not submit. No code field found: the card shows the code
with a copy button and its countdown. Recovery codes are detected by wording and shape (a list
of six or more similar tokens near "recovery" or "backup" wording in the supported languages);
the card then offers "Save recovery codes on the item".

### 2. Site pack and recipes (scripts, core, apps)

The site pack is one signed file, with the icon pack's manifest, Ed25519 signature, size and
SHA-256 checks, rollback refusal and atomic swap. Per registrable domain: 2FA methods, passkey
level, 2FA settings URL, passkey settings URL, help URL, additional domains, recipes.

Sources:

- 2fa.directory v4 (MIT): which sites offer 2FA, help link.
- 2factorauth/passkeys (CC-BY-4.0) and Dashlane passkeys-resources (MIT): which sites offer
  passkeys.
- The in-repo map `data/site-setup/<domain>.json`, one file per site, reviewed by pull request:
  settings URLs and recipes. It is the only source of deep links.
- Never bundled: bitwarden/passkeys-index (no licence), passkeys.directory (all rights
  reserved), 2fa.directory icons (excluded from its licence).
- Attribution goes in `NOTICE` and in a "Data sources" line in the app.

Build and update: `scripts/site_pack.py` after `scripts/icon_pack.py`, a weekly GitHub workflow,
published on a `site-pack` prerelease of the OnePass repository. The app ships a copy and
downloads the whole pack at most weekly, never per site. This needs a real pinned public key;
the private key is a GitHub Actions secret the owner creates.

Core and apps:

- `core/onepass-core/src/site_pack/` parses the pack, verifies the signature and validates
  recipes. `SiteDirectory` loads from it.
- The runtime download from `api.2fa.directory` is removed from the app and from the CLI
  defaults; the CLI keeps its `--sites` and `--passkeys` file options.
- Site checks no longer depend on "Check for breaches", since nothing leaves the device.
- Domain lookup uses the public suffix list.
- `FfiWatchtowerCheck` findings carry the settings URL, the help URL and whether a recipe exists.

Recipes use a closed vocabulary: `goto`, `click`, `wait_for`, `reauth`, `expect_qr`,
`expect_passkey_prompt`, `done`. Rules, enforced at pack build, at load and at run time:

- `goto` is https only, on the site's domain or its listed additional domains (for example
  `accounts.google.com` and `myaccount.google.com`).
- `click` targets a button, link or choice by role and accessible name (patterns in several
  languages), with an optional CSS hint.
- No free text entry, no script, twelve steps at most, 60 seconds per step.
- Never a click on an element whose name means delete, disable, remove or pay.
- The final "Verify" or "Activate" click is never in a recipe. For a passkey the recipe clicks
  "Create a passkey"; the existing OnePass passkey window stays the owner's approval.
- A target that is not found drops the journey to guided mode at that step.

```json
{
  "domain": "example.com",
  "additional_domains": ["accounts.example.com"],
  "totp": {
    "url": "https://example.com/settings/security",
    "verified": { "date": "2026-11-20", "browser": "chromium" },
    "steps": [
      { "do": "goto", "url": "https://example.com/settings/security" },
      { "do": "reauth" },
      { "do": "click", "role": "button", "name": ["Enable two-factor", "Activer la double"] },
      { "do": "click", "role": "radio", "name": ["Authenticator app"] },
      { "do": "expect_qr" }
    ]
  }
}
```

Each recipe carries the date and browser of its last check, and the pack build refuses an
unchecked recipe. A recorder, present only in the development build of the extension, notes the
owner's clicks (role, name, URL, never a field value) during one run of the flow on the owner's
own account, and writes the draft recipe.

### 3. The journey (app, bridge, extension)

Start: "Enable" on the item or in Watchtower, vault unlocked, Touch ID for a `reprompt` item.
The app creates a setup intent: item, kind (TOTP or passkey), site domain, start URL, single
use. It lives in the bridge host's memory and holds no secret. One journey at a time. It ends
after 10 minutes without progress or 20 minutes in all.

Handoff to the browser:

- Chromium and Firefox: the default browser's extension receives the intent on the existing
  long poll (`agent_wait`, new job `Setup`) and opens a new tab itself. The journey is bound to
  that tab.
- Safari on Mac, iPhone and iPad: no long poll. The app opens the start URL through the system.
  When the extension's worker wakes on a navigation it asks the bridge for a pending intent
  (`setup_pending`, a request that carries no URL) and binds to the first tab that reaches the
  site's domain within 30 seconds.
- No paired extension in the default browser: the app opens the settings page and says so.
- Never in a private window.

New bridge ops, all with `ctx = setup`: `setup_pending`, `setup_plan { intent_id }` (item id,
kind, allowed domains, start URL, steps), `setup_progress { intent_id, state }`,
`setup_end { intent_id, outcome }`.

Sign-in: when the site sends the tab to its sign-in page, the chain signs in with the intent's
item: identifier, password, and the TOTP code when the item has one. Ruling 9 supplies the
trusted gesture. Unchanged: look-alike domains refused, `Associated` matches refused, top
document only, cross-origin frames never, stop when the owner types in a targeted field, never
a submit on signup, checkout or payment forms.

What OnePass does not pass: CAPTCHA, SMS or email code, push approval, device approval, an
unknown step. The journey card says "Your turn", the journey stays armed in the tab, and it
resumes by itself once the tab is back on the site's domain, signed in.

Re-authentication asked by the site before its security settings: OnePass fills and submits the
password on the item's domain, twice at most per journey (the chain's existing limit).

Navigation and clicks: after sign-in, `goto` the settings URL, then the recipe's steps. Before
each click the target is looked up again; it must be visible, in the top document or a
same-origin frame, on an allowed domain. If the tab leaves the allowed domains, the journey
stops.

Journey card: a small OnePass card in the tab shows the current step and a "Stop" button, which
destroys the intent. Journey state lives in `storage.session` under the tab id, with no secret,
and survives a worker restart.

End:

- TOTP: QR read, confirmation card (section 1), write, code filled, the owner presses "Verify",
  recovery codes offered.
- Passkey: the recipe clicks "Create a passkey", the site calls WebAuthn, the existing OnePass
  window opens with the intent's item preselected, the owner approves.
- Tab closed or intent expired: nothing remains.

Extension layout: the chain machine gains three step kinds (`navigate`, `recipe`, `qr`). The
recipe interpreter, the QR finder and the journey driver are separate modules under
`extension/src/background/setup/` and `extension/src/content/setup/`, so `machine.ts` only
dispatches to them.

### 4. Prompts (apps)

- Item detail: a 2FA banner after the existing `PasskeyOfferBanner`, same restraint. Text:
  "This site offers two-factor authentication." Main button by what the pack holds: "Enable"
  (recipe), "Open settings" (URL only), "See how" (help article only). Secondary: "Ignore".
- The passkey banner's button starts the journey instead of opening the home page. Without a
  passkey URL in the pack, the app reads the site's own `/.well-known/passkey-endpoints` on the
  click, as today, then falls back to the home page.
- One banner at a time, in Watchtower severity order: 2FA first, then passkey. The other stays
  in the item's Watchtower section.
- Watchtower: every row of the "2FA available" and "Passkey available" cards gets the same
  button.
- During a journey the banner reads "In progress in <browser>" with "Stop". It goes away when
  the item has its code or passkey.
- "Ignore" is the existing `watchtower_exclusions`: encrypted in the item, synced, restorable
  from the item.
- Extension popup: no prompt, only "Scan 2FA QR code".
- Mac, iPhone and iPad. Nothing on Watch or Vision.
- French, English, Spanish and Italian in the same commit, existing keys reused.
- Real screenshots of the banner and the cards, light and dark, go to the owner before any
  polish.

### 5. Errors

| Case | Behaviour |
|---|---|
| QR unreadable or missing | Card "Paste the setup key" |
| Write refused (locked, Touch ID refused, origin differs, invalid URI) | Nothing is filled, the card says why |
| Pack missing or signature invalid | The shipped copy is used; no recipe from an unverified pack runs |
| Recipe target not found | Guided mode from that step |
| App or browser quits mid-journey | Intent lost, nothing to clean |
| Second journey started | Refused, the banner names the one in progress |

## Threats considered

- A page shows its own QR to plant an attacker's seed on an item: the scan needs a popup click
  or a journey, the card names the target, a replacement defaults to Cancel, and the old seed is
  kept.
- A page reads the secret back: it already displays it. OnePass adds no new reader; the secret
  never enters `storage`, which content scripts can read.
- A stolen signing key publishes hostile recipes: the closed vocabulary allows no text entry, no
  navigation off the site's domains, no final step and no destructive click.
- A look-alike or associated domain captures the sign-in: the journey signs in only on an
  `ExactHost` or `Domain` match of the intent's item, checked by the host.
- The intent is replayed: single use, bound to one tab, short-lived, held in memory only.

## Testing

- Core: pack parse and signature, recipe schema, refusal of out-of-vocabulary recipes,
  `attach_otp` keeps the old seed, `save_totp` policy (origin, ctx, token, `exists`).
- Extension unit tests: QR finder on fixture pages (img, canvas, SVG, CSS background,
  cross-origin frame, decoy QR), recipe interpreter, recovery-code detection.
- Extension end-to-end on the Atlas test site: full TOTP and passkey journeys, password asked
  again, CAPTCHA stop then resume, QR account different from the item, replacing a code.
- Security end-to-end: look-alike domain, recipe leaving its domains, destructive click refused,
  scan not startable by the page, secret absent from every `storage` dump.
- Apple: unit tests, then GUI tests on the demo vault with the QA bundle id.
- Real sites: each recipe checked by the owner with the recorder. Safari on Mac and iOS: a pass
  on real devices.

## Delivery waves

Each wave ships alone and gets its own plan.

0. Three short probes: which permission lets `captureVisibleTab` run without a click on the
   toolbar icon, per browser; the handoff on Firefox and Safari; the QR decoder (size, licence,
   hit rate on fixtures).
1. QR capture: popup button, `save_totp`, confirmation card, code fill, recovery codes
   (Chromium, Firefox).
2. Site pack, core, FFI, banners and Watchtower buttons, `NOTICE`.
3. Journey in guided mode: intent, open, sign in, land on the settings, resume at the QR or the
   passkey prompt (Chromium, Firefox).
4. Recipe engine, recorder, the twenty sites checked one by one.
5. Safari on Mac.
6. iPhone and iPad.

## Out of scope

- Submitting the final code for the owner, and any click that enables or disables a setting
  after the QR.
- HOTP and `otpauth-migration://` in the extension.
- Prompts in the popup or in the page.
- Removing the password once a passkey exists.
- Any telemetry on recipe health.
- Screen scan on the Mac through ScreenCaptureKit (still planned in the architecture spec).
- Android, Windows, Linux.

## Open points

- CC-BY-4.0 data inside an App Store build: not checked by a lawyer. If refused, the passkey
  list falls back to the Dashlane list and the in-repo map.
- The signing key for packs does not exist yet. The icon pack's updates are off for the same
  reason.
- `captureVisibleTab` inside a journey may need a click on the toolbar icon. Wave 0 settles it.
- The Safari handoff has never run on a device.
- The shape of the QR on the twenty sites (image, canvas, SVG, frame) is not verified; it needs
  signed-in sessions.
