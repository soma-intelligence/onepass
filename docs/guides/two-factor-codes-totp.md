# How to store 2FA codes (TOTP) in Cleon and set up two-factor authentication from a QR code

Cleon stores TOTP secrets on Login items and shows the current one-time code next to the password. Codes fill themselves in Safari and apps through iPhone, iPad and Mac AutoFill, and in the browser extension. To add 2FA to a site, the extension can find the site's setup QR code on the page, decode it locally, save the secret on the matching login and fill the first code. You can also import `otpauth://` links from Google Authenticator and similar apps.

## Set up 2FA on a site with the browser extension

1. Open the site's two-factor setup page, where it shows a QR code.
2. Click the Cleon button in the browser toolbar, then "Scan 2FA QR code".
3. The extension looks for the QR in the page (images, canvas, SVG, CSS backgrounds and `otpauth://` links in the document and same-origin frames). If nothing decodes, it captures the visible tab. If that fails too, paste the setup key.
4. Check the issuer and account read from the QR, pick the target login, and confirm. Once the app confirms the write, the code is filled in the site's field. You press the site's button yourself; Cleon never submits.

Recovery codes detected on the page are offered, and saved only after a click. If the login already has a code, Cleon asks "Replace?" with Cancel as the default, and keeps the old code on the login as "Old code".

Decoding is local (jsQR, loaded on demand) and sends no request. The feature uses only the `activeTab` and `scripting` permissions, so a page can never start a scan. Only `otpauth://totp/` is accepted; `otpauth-migration://` and HOTP are refused. Tested on Chromium (unit and end-to-end); Firefox and Safari are not yet exercised on real sites, per `extension/README.md`.

## Where codes show up

| Place | What you get |
|---|---|
| Item detail on iPhone, iPad, Mac, Vision Pro | The current code with its countdown |
| System AutoFill (iOS, iPadOS, macOS) | Codes in verification fields and QuickType |
| Browser extension | The code fills during sign-in, including multi-step logins |
| Apple Watch | TOTP rings for items marked "On Apple Watch" |
| iOS widget "Codes" | Codes precomputed by the app, marked privacy sensitive |
| Shortcuts | "Copy One-Time Code" after a fresh authentication |
| CLI | `onepass totp "Example"` |

The extension never receives the TOTP secret, only the current code. On the Watch, the secrets stay inside a Rust object that returns codes only.

## Import codes from another authenticator

Export `otpauth://` links (one per line) and import them with the "One-Time Codes" source in "Import from Another Password Manager…", or `onepass import codes.txt --format otpauth`. See [the import guide](import-from-other-password-managers.md).

## Find accounts that should have 2FA

Watchtower shows a card for logins whose site supports 2FA or passkeys where you have not turned them on, and the apps suggest it on each such login.

## Related

- [Does Cleon support passkeys?](passkeys.md)
- [Use Cleon in Chrome, Firefox and Safari](browser-extension.md)
- [Cleon on Apple Watch](apple-watch-vision-pro-widgets.md)
- [README](../../README.md)
