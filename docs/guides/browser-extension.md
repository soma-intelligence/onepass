# How to use OnePass in Safari, Chrome and Firefox

OnePass has a Manifest V3 browser extension (TypeScript, no framework) that talks to the OnePass Mac app over an end-to-end encrypted, post-quantum channel. **Safari** gets it built into the Mac app: open OnePass once, then turn the extension on in Safari > Settings > Extensions. **Chrome and Firefox** builds use the same app through its signed relay; the Chrome Web Store listing is pending, so for now you build them from a clone. The extension holds no vault: it asks the unlocked Mac app for exactly what the current HTTPS page needs.

## Safari on the Mac

1. Install OnePass from the [App Store](https://apps.apple.com/app/id6831411523) or the [Releases](https://github.com/soma-intelligence/onepass/releases) page, move it to Applications and open it once.
2. Safari > Settings > Extensions, tick OnePass.
3. The extension pairs on its own with the app on the same Mac, with no code to type, and the popup shows it is connected. (The README notes that the real-browser check of this automatic pairing is still pending.)

On iPhone and iPad, OnePass fills Safari and apps through the system AutoFill provider. The iOS app target also embeds the same web extension for Safari (`OnePassSafariMobile`, served in process by the app's extension handler).

## Chrome, Edge, Brave or Firefox from a clone

```bash
git clone https://github.com/soma-intelligence/onepass.git
cd onepass/extension && npm ci && npm run build
```

- **Chrome and other Chromium browsers:** open `chrome://extensions`, turn on developer mode, "Load unpacked", pick `extension/dist/chromium`. Chrome pairing also needs the extension's ID in the app's allow list (`ONEPASS_BROWSER_EXTENSIONS` in `apple/project.yml`) until the Web Store listing is live.
- **Firefox:** open `about:debugging#/runtime/this-firefox`, "Load Temporary Add-on", pick `extension/dist/firefox/manifest.json`. Firefox MV3 makes host permissions optional: grant access to `https://*/*` in `about:addons` > OnePass > Permissions, or no icon appears.

Then point the browser at the app's relay:

```bash
node extension/scripts/install-app-host.mjs --app /Applications/OnePass.app --browser firefox
```

The Mac app also writes the native messaging manifests itself for each known browser (Chrome, Edge, Brave, Firefox) that has been launched once, so a known signed browser pairs without a code. Another browser, or an extension you told the app to forget, pairs with a 6-digit code compared on both screens and approved with Touch ID.

## What the extension does

- An inline menu under the focused field, keyboard included.
- **One-click sign-in** that walks multi-step logins and "Sign in with Google, Apple, Microsoft or GitHub" chains, remembers which provider account you use on each site, and stops as soon as a step leaves the allowed domains.
- Save and update prompts and a never-save list.
- Passkeys ([details](passkeys.md)) and 2FA setup from a QR code ([details](two-factor-codes-totp.md)).
- "Unlock in OnePass" brings the Mac app forward to unlock, even when it was closed.
- Languages: French, English, Spanish and Italian.

## What it never fills or receives

- HTTPS origins only, with no development exception. Payment iframes from other sites are never filled.
- The extension never receives the master password, Secret Key, vault or item keys, TOTP secrets (only the current code), passkey or SSH private keys, recovery phrases, notes, attachments, password history, items that do not match the requested origin, or the full vault.

## How the channel is protected

Pairing uses an ML-KEM-1024 + X25519 hybrid KEM with a commitment, a 6-digit short authentication string compared by you, and MACs on both sides; nothing is stored before both confirmations (120 second timeout). Each session derives fresh keys (forward secrecy) and uses AES-256-GCM with one key and one strict counter per direction. Replayed, skipped, reflected or modified frames close the session. Details: [`docs/security/README.md`](../security/README.md), section 12 (in French).

## Known limits

- End-to-end tests run on Chromium only (Playwright loads extensions only there). Safari's relay has unit tests but no end-to-end test.
- Software that can read the browser profile obtains the pairing key and can ask for secrets for specific origins, like the extension itself.
- Unknown sign-in steps hand control back to you; corporate SSO spanning several domains stops at the domain boundary.

## Related

- [Does OnePass support passkeys?](passkeys.md)
- [Store 2FA codes in OnePass](two-factor-codes-totp.md)
- [Give an AI agent a password without showing it](mcp-server-ai-agents.md)
- [OnePass threat model](threat-model.md)
- [README](../../README.md)
