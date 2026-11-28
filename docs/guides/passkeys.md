# Does Cleon support passkeys?

Yes. Cleon creates and uses passkeys on iPhone, iPad and Mac through the system AutoFill provider, and in Chrome, Firefox and Safari through its browser extension. The private key is generated and used inside the Rust core (`onepass-core::webauthn`, ECDSA P-256 / ES256 via `aws-lc-rs`) and never crosses into Swift or the extension: Swift and the browser only receive the attestation, authenticator data and signature. Passkeys are stored on the Login item, encrypted like any other value, and sync with the vault.

## Use a passkey on iPhone, iPad or Mac

1. Turn on Cleon as an AutoFill provider in the system settings (iOS, iPadOS or macOS).
2. On a site or app that offers a passkey, pick Cleon in the system sheet.
3. Unlock with Face ID, Touch ID or your master password. Every request goes through a fresh unlock.

To save a new passkey, choose Cleon when the site offers to create one. Cleon never creates a passkey silently: conditional registration (a site upgrading you to a passkey automatically) always answers `failed`, so a passkey is created only after an explicit choice.

## Use a passkey in the browser extension

A shim replaces `navigator.credentials.get` and `create` for `publicKey` requests only. A Cleon window shows the exact origin and `rpId`, and nothing is signed before a trusted click in that window. The host builds `clientDataJSON` itself, checks that the `rpId` matches the page's registrable domain (never a public suffix), and refuses mismatched top-level origins. In these cases the page gets the browser's own passkey dialog instead:

- conditional mediation (`mediation: "conditional"`),
- `cross-platform` authenticator requests,
- `userVerification: "required"` (the extension signs with UV set to 0, because a click proves presence only, without biometrics),
- `http:` pages, opaque frames, and frames whose ancestors have a different origin.

Rate limits stop a page from opening windows in a loop: at most 3 windows per tab per minute, and 10 seconds of the browser's own API after you cancel.

## Technical details

| Property | Value |
|---|---|
| Algorithm | ES256 (ECDSA P-256) only |
| Storage | PKCS#8 DER in the Login's `passkeys` field, encrypted |
| Credential id | 16 random bytes |
| Signature counter | Always 0 (synced passkeys cannot keep a monotonic counter) |
| Flags (apps) | UP, UV, BE, BS |
| Attestation | `none`, with a Cleon AAGUID |

## Watchtower and passkeys

Watchtower lists logins whose site supports passkeys or 2FA where you have not turned them on, using a signed site pack bundled with the app.

## Limits

- A passkey deleted in Cleon stays known to the site: Cleon does not yet report unknown credentials back.
- The plaintext CSV export writes only `passkey:<rp_id>`, never the private key. Use the encrypted `.onepass` archive for a full backup.

## Related

- [Store 2FA codes and set up 2FA from a QR code](two-factor-codes-totp.md)
- [Use Cleon in Chrome, Firefox and Safari](browser-extension.md)
- [Post-quantum cryptography in Cleon](post-quantum-encryption.md)
- [README](../../README.md)
