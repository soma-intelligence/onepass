# Kelid master password, Secret Key and Emergency Kit: what each one does

Kelid unlocks your vault with two secrets: your **master password** and a **256-bit Secret Key** generated on your device when you create the account. Both go into the key derivation, so a stolen copy of the sync data is useless without both. The **Emergency Kit** is a PDF generated on the device that holds your Secret Key (in clear and as a QR code); you need it, together with your master password, to restore the account on a device that has neither.

## How the unlock key is derived

```
argon2_out = Argon2id(password_nfc, salt, m = 256 MiB, t = 4, p = 4)
AUK        = HKDF-SHA256(salt, argon2_out || secret_key, "onepass/auk/v1")
```

- The master password is normalized to Unicode NFC before hashing.
- The Argon2id parameters are enforced floors, checked at creation and at every unlock. Parameters coming from storage are also capped (2 GiB, 16 passes, 16 lanes) so a hostile server cannot exhaust the device.
- The Account Unlock Key (AUK) seals the keyset, which wraps one key per vault, which wraps one key per item.

## What the Secret Key looks like

256 bits, shown as 53 base32 characters (52 plus a Luhn mod 32 check character) in groups of 4. When you type it, spaces and hyphens are ignored, lowercase is accepted, and `0`, `1` and `8` are read as `O`, `I` and `B`. The check character catches any single wrong character and most swaps of two neighbours.

## Where the Secret Key lives

| Where | Storage |
|---|---|
| iPhone, iPad, Mac, Vision Pro | The data protection Keychain, class `WhenUnlockedThisDeviceOnly`: never in iCloud Keychain, never in a backup that restores to another device |
| Development CLI on macOS | The login keychain, service `me.somalabs.onepass.cli` |
| Development CLI on Linux | The Secret Service (GNOME Keyring, KWallet, KeePassXC) |
| CLI with `--insecure-file-secret-key` | In clear in `device.bin`, by explicit choice (machines without a secret store) |

## Face ID, Touch ID, Optic ID and Apple Watch

Biometric unlock wraps the AUK (never the decrypted keyset) to a per-account Secure Enclave P-256 key with ECIES, bound to `.biometryCurrentSet`: adding or removing a finger or face invalidates it and the master password is asked again. On the Mac, a setting also accepts an unlocked Apple Watch as an alternative. The master password is required again after a reboot or after 14 days. After 5 wrong passwords the app waits 30 seconds, then 1 minute, then 5 minutes per further failure. On Vision Pro, Optic ID goes through the same Secure Enclave key.

## The Emergency Kit

- Generated on the device as a PDF (Secret Key in clear plus a QR code), shared through the system share sheet, and deleted from the temporary folder once the step is gone.
- Used to restore the account on a device that has no other way in, and offered as a recovery path if the account disappears from storage ("Restore with My Emergency Kit").
- After a key rotation, old kits restore into the old identity: the app asks you to destroy them.

Keep the kit offline, apart from your master password. Anyone with your latest kit **and** your master password can restore your account.

## Changing the master password

You can change your master password from Settings. The development CLI also offers `onepass account rotate-keys`, which rotates every key, draws a new Secret Key and writes a new Emergency Kit (file mode `0600`, never overwritten).

## If you lose both the password and the kit

The repository documents no recovery path without your master password and Secret Key for a personal account. Recovery codes are listed as planned in the [README roadmap](../../README.md#roadmap). Keep an encrypted export as a second copy ([how](export-and-backup.md)).

## Related

- [Post-quantum cryptography in Kelid](post-quantum-encryption.md)
- [Add a new device](add-a-device.md)
- [Export or back up a vault](export-and-backup.md)
- [README](../../README.md)
