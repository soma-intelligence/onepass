# How to export or back up a Cleon vault

Cleon exports to a signed, encrypted `.onepass` archive, either protected by a passphrase (portable: it restores into any Cleon account) or encrypted to your account (a backup only that account opens, signed by it). In the apps, use Settings > General > Backup: "Encrypted Backup…" or "Unencrypted CSV Export…", and "Restore a Backup…" to bring one back. A plaintext CSV export exists for moving elsewhere, but it is not a full backup.

## The two kinds of encrypted archive

| | Passphrase export | Account backup |
|---|---|---|
| Who can open it | Anyone with the passphrase, into any account | Only the account that made it |
| Key | `KEK = HKDF(Argon2id(passphrase), "onepass/archive/kek/v1")` | Content key wrapped to the account's ML-KEM-1024 + X25519 key |
| Signature | None | ML-DSA-87 + Ed25519, required and checked against the opening account |
| Passphrase rule | zxcvbn score of 3 or more, Argon2id at the account floor | No passphrase to type |

The payload is always sealed with AES-256-GCM-SIV and key commitment. A tampered passphrase archive reads as a wrong passphrase and never releases content. Format details: [`docs/security/README.md`](../security/README.md), section 6 (in French).

## Restoring

Restore reuses the vault with the same id if it exists, or creates one. An item whose id already exists is skipped and counted, never overwritten. Trash and archived items come back as they were. All items are validated before the first write, so a forged archive is refused as a whole. Restore is refused while Travel Mode is on.

## Plaintext CSV export

- Off unless you ask for it explicitly (`--plaintext` in the CLI, "Unencrypted CSV Export…" in the apps).
- The file is created with mode `0600` and never overwrites an existing file.
- It leaves out passkey private keys (only `passkey:<rp_id>` is written) and Location values.
- Spreadsheet formulas are not escaped, so opening it in a spreadsheet may interpret them.
- It re-imports with the `onepass-csv` format.

Delete it once you are done with it.

## From the development CLI

```bash
onepass export --out vault.onepass --generate-passphrase
onepass export --out vault.csv --format csv --plaintext
onepass backup create --out backup.onepass --passphrase
onepass backup restore backup.onepass
onepass backup inspect backup.onepass       # reads the clear header only, no key needed
```

## Why keep one

The README asks you to keep an encrypted export while Cleon has not had an external audit, so Cleon is never the only copy of a secret.

## Related

- [Import from another password manager](import-from-other-password-managers.md)
- [Master password, Secret Key and Emergency Kit](master-password-secret-key-emergency-kit.md)
- [Has Cleon been audited?](security-audit-status.md)
- [README](../../README.md)
