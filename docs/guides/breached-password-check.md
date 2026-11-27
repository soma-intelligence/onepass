# How Cleon checks for breached and weak passwords (Watchtower)

Watchtower is Cleon's password health check. It shows a score dial and one card per check: weak, reused and old passwords, sites that support 2FA or passkeys where you have not turned them on, breached sites, exposed accounts, and a funded crypto wallet whose recovery phrase is not protected by Travel Mode. Leaked passwords are checked through Have I Been Pwned with **k-anonymity**: only the first 5 hex characters of each password's SHA-1 hash leave the device, and offline modes send nothing at all.

## What leaves the device for the leaked password check

- The SHA-1 of each distinct password is computed in memory (`Zeroizing`).
- Only its 5-character uppercase hex prefix is sent to `https://api.pwnedpasswords.com/range/{prefix}`. The other 35 characters are compared locally against the response.
- Requests carry `Add-Padding: true`, so the server pads the response with fake zero-count lines that hide its size.
- Neither the password, the full hash, the suffix nor the item leaves the device. Each prefix is asked once per analysis.

The project states the limit plainly: the prefix tells the service that the device tested a password whose SHA-1 starts with those characters, among about a million possible passwords per prefix, and a network observer sees the request. Only the offline mode avoids that.

## Offline mode

```bash
onepass watchtower --offline --hibp-dir ./pwned --sites 2fa.json --passkeys passkeys.json --breaches breaches.json
```

`--offline` runs no network command. `--hibp-dir` reads a folder of `ABCDE.txt` range files (as written by PwnedPasswordsDownloader), so the leak check is fully local.

## Where the site data comes from

The list of sites that support 2FA or passkeys, and their security settings pages, comes from a **site pack** built weekly from open datasets (2FA Directory and 2factorauth/passkeys) and signed with Ed25519. The app downloads the whole pack from the Cleon GitHub release at most once every 7 days, never one request per site, and uses it only after `verify_site_pack` succeeds, at every load. Details: [`docs/site-pack.md`](../site-pack.md) (in French). The core itself makes no network request; the caller supplies every catalog, each capped at 16 MiB and 100,000 entries.

## Nothing is stored

Watchtower analyses unlocked items in memory and persists nothing. A source that fails marks the leak status as partial or unavailable, so a password is never reported safe by mistake. You get notifications for new findings and can exclude single items.

## Related

- [Store 2FA codes and set up 2FA from a QR code](two-factor-codes-totp.md)
- [Does Cleon support passkeys?](passkeys.md)
- [Cleon command line (CLI)](command-line-cli.md)
- [README](../../README.md)
