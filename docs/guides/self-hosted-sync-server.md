# Can I self-host OnePass sync?

Not in a released app yet. Today the App Store apps sync through CloudKit in your own private iCloud, and the [README roadmap](../../README.md#roadmap) lists a self-hosted server as planned. The repository already contains the server for that work, the **OnePass mailbox** (`mailbox/`): a Supabase project (Postgres 17, edge functions) that stores opaque, end-to-end encrypted records, with self-hosting steps in [`mailbox/README.md`](../../mailbox/README.md). Treat it as work in progress.

## What the mailbox is for

Per the security doc (section 18, in French), the mailbox syncs devices outside Apple's ecosystem and accounts that leave CloudKit. Code lives in `mailbox/supabase/`, `core/onepass-mailbox-proto`, `core/onepass-mailbox`, `core/onepass-sync` and `core/onepass-ffi/src/mailbox.rs`. The server is treated exactly like CloudKit: it can be hostile, and nothing it returns is trusted without verification.

## How the mailbox protects you

- **Signed requests.** Every request except `GET /v1/config` is signed by the device's Ed25519 mailbox identity over method, path, body hash, time and a random nonce. Requests more than 300 seconds off the server clock, or with a reused nonce, are refused.
- **Transport.** TLS 1.3 only, with the hybrid X25519MLKEM768 key exchange preferred. A self-host can add its own CA in PEM.
- **Row level security.** Supabase's `anon` and `authenticated` roles have no direct access to the mailbox tables; only the mailbox SQL functions, called after signature checks, read and write.
- **Enrollment by ticket.** A device joins a mailbox only with a single-use ticket (300 second expiry) signed by an already enrolled device, for the key the new device sent through the pairing channel.
- **Signed sync home.** Where an account syncs (CloudKit, or a given mailbox on a given server) is a `SyncHome` record signed by the account key and chained by sequence number. A server cannot redirect a device to another mailbox or back to an older location.
- **Hostile server tests.** `core/onepass-sync/tests/hostile_mailbox.rs` covers replayed pages, withheld records, reordered pages, injected records, lost commit answers, partial batches and a mailbox rolled back in time.
- **Formal model.** `formal/proverif/mailbox.pv` proves that only an enrolled identity gets the records, that the server enrolls a key only with a ticket issued for it, and that a device changes location only for a `SyncHome` signed by the account.

## What a mailbox server can see

Record counts per kind, versions, padded body sizes, manifest sequence numbers, write timing, device names from the signed list, client IP addresses (in Supabase and function logs; OnePass itself stores only a daily HMAC key for rate limiting), mailbox ids and public keys, and push tokens. It sees no Apple ID, and never item contents, vault keys, the Secret Key or the password.

## Running your own

You need the official self-hosted Supabase stack (Docker: Postgres 17, Kong, Realtime, Storage, edge runtime, with `pg_cron`, `pg_net` and Vault) and the Supabase CLI pinned in `mailbox/supabase/config.toml`. In short:

```bash
supabase db push --db-url <postgres URL of your stack>
psql -f mailbox/supabase/seed.sql
supabase functions deploy mailbox mailbox-push mailbox-gc --no-verify-jwt
```

Then set the role passwords, Vault entries and function secrets listed in [`mailbox/README.md`](../../mailbox/README.md), and run the end-to-end conformance suite from `core/`:

```bash
ONEPASS_MAILBOX_E2E_URL=... cargo test -p onepass-mailbox --features testing --test conformance_e2e
```

A self-host usually opens signup (`MAILBOX_OPEN_SIGNUP=true`), and new mailboxes then get the `selfhost` plan.

## Related

- [How sync through iCloud works](icloud-sync.md)
- [Is OnePass on Android, Windows or Linux?](android-windows-linux.md)
- [OnePass threat model](threat-model.md)
- [README](../../README.md)
