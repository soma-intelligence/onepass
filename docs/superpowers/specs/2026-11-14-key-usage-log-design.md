# Key usage log: who used a secret, where, through which channel

Date: 2026-11-14. Status: built on branch feat/key-usage-log (commits 80f81f76d..d4f444add), not merged, not pushed.

## Goal

Every use of a secret leaves a trace on its item: when, through which channel (app, AutoFill,
CLI, MCP, SSH agent), on which device, by which client, what was done and which field was read.
The owner sees it on the item, on every device, and Watchtower points at API and SSH keys nobody
used for 90 days.

Success: an agent reads an API key through the MCP on the Mac, and a minute later the item on the
iPhone shows "Claude Code · MCP · API key revealed · MacBook Pro". Fifty `git push` signatures in a
row show as one line "×50". A key untouched for 90 days shows up in Watchtower.

## Where it stood (exploration 2026-11-14)

- AutoFill fills are remembered per site in the item's `UsageTrailer`
  (`core/onepass-core/src/model/usage.rs`, `Repo::record_usage`, `core/onepass-core/src/repo.rs`).
- Uses inside the app are counted (`Repo::record_app_use`, `app:` key of the same trailer). The
  apps read `uses` and `last_use_at` (`apple/VaultKit/Sources/VaultKit/Session/VaultSession+Usage.swift`).
- The item timeline (`model/events.rs`, `ItemTrailer`, 200 events) records edits, never uses.
- The device-local autofill history (`autofill_history.rs`) records which login was chosen on
  which site, never synced.
- The CLI (`onepass-cli`), the MCP (`onepass-mcp`: `reveal_secret`, `run_with_secrets`,
  `totp_code`, `fill_in_browser`, `fill_template`) and the SSH agent (`onepass-ssh-agent`, `sign`)
  record nothing. A key read by an agent or a key that signs leaves no trace.

## Owner rulings (2026-11-14)

1. Scope: a detailed log per item (date, channel, device, client, action, field), not only a
   counter.
2. Storage: synced inside the item, sealed with it.
3. Detail kept: client name, action and the label of the field read. Never a value.
4. Watchtower flags dormant keys only (no use for 90 days). No "new client" alert, no per-agent
   report.
5. Read-only sessions: a sealed local queue on the device, flushed at the next write session.
6. An older build that saves the item drops the log it cannot read (same accepted trade-off as
   the timeline).

## Data model

New module `core/onepass-core/src/model/key_use.rs`.

```rust
/// Postcard encodes variants by index: only append (pinned by model::wire_tests).
pub enum KeyUseChannel { App, AutoFill, Cli, Mcp, SshAgent }

/// Only append.
pub enum KeyUseAction { Revealed, Copied, Injected, Totp, Signed, Filled }

pub struct KeyUse {
    pub channel: KeyUseChannel,
    pub action: KeyUseAction,
    pub device_id: Id,
    pub device_name: String,   // at most 64 chars
    pub client: String,        // at most 64 chars, may be empty
    pub field: String,         // field label, at most 64 chars, may be empty
    pub first_at: OffsetDateTime,
    pub last_at: OffsetDateTime,
    pub count: u32,            // saturating
}

pub struct KeyUseTrailer {
    pub entries: Vec<KeyUse>,
    /// Set by "Clear log": entries with last_at <= cleared_at are dropped at merge.
    pub cleared_at: Option<OffsetDateTime>,
}
```

Meaning of the fields:

- `client`: MCP `clientInfo.name` from `initialize` (e.g. "Claude Code"); for the CLI the name of
  the parent process; for the SSH agent the code identity of the client it already resolves; for
  the app and AutoFill the app or browser name.
- `field`: the label of the field the action touched ("API key", "password", "private key").
  Empty when the action covers the whole item (`Filled`).
- Device name comes from the account's device list, truncated, never the host name of the machine
  when the device has no name.

Limits:

- `MAX_KEY_USES = 200` entries per item, the oldest `last_at` dropped first.
- `KEY_USE_TTL_DAYS = 365`: an entry whose `last_at` is older is dropped at the next write.
- Coalescing key: `(channel, action, device_id, client, field)`.

## Wire format

- `vault::encode_item` writes `KeyUseTrailer` as a third sealed trailer, after `ItemTrailer` and
  `UsageTrailer`. The earlier trailers are always written when a later one is (as `UsageTrailer`
  is today), so position identifies each one.
- An item without key uses is written exactly as before.
- A trailer a build cannot read opens the item without the log, never fails it.
- `Item` skips `key_uses` in its own serde form, so the MCP and the CLI never list it through
  `get_item`.
- Wire tests pin the trailer order and the enum indexes.

## Writing a use

New `Repo::record_key_use(vault, item_id, use_: KeyUseInput, now) -> Result<bool>`.

1. Find the entry with the same coalescing key.
2. If it exists and `now - last_at < REWRITE_AFTER_SECS` (3600), the item is not written: the
   use goes to the local queue (below), which coalesces it. The item is written at most once per
   hour per coalescing key.
3. Otherwise merge any queued rows of this item, bump or insert, apply the TTL and the cap, save
   the item with `updated_at` unchanged (as `record_usage`).
4. Returns `true` when the item was written.

The queue therefore serves two cases: read-only sessions and uses inside the hour. Counts stay
exact; the synced `last_at` may lag by up to an hour until the next write or flush.

Rules shared with `record_usage`:

- A key-use write never beats a real edit from another device: the sync rebase lets a remote edit
  win, then carries the local log over.
- Merge of two logs: union by coalescing key, `count = max`, `first_at = min`, `last_at = max`,
  then drop entries at or before the larger `cleared_at`, then TTL and cap.
- Archived and trashed items still record uses (a trashed key that still signs is worth seeing).

Best effort: every caller hands the secret out or signs first, then records. A failure to record
is logged at debug level and never fails the read, the injection or the signature.

## Local queue for read-only sessions

- A CLI or MCP session that is read-only (`Error::ReadOnly`) cannot write the item. The use goes
  to a device-local queue instead.
- Storage: the device database, each row sealed under a key derived from the account keyset with
  a new `BlobKind::KeyUseQueue` (next free number), filed under a keyed tag of the item id.
- At most 1000 rows, the oldest dropped first. Rows coalesce on the same key as the trailer.
- Flushed at the start of each write session on that device (app unlock, CLI or MCP write
  session) and at each app foreground, for rows whose last use is more than an hour old, item by
  item. A row whose item is gone is dropped.
- Travel Mode erases the queue. A row a build cannot open is dropped.

## Callers

| Channel | Entry points | Action | Client |
|---|---|---|---|
| MCP | `reveal_secret` | Revealed | `clientInfo.name` |
| MCP | `run_with_secrets`, `fill_template` | Injected | `clientInfo.name` |
| MCP | `totp_code` | Totp | `clientInfo.name` |
| MCP | `fill_in_browser` | Filled | `clientInfo.name` |
| CLI | `read`, `item get --reveal` | Revealed | parent process name |
| CLI | `totp` | Totp | parent process name |
| SSH agent | `sign` | Signed | client code identity |
| App | copy of a secret field, reveal | Copied / Revealed | app name |
| App | TOTP copied | Totp | app name |
| AutoFill | fill accepted (existing `record_usage` path) | Filled | browser or app |

One use of several fields of one item (e.g. `run_with_secrets` injecting two fields) records one
entry per field.

## FFI and apps

- FFI: `item_key_uses(vault_id, item_id) -> Vec<FfiKeyUse>`, `clear_key_uses(vault_id, item_id)`,
  and the app-side `record_key_use` for copies and reveals.
- `ItemDetailView`: a new collapsed section "Utilisation" below the Watchtower section. Header
  summary: "Utilisée il y a 2 h · 365 fois depuis mars" (every use since the month of the earliest
  `first_at`, the year added when it is not this year; an entry's count runs from its first use,
  so the log holds no per-month count). Open: newest first, one row per entry:
  client · channel · action and field · device · ×count, one SF Symbol per channel. Styled after
  `ItemTimelineView`, loaded the same way as `itemTimeline`.
- "Effacer le journal" sets `cleared_at` and empties the entries; it syncs like any item write.
- Hidden when the log is empty. Shown on iPhone, iPad, Mac and visionOS.

## Watchtower: dormant keys

- New `Check::Dormant`, appended to the enum, severity `Low`.
- Applies to items of template `ApiCredential` and `SshKey`, active (not archived, not trashed).
- Flags an item created more than 90 days ago whose last key use is more than 90 days old, or
  that has no key use at all.
- Warm-up: the check runs only once the account has recorded key uses for 90 days (first
  `record_key_use` date stored in the account metadata). Before that no item is flagged, so the
  first launch does not mark every key as dormant.
- Text: suggests revoking the key at its provider, then archiving the item.
- Excluded per item through the existing Watchtower exclusion.

## Privacy

- Never a secret value, never a command line, never an argument, never a file path.
- Client names come from the client itself and are not trusted: shown as text, never as markup,
  truncated to 64 characters.
- The log is sealed inside the item and shared with whoever shares the vault: members of a shared
  vault see each other's device names and clients. Called out in the sharing sheet's footnote.

## Testing

- Wire: trailer order, an item without log written byte for byte as before, an unreadable trailer
  opens the item, enum indexes pinned.
- Merge: union, max and min rules, `cleared_at` tombstone, remote edit wins over a log-only write.
- Coalescing within the hour, cap of 200, TTL of 365 days, saturating count.
- Best effort: a failing `record_key_use` never fails `reveal_secret`, `read` or `sign`.
- Queue: read-only session queues, write session flushes, cap of 1000, Travel Mode erases.
- MCP and CLI integration: each entry point of the table records the expected channel, action,
  client and field.
- SSH agent: 50 signatures in a row give one entry with count 50 and at most one item write.
- Watchtower: 90-day threshold, warm-up, exclusion, only `ApiCredential` and `SshKey`.
- Swift: section hidden when empty, summary text, clear.

## Out of scope

- Alerts on a new client or device, per-agent reports.
- Export of the log.
- Remote host of an SSH signature (the agent protocol does not give it reliably).
