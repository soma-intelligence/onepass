# Recover wipe and stolen devices (2026-11-03)

Founder decisions of 2026-11-03, binding:

1. After a `Recover` rotation, the account's old devices are quarantined and erase their local vault automatically 7 days later, unless re-approved before then.
2. A device the user marks as stolen erases its local vault at once, as soon as it sees the order. The user marks it from another device of the account (devices list), also right after a `Recover`.

This amends rule I1 of the key rotation v2 spec (8.4) for `Recover` only, and adds a wipe order. Code: `core/onepass-core/src/repo/follow.rs` (`quarantine_tick`, `erase_clock_runs`, `quarantine_erase_at`), `src/trust.rs` (`QuarantineClock`, version 5), `src/lineage/wipe.rs`, `src/repo/stolen.rs`; FFI `Session::mark_stolen`, `Session::stolen_devices`; apps `VaultSession.runQuarantineClock`, `VaultSession.markStolen`, the devices screen and the removed-device screen.

## 1. The 7-day erase after a Recover

- A `Recover` child of the device's head, admitted by the resolver (identity-signed self intro of the rotator), counts its rotator `Verified` in `erase_clock_runs`. Every other step of the path keeps the I1 rule.
- The clock starts when the device first reads the `Recover` (its first tick), not at the rotation's `issued_at`: that date is chosen by the signer, and a forged `Recover` dated in the past would otherwise erase at first sight with no window for "Ce n'était pas moi".
- Re-approval ("Ce n'était pas moi" with the password and Secret Key, or a kit restore) ends the quarantine and the clock.

## 2. A clock that cannot be set back

`TrustState` version 5 adds `quarantine_clock: Option<QuarantineClock { by, last, elapsed }>`. Each tick adds `max(0, now - last)` to `elapsed` and sets `last = now`. A clock set back counts nothing, and the count goes on from the new reading. Erase when `elapsed >= 7 days`; `erase_at = now + (7 days - elapsed)`. A version 4 state decodes as version 5 with no clock; a quarantine with no clock (or a clock of another `by`) starts with `now - since` counted. A clock set forward brings the erase forward (the device's own clock, as before).

## 3. Wipe orders

`SignedWipe { body: WipeBody { format, account_id, target, target_key, removed_by, head, issuer, issued_at }, identity_sig }`, encoded `"OPWIPE01" || postcard`, signed by the identity of `head` under `onepass/wipe-order/v1`. `target_key = SHA-256("onepass/wipe-target/v1" || postcard(DevicePublic))`. Stored as a `RecordKind::Lineage` row (immutable, never deleted by a client, remote deletions refused), id `SHA-256("onepass/wipe-id/v1" || encoding)[..16]`, version = head generation. No new record kind: every lineage reader skips rows that do not decode as `LineageRecord`, and the magic is no `LineageRecord` variant.

Issuer (`Repository::mark_stolen`): trust state `Current`, the target is not this device and is in `TrustState::revoked`, the unlocked identity is the head's; `removed_by` is the rotation of the own chain that revoked it; the target's public keys come from a roster, a genesis creator or an intro. Marking twice writes once. The app asks for presence first, as for a removal.

Target (`quarantine_tick`): applied only while `Quarantined { by }` with `by == removed_by`, the erase clock running (not `Locked`), `target` and `target_key` its own, `head` equal to `by` or a descendant through rotations each signed by a device of its parent's roster (both signatures, consecutive generations, no `Recover`, at most 64 steps), `issuer` in `head`'s roster and not the target, and the identity signature valid under `head`'s identity. Then `erase_device` at once.

## 4. Apps

- Lock and startup path: `runQuarantineClock` at every re-read of the store and when a session is found removed. `Waiting` and `Locked` show the removed-device screen (with the date and time left for `Waiting`); `Erased` removes the account's Keychain items and settings (`forgetErasedAccount`) and ends in `.noAccount`. A store with no lineage is never touched.
- Devices screen: "Marquer comme volé" on a removed device of an account that removes by lineage, with a confirmation and the presence check of a removal; "Marqué comme volé" once done.

## 5. Tests

Core `tests/rotation_v2.rs`: `old_devices_quarantined_then_repair` (now `Waiting`), `recover_quarantine_erases_after_seven_days`, `clock_set_back_does_not_stop_the_erase`, `erase_date_follows_the_saved_clock`, `reapproval_cancels_countdown_and_order`, `stolen_after_recover_erases_at_once`, `stolen_before_first_tick_erases_at_once`, `marking_twice_writes_once`, `forged_orders_erase_nothing`, `order_for_another_device_erases_nothing`, `order_without_its_removal_erases_nothing`, `removed_then_marked_stolen_erases_at_once`, `other_account_store_untouched`. Unit: `trust::version_4_reads_without_clock`, `trust::quarantine_clock_ignores_rollback`, `lineage::wipe` codec tests. FFI `tests/rotation.rs`: `quarantine_erases_only_after_seven_days` (rollback rule), `stolen_device_erases_at_its_next_fetch`. Fuzz: `lineage_record` decodes orders too.
