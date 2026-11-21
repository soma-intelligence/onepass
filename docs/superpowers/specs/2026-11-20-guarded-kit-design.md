# Guarded Kit: a rate-limited third secret (2026-11-20)

Status: founder decisions of 2026-11-20 taken (section 12), binding. No code yet.

## 1. Problem

The AUK needs two secrets: the master password (through Argon2id, 256 MiB) and the 256-bit Secret Key (`docs/security/README.md`, 3.1). Storage alone can do nothing. But once the Secret Key leaks (a stolen Emergency Kit, a photo of it, a kit left in a drawer), the only thing between the attacker and the whole account is Argon2id on the master password, **offline, with no limit on guesses**. A 40-bit password falls in days on a GPU farm, even at 256 MiB.

The same gap exists for:

- passphrase archives (`docs/security/crypto-review.md`, section 10), which have no Secret Key at all;
- the recovery help of families (README 19.5): organizer and storage together open the keyset.

This spec closes the first case and prepares the other two.

## 2. Goal and non-goals

**Goal.** An attacker who holds the Emergency Kit **and** a full copy of the storage gets at most a small, fixed number of online guesses on the master password (30 in total with the defaults of section 6), after which the guard is destroyed. Today that attacker has unlimited offline guesses.

**Invariant.** The guard never lowers security. In every scenario where the guard fails (all realms compromised, realms colluding with the attacker, quantum attacker on the realms), the attacker is exactly where they are today: Secret Key plus offline Argon2id.

**Non-goals.**

- Daily unlock does not change and stays offline. Realms are only contacted when restoring onto a new device, and when registering or rotating.
- No protection against a compromised unlocked device. That device holds every secret, as today (README 1, out of scope).
- No change to the primitives of sections 3.2 to 3.4.

## 3. Prior work

- **Juicebox protocol** (Juicebox Systems, 2023): secret shared across T-of-N "realms", each realm holds an OPRF key and a guess counter, the secret share is released only after a correct PIN proof. This spec follows its structure.
- **Signal SVR3** (2024): the same idea across three hardware enclaves from three clouds (SGX, Nitro, SEV-SNP), with consensus inside each realm to stop rollback of the counters.
- **RFC 9497** (OPRF, VOPRF): the OPRF used here.
- **Apple iCloud Keychain escrow**: HSM clusters with a 10-attempt limit on the device passcode. Same promise, single operator.

## 4. Overview

A third secret, the **guard** `G` (256 bits), joins the AUK:

```
x      = HKDF-SHA256(salt = kdf.salt, ikm = argon2_out, info = "onepass/guard/x/v1")
AUK_v2 = HKDF-SHA256(salt = kdf.salt, ikm = argon2_out || secret_key || G, info = "onepass/auk/v2")
```

- `argon2_out` is the existing Argon2id output: no second 256 MiB derivation.
- `G` is split T-of-N (Shamir over GF(2^8), byte by byte) across N **realms**. Realm `i` releases its share only to a client that proves knowledge of `x` through an OPRF, and counts every attempt.
- Each device keeps `G` in its secure storage next to the Secret Key (same Keychain class, `WhenUnlockedThisDeviceOnly`). Daily unlock reads it locally.
- Pairing a new device sends `G` in the snapshot, like the Secret Key.
- Restoring from the Emergency Kit on a new device is the only path that asks the realms.

Downgrade is impossible by construction: once the keyset is sealed under `AUK_v2`, no `AUK_v1` opens it. A storage that hides the guard descriptor only gets a failed unlock.

## 5. Realms

**Defaults.** N = 3, T = 2, all three operated by Soma Labs (decision Q2), each on a different cloud and TEE family: Azure confidential VM (AMD SEV-SNP), AWS Nitro Enclaves, Google Cloud Confidential Space (Intel TDX). No single cloud and no single TEE vendor can read two shares. A Soma insider who controls all three realms is back to today's level (Secret Key plus offline Argon2id), never below: the security page says so in plain words.

**Pinned in the app.** The realm list (id, URL, Ed25519 response key, expected TEE measurement) is compiled into each release, like the HIBP endpoint. It is **never** read from storage. Reason: if storage could point a client at a fake realm, the fake realm would see a phase 2 tag (section 7) computed under an OPRF key it controls, and could test password guesses offline against it. With the password, the attacker would then ask the real realms once. Pinning is what makes the guarantee hold. The ProVerif witness `guard_unpinned.pv` (section 10) shows the attack without it.

**What a realm stores per guard** (`guard_id`, 16 random bytes):

| Field | Content |
| --- | --- |
| `oprf_key` | ristretto255 scalar `k_i`, generated in the realm, never leaves it |
| `tag` | 32 bytes, checked in constant time (section 7) |
| `share_ct` | share `s_i` sealed with the existing blob format (AES-256-GCM-SIV + HMAC commitment) |
| `owner_key` | Ed25519 public key that may update, rotate or delete this guard |
| `limit`, `attempts` | guess limit and counter |
| `version` | u32, raised at each re-registration |
| `failures_log` | dates of failed attempts since the last success (no IPs) |

**Rollback.** A realm that restores an old snapshot resets its counters. Requirement R1: each realm keeps its state replicated with consensus inside the TEE (as SVR3), or on a hardware monotonic counter. Until a realm meets R1 it is marked `rollback-exposed` in the pinned list and the app shows it in the security page.

## 6. Guess limit

- `limit = 10` per realm. Counter raised **before** each OPRF evaluation (phase 1), reset to 0 on a correct phase 2.
- A correct tag at a single realm already tells the attacker their guess is right, so the bound is `N x limit = 30` guesses in total, not 10. Stated as is to the user ("une trentaine d'essais au plus").
- When `attempts` reaches `limit`, the realm erases `oprf_key`, `tag` and `share_ct` at once and for good (decision Q4: no cooldown, no growing delay). The guard is gone at that realm.
- With N = 3 and T = 2, losing one realm is survivable. Losing two means `G` can only come from a device of the account (section 8.4).

## 7. Protocol

All messages are postcard, wrapped in the existing signed-request frame of the mailbox (README 18.2) when the client has an `owner_key`; restore requests carry no signature.

### 7.1 Registration (a device of the account, unlocked)

1. Draw `G` (covered randomness, README 17). Split into N shares `s_1..s_N`, threshold T.
2. For each realm `i`, open a registration with `owner_key` (a device key of the account, domain `onepass/guard/owner/v1`). The realm draws `k_i` and returns `guard_id_i` and a signed receipt.
3. OPRF round with realm `i` on `x` (RFC 9497, mode OPRF, ristretto255-SHA512): the client gets `y_i = OPRF(k_i, x)`.
4. Derive per realm:
   ```
   tag_key_i   = HKDF(y_i, info = "onepass/guard/tag-key/v1")
   tag_i       = HMAC-SHA256(tag_key_i, "onepass/guard/tag/v1" || realm_id || guard_id_i || version)
   share_key_i = HKDF(y_i, info = "onepass/guard/share-key/v1")
   share_ct_i  = seal(share_key_i, s_i, aad = realm_id || guard_id_i || version)
   ```
5. Send `tag_i` and `share_ct_i` to realm `i`. The realm stores them with `limit`.
6. Write the **guard descriptor** to storage (section 7.3) and re-seal the keyset under `AUK_v2` in one manifest write.
7. Keep `G` in the device's secure storage. Pairing sends it to every device of the roster.

A realm never sees `x`, `y_i`, `s_i` or `G`. It cannot forge `share_ct_i`: the key comes from `y_i`, which needs `x`.

### 7.2 Restore (new device, Emergency Kit + password)

1. The user types the Secret Key and the password. Compute `argon2_out`, then `x`.
2. Read the guard descriptor from storage and open its locator (section 7.3) with the Secret Key: this gives `guard_id_i` per realm.
3. Phase 1, for T realms (at random among the N): blind `x`, send the blinded element. The realm raises `attempts`, evaluates, returns the result and `limit - attempts`. Unblind: `y_i`.
4. Phase 2: send `tag_i`. The realm compares in constant time. Match: `attempts = 0`, return `share_ct_i`, log a success. No match: log a failure, return the remaining count.
5. Open each `share_ct_i`, combine T shares into `G`, derive `AUK_v2`, open the keyset. If the keyset does not open with a set of T shares, try another set from the remaining realm (a wrong share is only possible through a bug: realms cannot forge).
6. Continue with today's kit restore (`repo/kit.rs`): identity, roster, pinning by another device.

Wrong password: the tags fail at every realm asked, nothing else is learned. The screen says how many attempts remain at the realm with the fewest.

### 7.3 Guard descriptor in storage

```
GuardDescriptor {
  format, account_id, version, threshold,
  locator_ct,          // seal(HKDF(secret_key, "onepass/guard/locator/v1"), postcard([(realm_id, guard_id_i)]))
  realm_set_hash,      // SHA-256 of the pinned realm list used at registration
}
```

- `guard_id` values are sealed under the Secret Key so that **storage alone cannot burn the attempts**: only a holder of the Secret Key (a kit holder or a device) can locate the guard at the realms.
- After unlock, the descriptor is checked against the account parameters signed by the identity (`account-params` gains `guard: Option<(version, descriptor_hash)>`), like the Argon2id parameters.
- A pinned realm list that no longer contains a realm of `realm_set_hash` makes the app re-register (section 8.3).

## 8. Lifecycle

### 8.1 Turning the guard on

Opt-in only (decision Q1): off for every account, new or old, until the user turns it on from Settings > Sécurité, after the password. No onboarding prompt. Registration (7.1), then the app asks to print a new Emergency Kit: the old kit still works with the password **and** the realms, so it is not weaker, but the new one carries the text of section 9.

### 8.2 Password change, key rotation v2

Both change `x` or the Secret Key: re-register under a new `version`, then delete the old guard at each realm with `owner_key`. A rotation (README 16) registers with the new identity's device keys as owners. A removed device loses `owner_key` rights at the next re-registration.

### 8.3 Realm list change in a release

The app re-registers at the next unlock with `G` unchanged (new shares only): no new kit needed.

### 8.4 Attempts seen, guard burnt

- Each device polls its realms (signed with `owner_key`) at most once a day, and after each sync. Any failure in `failures_log` shows an alert: "Quelqu'un a essayé de restaurer ton compte avec ton kit d'urgence." with dates, and offers a rotation (new Secret Key, old kit dead).
- A realm whose guard is erased triggers a re-registration from any device that still holds `G`.
- The only loss case: **every device lost and T realms burnt or gone**. The account is then unrecoverable, even with the kit and the password. This is the price of the guarantee and the reason for decision Q1.

## 9. Apps and copy

- Settings > Sécurité > "Protection du kit d'urgence". Off: "Avec ton kit et ton mot de passe, quelqu'un peut essayer des mots de passe sans limite." On: "Une trentaine d'essais au plus, puis le kit ne sert plus à rien sans un de tes appareils."
- Restore screen: remaining attempts, shown from the first failure.
- Kit PDF: one line, "Restauration en ligne, essais limités."
- Watch, widgets, AutoFill extension: no change (they never restore).
- Same feature, same copy and same release on every client (decision Q6): iPhone, iPad, Mac, Vision Pro, Android, Windows and the CLI.
- Before turning it on, the confirmation sheet states the loss case of 8.4 and that Soma runs all three realms.
- CLI: `onepass guard enable | status | rotate | disable`. `disable` re-seals under `AUK_v1` after the password and deletes the guard at the realms.

## 10. Formal model

`formal/proverif/guard.pv`, processes in `guard_core.pvl`:

- **G1** `weaksecret pw` holds for an attacker holding the Secret Key, the storage and T - 1 realms: no offline guessing. ProVerif models the guess limit as the absence of an offline test, not as a count.
- **G2** secrecy of `G` under the same attacker, for a password that is not guessed.
- **G3** a realm-held share is released only after a tag computed from the right `x`.
- Negative witnesses, expected `false`: `guard_t_realms.pv` (T realms compromised: offline guessing comes back, at Argon2 cost, which is today's level) and `guard_unpinned.pv` (realm list read from storage: one fake realm gives offline guessing).

Results go to `docs/security/formal/results.md`.

## 11. Implementation

- **Core** (`core/onepass-core/src/guard/`): `shamir.rs`, `oprf.rs` (crate `voprf`, the one under `opaque-ke`, audited by NCC Group; a new dependency, so it goes through `deny.toml` and `supply-chain/` like the others, and `crypto-review.md` gains a section for it), `descriptor.rs`, `client.rs` (registration and restore state machines, no network: the apps and the CLI carry the bytes, as for pairing). `crypto/kdf.rs` gains `derive_auk_v2`. `account.rs` carries `guard` in the signed parameters.
- **FFI**: UniFFI objects `GuardRegistration`, `GuardRestore`, bound for Swift, Kotlin (Android) and the Windows client; each sees opaque bytes. `G` goes to each platform's secure storage (Keychain, Android Keystore, DPAPI), as the mailbox credential does (README 18.2).
- **Release gate** (decision Q6): the feature ships only when every client passes the restore and burnt-realm tests; no platform gets it alone.
- **Realm server** (`realm/`): small Rust service, same crates, built reproducibly (`docs/security/reproducible-builds.md`), its measurement published per release.
- **Tests** (`core/onepass-core/tests/guard.rs`): `restore_with_kit_and_realms`, `wrong_password_counts_once_per_realm`, `limit_erases_share`, `t_minus_one_realms_cannot_restore`, `storage_alone_cannot_locate_guard`, `fake_realm_rejected_by_pinning`, `v1_auk_never_opens_guarded_keyset`, `password_change_reregisters`, `burnt_realm_reregistered_from_device`, `forged_share_ct_refused`. Shamir and OPRF vectors: RFC 9497 appendix A, plus a differential test against a second Shamir implementation. Fuzz target on realm message decoding.

## 12. Founder decisions (2026-11-20)

- **Q1. Default: opt-in.** Off for every account until the user turns it on. No account can be lost because of this feature without the user's choice.
- **Q2. Operators: Soma alone, for good.** Three realms run by Soma Labs on three clouds and three TEE families (section 5). No third-party operator is planned. Consequence stated in section 13 and in the app.
- **Q3. Limit: 10 per realm, 30 in total.**
- **Q4. Burnt guard: erased for good**, as Juicebox and SVR3. A device that still holds `G` re-registers it (8.4).
- **Q5. Next phases: archives, then family.** Phase 2: guarded passphrase archives (an archive guard registered per export, its own `G_archive`). Phase 3: `S_store` of family recovery behind the realms, which closes "organizer and storage together" (README 19.5). Each phase gets its own spec.
- **Q6. Platforms: all at once.** Apple apps, Android, Windows and the CLI in the same release (section 11, release gate).

## 13. Limits

- A realm operator who can roll back state resets its counter (R1, section 5).
- The realms see the IP and the time of each restore attempt.
- One operator (Q2). The three realms protect against outsiders, a breach of one cloud or one TEE family, and a storage leak. They do not protect against Soma Labs itself, or someone who controls Soma's accounts on all three clouds: that party is back to today's level, never below.
- The OPRF is not post-quantum. A quantum attacker who also breaches T realms gets offline guessing back, which is today's level. The keyset itself stays under the Secret Key (symmetric, 256 bits) and ML-KEM.
- Total loss case of 8.4.
