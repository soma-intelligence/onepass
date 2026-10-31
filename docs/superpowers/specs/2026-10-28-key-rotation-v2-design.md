# Account key rotation v2: trust anchored in device keys

Date: 2026-10-28
Status: draft for the owner's review (rulings R1 to R24 proposed, open questions in section 17). Nothing is implemented.
Branch: `docs/key-rotation-v2`, from the private `main` (`df19ac8`).
Scope: audit finding F1 (device revocation only flags the device; password change keeps the keys). Replaces the protocol part of `2026-10-28-key-rotation-design.md` (branch `fix/key-rotation`, tip `0f1c58b`, rulings K1 to K20, principles P1 to P3) and keeps its re-keying part (section 14).
Formal model: `formal/proverif/rotation.pv`, `rotation_core.pvl`, negative controls `rotation_autofollow.pv` and `rotation_account_anchor.pv` (section 13).

## 1. Why a redesign

The first implementation re-keys correctly: new keyset (KEM, signing, identity), new Secret Key, new vault keys, every item re-encrypted, one atomic local write. Four adversarial review rounds then kept finding protocol holes in how the other devices learn about the rotation and how concurrent rotations settle. The last round left:

1. **Critical.** The revoked device runs its own rotation to a fresh identity and makes it look complete on the server. Under P3 (first complete wins) the honest rotating device A abandons its rotation, drops its unsynced data and can no longer unlock; the only exit shown is to type the attacker's Secret Key (repro `zz4_revoked_device_fake_complete_rotation_beats_a`).
2. **Medium.** Two incomplete rotations livelock, and the revoked device can use that to postpone its revocation forever (`zz5_two_incomplete_rotations_alternate`).
3. **Medium.** A biometric-only device with no record of its known Secret Keys is stranded after a legitimate rotation: fail-closed with no exit (`zz_biometric_device_has_no_known_keys`, `zz6_updated_device_follows_legit_rotation`).
4. **Low.** Password-change handling decodes server params without verifying them.

Earlier rounds: concurrent password changes destroying rotations (`zz1`), the server choosing reissue epochs up to `u64::MAX` (`zz2_hostile_epoch_inflation`), the revoked device wedging the rotation (`zz_revoked_device_wedges_rotation_with_epoch_jump`, `zz2_epoch_drop_reopens_pair_drop`), two concurrent rotations (`zz3`), argument-order bugs in `unlock_after_rotation`.

**Root cause.** After a revocation the revoked device holds every account secret: master password, old Secret Key, old keyset including the identity key. The server stores anything. So nothing on the server, and nothing signed by an account key, can tell a legitimate rotation from one forged by the revoked device. Every patch of the first design (epochs, markers, known keys, first complete wins) tried to decide from data the attacker can produce as well as the owner. `rotation_account_anchor.pv` shows the root cause formally: with the rotation authenticated by an account key of the old identity, the user confirms "iPhone removed iPad" and still adopts the attacker's identity.

**The fix.** Anchor trust in two things the revoked device does not hold: the per-device keys of the remaining devices, pinned locally through the SAS-verified pairing channel, and the user's own memory of what they did. The server becomes a mailbox.

## 2. Threat model

**Attacker T1: the revoked device plus a hostile server.** It holds the revoked device's whole local state (database, Secret Key, keyset of every identity it lived under, its own device keys), the master password, every old Emergency Kit, and controls the storage: it reads, withholds, delays, replays, reorders and forges any record, and accepts any write. It runs any client code. It does not hold the device keys of the remaining devices, does not control their screens, and does not know the new Secret Key unless a remaining device gives it away.

**Attacker T2: the server alone.** Same storage powers, no account secret, no device key.

**Trusted:** the remaining devices (their code, their Keychain, their local pinned state), the SAS comparison at pairing (ruling F-02 of the formal model spec), the user's memory of the rotations and revocations they started, the latest Emergency Kit while it stays secret.

**Out of scope:** a remaining device compromised at system level; the revoked device acting before it was revoked (until the owner revokes it, it is a legitimate device and its writes are legitimate); a user who confirms a rotation they did not start after the warning of section 9; denial of service by the server (it can always withhold everything); traffic analysis.

## 3. Goals and non-goals

Goals:

- **G1 Secrecy after rotation.** Nothing written after a rotation, by any remaining device, opens with anything the revoked device holds (T1).
- **G2 No forged identity.** A remaining device adopts a new account identity only if a device it pinned and still trusts introduced it, and the user confirmed it on that device. Neither T1 nor T2 can make a device adopt another identity, silently or not, unless the user confirms a summary that names a device they no longer have.
- **G3 No silent outcome of a race.** "A revokes B" against "B revokes A" is never settled without the user, on any device that cannot tell them apart by its own pins.
- **G4 Never lose local data automatically.** No record, merge rule or server state makes a device drop its local items, pending writes or own writes. Erasing a device is always a user action.
- **G5 An exit from every stuck state**, listed in section 8.6, including a device that only unlocks by Face ID and the Emergency Kit when no trusted device remains.
- **G6 Convergence without livelock** between honest concurrent rotations, whatever the server does short of withholding forever.
- **G7 The server cannot postpone a revocation** on the device that made it, and cannot hold it back on the others by anything but withholding (T2 denial of service).
- **G8 Server params are always verified before use** (hold-out 4).

Non-goals:

- Protecting what the revoked device already decrypted, or what it can still decrypt from old ciphertexts a hostile server keeps (the past, as in the first design, section 10 there).
- Automatic follow-up with no user step on the other devices. Every adoption is a user step (R5); this is the price of G3.
- Multi-user sharing, organization recovery, server-side escrow.
- Protecting a device from its own user (a user who confirms everything).

## 4. Design in brief

1. Every device has a device key pair (hybrid signing ML-DSA-87 + Ed25519, hybrid KEM ML-KEM-1024 + X25519), created on the device, kept in its Keychain, never synced. On Apple the ML-DSA-87 and ML-KEM-1024 halves are Secure Enclave keys (O3, 5.1).
2. Device public keys are exchanged inside the SAS-verified pairing channel and pinned in local device state, never trusted from the server. A device learns devices paired by others through `Intro` records signed by a device it already trusts.
3. The account has a **lineage**: genesis, then a chain of rotation records. Each rotation record is signed by the rotating device's key and by the new identity (proof of possession), names its parent, the revoked devices and the full roster of devices trusted afterwards.
4. A device moves to a child of its current head only if the rotator is in its roster and not revoked or excluded, the record is well formed, and the user confirms it on that device, which also asks the master password.
5. The new Secret Key reaches each remaining device sealed to its device KEM key. Typing a Secret Key is only for the Emergency Kit.
6. Params, keyset, signed lists and restore epochs of each identity live in records keyed by that identity: two rotations never overwrite each other's account records.
7. Races are settled by the user when two records exclude each other's signer; honest concurrent rotations by a deterministic order, the losers re-applying their removals on top.
8. Nothing is ever dropped: a device that moves to another identity replays its own writes under the new keys; a device that reads its own revocation is quarantined, then erases itself 7 days later unless the user says it was not them (O1, 8.4).
9. The Emergency Kit restores through the identity signature on the rotation record (2SKD authenticates the identity, the identity authenticates the roster).
10. ProVerif proves secrecy, authentication and the race property, and two negative controls show that dropping either the device keys or the user step reopens the attacks.

### 4.1 Alternatives considered

| Option | Why not |
| --- | --- |
| Keep account keys as the anchor (link signed by the old identity, first complete wins, known Secret Keys) | The revoked device holds the same keys: every rule is reproducible by it. Four review rounds, formal negative control `rotation_account_anchor.pv`. |
| Device keys without a user step (follow any record signed by a pinned device) | A device that has not yet seen "A revokes B" still trusts B; B's "B revokes A" is as valid as A's record. `rotation_autofollow.pv`: the device adopts the attacker's identity silently. |
| Quorum of devices (k of n co-signatures) | A single-device account (A plus the lost B) has no quorum; two-device accounts are the common case. Kept as a possible later hardening, not a base. |
| Server timestamps or "first seen" ordering | The server chooses both. |
| Re-pair every remaining device (QR and SAS) after a rotation (K4) | Sound but heavy, and the user must hold two devices side by side for each. Kept as the universal fallback (section 8.6). |
| Deliver the new Secret Key to the Secure Enclave key of each device's biometric enrollment | The SE public key changes with `.biometryCurrentSet` and is not pinned anywhere today; open question O5. |

## 5. Device keys

### 5.1 Keys and storage

`DeviceKeys { sign: HybridSigningKey, kem: HybridKemSecret }` (existing types of `crypto/sign.rs` and `crypto/kem.rs`). `DevicePublic { device_id: Id, sign_pub: HybridVerifyingKey, kem_pub: HybridKemPublic }`. Fingerprint: `SHA-256("onepass/device-fpr/v1" || postcard(DevicePublic))`.

- **Apple:** one generic Keychain item per account, `device.<account_id>`, data-protection keychain, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, in the app's own access group, not the group shared with the AutoFill extension (the extension never signs or follows a rotation; it shows "Ouvre OnePass pour continuer"). Same protection class as the Secret Key. Read only by the unlocked app for pairing, rotation, follow and intro, each of which already requires presence (Face ID, or the master password). Never in iCloud Keychain, never in a backup restorable elsewhere.
- **Secure Enclave (O3, ruled 2026-10-30):** since iOS and macOS 26 (the app's deployment target), CryptoKit has Secure Enclave ML-DSA-87 and ML-KEM-1024 keys (`SecureEnclave.MLDSA87.PrivateKey`, `SecureEnclave.MLKEM1024.PrivateKey`). On Apple, the post-quantum half of both device keys is created in the SE and never leaves it; the Keychain item stores only its `dataRepresentation` (an SE-wrapped blob, useless on any other device) next to the Ed25519 and X25519 halves. Access control: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` with `.privateKeyUsage` only, no biometry flag, so a Face ID re-enrollment does not destroy the key (presence is already required by every flow that signs). The wire format, `DevicePublic`, the domains of 6.1 and the formal model are unchanged: a verifier cannot tell an SE key from a software key, and does not need to. Signature interop: the SE signs pure ML-DSA-87 with an empty context over `signed_message(domain, msg)`, exactly what `HybridVerifyingKey::verify` checks; ML-KEM-1024 ciphertexts are FIPS 203 on both sides. The Swift plan proves both on a real device (the simulator has no SE). Where no SE exists (simulator, CLI, a Mac without one) the half is a software key, as before. Gain: copying the Keychain item off the device no longer lets anyone sign as the device or open its key deliveries; malware must run on the unlocked device itself.
- **CLI:** `device.bin` already holds the Secret Key in clear (development CLI, `core/README.md`); the device keys go next to it, same protection. Documented, as today.
- **Fuzzing:** `DevicePublic` and every record of section 6 decode strictly (whole buffer, canonical re-encoding) and get fuzz targets.

### 5.2 Pinning at pairing (milestone 2b protocol, extended)

The pairing channel is authenticated by the SAS (spec 2b, section 5; `bridge.pv` proves the same construction). Inside it:

- **N to A**, after the SAS: new message `Message::ConfirmedWithKey { device: DevicePublic, pop: HybridSignature }` (variant added at the end of the enum), `pop` = N's device signature over `postcard((session_transcript_hash, DevicePublic))`, domain `onepass/device-pop/v1`. A refuses a `pop` that does not verify.
- **A to N**: new grant variant `Grant::FullV2(FullGrantV2)` (added at the end) = `FullGrant` plus `trust: TrustSnapshot { lineage: Vec<LineageRecord>, roster: Vec<RosterEntry>, approver: DevicePublic }`. N pins the roster and the lineage head from A: it trusts A because of the SAS, exactly as it already trusts A for the Secret Key and the snapshot.
- **A** then writes an `Intro` record (6.4) for N, in the same store transaction as the device list entry and the sealed grant (as today, spec 2b 15.6).
- Old peers: an approver that receives `Confirmed` (no key) pairs as today and N is a legacy device (section 15).

### 5.3 Local trust state

New local state `TrustState`, beside `ChainState` in the `meta` table, written in the same transaction as any record that changes it, strict versioned postcard:

```
TrustState {
  version: 1,
  account_id: Id,
  me: DevicePublic,                    // this device
  head: LineageHead { generation: u64, hash: [u8; 32] },
  identity_pub: IdentityPublic,        // the identity of `head`
  roster: Vec<RosterEntry>,            // devices trusted at `head`, sorted by id
  levels: BTreeMap<Id, TrustLevel>,    // Verified | Tofu (legacy, section 15)
  revoked: BTreeSet<Id>,               // every device revoked along the lineage, monotone
  excluded: BTreeSet<Id>,              // devices the user distrusted on this device ("Ce n'était pas moi")
  ignored: Vec<[u8; 32]>,              // rotation records the user rejected (to revisit, at most 64)
  retired: Vec<RetiredIdentity>,       // identities this device left: identity id, signing pub, generation (public data)
  own_writes: OwnWriteLog,             // section 10.4
  state: DeviceLineageState,           // section 8
}
```

Nothing in it is secret. Like `DeviceState` it is integrity-protected only by the device (hostile local storage is out of scope, as today).

## 6. Records and messages

All bodies are `postcard`, decoded strictly (whole buffer, canonical re-encoding, sorted and unique lists). Hashes are SHA-256. Every signature uses the existing framing `"onepass/sig/v1" || len(domain) || domain || message` (`crypto/sign.rs`).

### 6.1 Labels

| Label | Kind | Key | Over |
| --- | --- | --- | --- |
| `onepass/device-pop/v1` | signature domain | new device's key | `(transcript hash or account id, DevicePublic)` |
| `onepass/device-intro/v1` | signature domain | introducer's device key | `IntroBody` |
| `onepass/genesis/v1` | signature domain | creator's device key | `GenesisBody` |
| `onepass/genesis/identity/v1` | signature domain | identity (SLH-DSA) | `GenesisBody` |
| `onepass/rotation/v1` | signature domain | rotator's device key | `RotationBody` |
| `onepass/rotation/identity/v1` | signature domain | new identity (SLH-DSA) | `RotationBody` |
| `onepass/legacy-device/v1` | signature domain | account signing key of the current identity | `LegacyIntroBody` (section 15) |
| `onepass/rotation/secret-key/v1` | `wrap_key_labeled` label | recipient's device KEM key | the 32-byte new Secret Key, context `postcard((account_id, lineage_hash, recipient_id))` |
| `onepass/lineage/v1` | hash prefix | | lineage hash of a genesis or rotation body |
| `onepass/identity-id/v1` | hash prefix | | identity record id |
| `onepass/delivery-id/v1` | hash prefix | | delivery record id |
| `onepass/intro-id/v1` | hash prefix | | intro record id |
| `onepass/rotation/code/v1` | HKDF info | | 6-digit rotation code |
| `onepass/device-fpr/v1` | hash prefix | | device fingerprint |

The identity key, which today signs only `account-params` (security README 3.4), also signs the two `.../identity/v1` domains; the domains keep the three uses apart.

### 6.2 Genesis

```
GenesisBody { format: 1, account_id, identity_pub, creator: RosterEntry, created_at: i64 }
SignedGenesis { body, device_sig, identity_sig }
RosterEntry { device_id, sign_pub, kem_pub, name (<= 64 chars), kind, mode, introduced_by: Option<Id> }
```

Written by `create_account` (new accounts) or by the first migrating device (section 15). Lineage hash `h0 = SHA-256("onepass/lineage/v1" || 0x00 || postcard(body))`.

### 6.3 Rotation record

```
RotationBody {
  format: 1,
  account_id: Id,
  generation: u64,                   // parent generation + 1
  parent: [u8; 32],                  // lineage hash of the parent (genesis or rotation)
  rotator: Id,                       // in the parent roster
  reason: Revoke | Rotate | RotateWithPassword | Reapply | Finish,
  revoked: Vec<Id>,                  // sorted, unique, never the rotator, all in the parent roster
  roster: Vec<RosterEntry>,          // sorted, every device trusted afterwards, the rotator included, no revoked id, <= 64
  identity_pub: IdentityPublic,      // the new identity
  params_hash: [u8; 32],             // SHA-256 of the AccountParams record data of the new identity (epoch 1)
  keyset_hash: [u8; 32],             // SHA-256 of its Keyset record data
  deliveries: Vec<(Id, [u8; 32])>,   // recipient (roster minus rotator), SHA-256 of the envelope
  from_heads: BTreeMap<Id, SeenManifest>, // per live vault, the old-identity manifest the content was rotated from
  issued_at: i64,                    // informative, shown to the user
}
SignedRotation { body, device_sig: HybridSignature, identity_sig: SlhDsaSignature }
```

Lineage hash `h = SHA-256("onepass/lineage/v1" || 0x01 || postcard(body))`. Record `RecordKind::Lineage` (new code 10), id = `h[..16]`, version = generation, data = `postcard(LineageRecord::Rotation(SignedRotation))`; genesis uses the same kind with `LineageRecord::Genesis`. Lineage records are immutable: written with `put_if_version(None)`, never deleted by any client, deletions from the server refused by `commit_remote` (as account params today, security README 10.6).

**Rotation code**: `HKDF-SHA256(ikm = h, info = "onepass/rotation/code/v1")`, 8 bytes, modulo 10^6, shown as `482 913` on the rotator and on every confirmation screen (section 9).

### 6.4 Intro

```
IntroBody { format: 1, account_id, head: [u8; 32], entry: RosterEntry, introducer: Id, pop: HybridSignature }
SignedIntro { body, sig }   // introducer's device key, onepass/device-intro/v1
```

`pop` is the new device's signature over `postcard((bytes(account_id), DevicePublic { entry.device_id, entry.sign_pub, entry.kem_pub }))`, domain `onepass/device-pop/v1`: the single proof-of-possession form of 6.1 (`sign_pop` with the account id as context), shared with pairing, where the context is the transcript hash. Record `RecordKind::DeviceIntro` (11), id = `SHA-256("onepass/intro-id/v1" || postcard(body))[..16]`, immutable. A device accepts an intro if `head` is its current head, the introducer is in its roster, not revoked or excluded, both signatures verify and the id is new (never revoked, never in the roster with another key). The new entry then joins its roster at that head. An intro under an older head is not carried over: the rotator includes in its roster every device it trusts, and after an adoption each device re-introduces the devices it introduced itself that the new roster misses (8.5).

### 6.5 Secret Key delivery

`RecordKind::KeyDelivery` (12), id = `SHA-256("onepass/delivery-id/v1" || h || recipient_id)[..16]`, data = `wrap_key_labeled(recipient kem_pub, label "onepass/rotation/secret-key/v1", context postcard((account_id, h, recipient_id)), new Secret Key)`. Immutable. The envelope hash is in the rotation body, so a substituted envelope is refused before any decapsulation. The revoked device is never a recipient.

### 6.6 Identity-keyed account records

For generation 0 (genesis or legacy) nothing moves: `AccountParams`, `Keyset`, `RestoreEpoch`, `DeviceList`, `VaultList` keep id = account id. From generation 1 they use id = `identity_id = SHA-256("onepass/identity-id/v1" || identity_pub)[..16]`. Two sibling rotations therefore never overwrite each other's params or keyset (the source of hold-outs 1, 2 and `zz1`, `zz2`). A device reads the records of its own identity only; records of any other identity are ignored unless a lineage record it accepted names that identity.

Params format unchanged (`OPP2`, epoch). The epoch now counts password changes **within one identity**, starting at 1 for each new identity; epochs of different identities are never compared (this keeps P1 of the first design in a simpler form: nothing of a left identity can block or outbid anything). Keyset: format `OPK3`, `OPK2` plus `retired_kem: Vec<HybridKemSecret>` (at most 16, newest first): the KEM secrets of the identities this one replaced, to open account-bound archives and travel states made before (R18). Retired signing and identity keys are never carried.

### 6.7 Vault content

Unchanged formats. A vault keeps its id and its single-slot records (`VaultKey`, `VaultMeta`, `Manifest`, id = vault id); items get new record ids at every version, as today. Under the new identity the first manifest of a vault has `prev_hash = from_heads[v].hash` and `seq = from_heads[v].seq + 1`, signed by the new signing key.

## 7. Flows

### 7.1 Rotate (on the rotating device R)

Triggers: "Retirer cet appareil" (always rotates, `reason = Revoke`), "Faire tourner les clés" (`Rotate`), "Changer le mot de passe" with "Faire aussi tourner les clés" (`RotateWithPassword`).

Preconditions (refused otherwise, nothing written): session unlocked; fresh presence and the master password (already asked by the app); Travel Mode off (K8 kept); a full sync just done; every live vault of the signed vault list loads through the verified path (`VaultMissing` or any integrity error refuses, R22); the device is in state `Current` and holds its device keys; every device to revoke is in the roster and is not the rotator; the new Secret Key differs from the current one (K11 kept).

Steps, all built in memory first:

1. New Secret Key (from the caller, stored as pending in the Keychain before the call, K6 kept), new identity, signing and KEM keys, new Argon2id salt (costs = max(current, floor)), new params (epoch 1) signed by the new identity, new keyset `OPK3` sealed under `AUK(password, new Secret Key, new params)`, with the current KEM secret prepended to `retired_kem`. Proof that the pair opens (as the first design).
2. Roster = current roster minus revoked minus excluded; one `KeyDelivery` per roster member except R.
3. For every live vault: new vault key wrapped for the new KEM key, meta resealed, every listed item (live, archived, trash) resealed under a fresh item key at version + 1, next manifest signed by the new signing key (6.7). `from_heads` records the manifests loaded.
4. Device list and vault list re-signed by the new signing key at seq 1 under the identity id; the device list marks the revoked devices.
5. Rotation body, device signature, identity signature.
6. **One local transaction** (`put_all_if_version_and_delete`, kept from the first design): all records, the new `TrustState` (head = h, roster, revoked += revoked, `retired` += old identity, state `Rotating { phase: 1 }`). Before it nothing is written; after it the call succeeds whatever follows (K12 kept).

Push (CloudKit), in phases, each a set of conditional writes:

- **Phase 1**, all new ids, so no conflict is possible: deliveries, identity-keyed params and keyset, lists, then the lineage record last. A device acts on a lineage record only when everything it names that it needs (its delivery, params, keyset) is present and hash-matches; until then it waits.
- **Phase 2**, per vault, the existing order: vault key, meta and items, then the manifest. The single-slot records hold either old-identity content (an old manifest that verified at step 3) or a sibling identity's content: R overwrites them conditionally on the version it reads (R21). A manifest signed by an identity R does not know is not an integrity alert for R in state `Rotating`.
- **Phase 3**, after phase 2 is confirmed: delete the old item records listed in the `from_heads` manifests, and nothing else (R23).

State `Rotating { phase }` is durable; a cut resumes at the phase reached. When phase 3 is confirmed the state is `Current`. The rotator shows the new Emergency Kit and the rotation code right after step 6.

### 7.2 Follow (on a remaining device D)

D reads a lineage record whose parent is its head. It computes, without unlocking:

- **valid**: the rotator is in D's roster, not in `revoked` or `excluded`, `generation` and `parent` match, `revoked` and `roster` are well formed (6.3), both signatures verify (device key from D's local roster, never from the record or the server; identity signature under `identity_pub`).
- **for me**: D is in `roster` (else `Orphaned`, 8.6), D is not in `revoked` (else quarantine, 8.4).
- **complete for me**: D's delivery, the params and the keyset are present and hash-match.

Then (section 8 for several records) D enters `Candidate` and shows the confirmation screen (section 9). On "C'est moi" and the master password:

1. open the delivery with D's device KEM key (the app reads it from the Keychain after presence), giving the new Secret Key;
2. verify the params under `identity_pub` (G8), derive the AUK, open the keyset, check its three public keys against the params and its identity against the record;
3. **one local transaction**: new `TrustState` (head, roster, revoked, `retired` += left identity), `ChainState` pins reset for the new identity (params epoch 1, lists unseen), `last_seen[v] = from_heads[v]` for every vault in `from_heads` (R12), own writes queued for replay (10.4);
4. Secret Key promoted in the Keychain, biometric enrollment recreated from the new AUK, session opened on the new identity;
5. replay of own writes, then normal sync.

Normal unlock (`unlock`, `unlock_with_auk`) never follows a lineage record (K9 kept in spirit): only this flow does, and it always needs the user.

### 7.3 Password change within an identity

As milestone 2b (B1), on the identity-keyed records, epoch + 1. Every params record read from the server is decoded, then verified under the identity of the device's head before it can change anything (G8); an unverified record is ignored and logged. A password change pending on a device that then follows a rotation is not lost silently: the follow screen says "Tu avais changé ton mot de passe sur cet appareil. L'appliquer aux nouvelles clés ?" and re-applies it as epoch 2 of the new identity on yes.

### 7.4 Pairing after a rotation

Unchanged for the user. The approver sends its trust snapshot (5.2); the newcomer pins it. A device that missed a rotation can always be re-paired from a device on the latest head: the grant carries the Secret Key and the snapshot, so re-pairing is the universal exit (8.6). Re-pairing a device that already holds this account (same account id) must not go through the empty-store import of milestone 2b (ruling A9), which would drop its unsynced data: the grant is applied as a follow (the user confirms the approver's head shown from the trust snapshot, then the master password), the local data stays and own writes are replayed (10.4, task 13).

### 7.5 Emergency Kit restore

On a device with no pins (new device, or after "Restaurer avec mon Emergency Kit"):

1. Read the lineage records and every identity-keyed params and keyset record.
2. Find the identity whose keyset opens under the kit's Secret Key and the typed password (2SKD; for generation 0, the legacy records).
3. That identity is introduced by a genesis or rotation record carrying its identity signature: verify it, then pin its roster and head. The device has no device key pinned, so the identity signature is what authenticates the roster (R14); the identity is authenticated by 2SKD.
4. **Outdated kit:** if the identity has children in the lineage (valid identity signatures, rotators in its roster), the kit is outdated: "Cet Emergency Kit n'est plus à jour : les clés ont changé le 28 oct. sur iPhone de Quentin. Utilise le dernier kit, ou ajoute cet appareil depuis un appareil que tu as encore." No continue button. If the server hides the children, the restore lands on the old identity, which the revoked device also controls: documented limit (section 11), shown in the formal model (`restore_old`).
5. The restored device then registers itself. No trusted device can introduce it, and it must not rotate (that would cut the remaining devices off). It writes a self-introduction: an `Intro` with `introducer = self`, signed by its own device key and also by the identity (same domain `onepass/device-intro/v1`, identity key). The remaining devices hold the identity public key, verify it, and show "Nouvel appareil restauré avec l'Emergency Kit : <nom>. Faire confiance ?"; they pin it only on the user's yes (R14). The revoked device cannot produce such an intro: it does not hold the current identity.

## 8. Device state machine, races and stuck states

### 8.1 States

| State | Meaning | Can write? |
| --- | --- | --- |
| `Legacy` | no device key yet (paired before this design) | yes, under the current identity |
| `Current { head }` | normal | yes |
| `Candidate { head, children }` | at least one valid child of `head` is known, not yet decided by the user | **no**: read-only (R10) |
| `Rotating { head, phase }` | this device made `head`, pushing phases 1 to 3 | yes, under the new identity |
| `Quarantined { head, by, since }` | a valid child of `head` revokes this device, first read at device time `since` | no; locked, biometric enrollment deleted, erased at `since` + 7 days |
| `Orphaned { head, child }` | a valid child of `head` does not list this device | no; local data readable after unlock |

### 8.2 Transitions

| From | Event | To | Automatic? |
| --- | --- | --- | --- |
| `Legacy` | unlock after update | `Current` (genesis or legacy intro, section 15) | yes |
| `Current` | valid child, for me | `Candidate` | yes (it only blocks writes and shows the screen) |
| `Current` | valid child revoking me | `Quarantined` | yes (lock only) |
| `Current` | valid child without me | `Orphaned` | yes |
| `Current` | user rotates | `Rotating { phase: 1 }` | user |
| `Candidate` | user confirms child X, password | `Current { head: X }` | user |
| `Candidate` | user: "Ce n'était pas moi" for child X | `Current` if no other child, signer of X added to `excluded`, X added to `ignored` | user |
| `Candidate` | user: "Retirer <signer> et faire tourner les clés" | `Rotating` (sibling of X, revoking X's signer) | user |
| `Rotating` | phase 3 confirmed | `Current` | yes |
| `Rotating` or `Current` | valid sibling S of own head wins the order (8.5) | `Candidate { children: [S] }` with the switch explained | yes (blocks writes) |
| `Quarantined` | user: "Effacer cet appareil" | erased (as spec 2b A5) | user |
| `Quarantined` | device time reaches `since` + 7 days, checked at launch and on the quarantine screen | erased | yes |
| `Quarantined` | user: "Ce n'était pas moi", password | `Current`, signer excluded, offer to remove it | user |
| `Orphaned` | an intro for me under the child, from a trusted device | `Candidate` | yes |
| `Orphaned` | re-pair or Emergency Kit | `Current` | user |
| any | "Restaurer avec mon Emergency Kit" | section 7.5 | user |

A lineage record whose parent is not the head is never a child; it is either old (generation at most the head's, on the device's own chain: ignored), a sibling of an ancestor (8.5), or unknown (ignored until its parent is known).

### 8.3 The race: A revokes B, B revokes A

B is lost; the user revokes it from A. A's record R_A (signer A, revokes B). The attacker signs R_B (signer B, revokes A, its own identity, its own Secret Key delivered to C).

- **On A**: B is in `revoked` the moment A commits R_A. R_B is signed by B: invalid. A keeps its rotation and pushes it whatever the server holds; nothing on the server can make A abandon anything (hold-out 1 is closed: there is no "complete wins" contest).
- **On C, R_A seen first**: confirmation "iPhone de Quentin a retiré iPad de Quentin", the user confirms, B is revoked, R_B is invalid from then on.
- **On C, R_B seen first, R_A withheld**: confirmation "iPad de Quentin a retiré iPhone de Quentin". The user did not do this: "Ce n'était pas moi" excludes B on C; C returns to `Current` and offers "Retirer iPad de Quentin et faire tourner les clés". If the user does that, C's record and R_A are honest siblings, settled by 8.5.
- **On C, both seen**: R_A revokes B, R_B revokes A: **mutual exclusion**. C asks "Deux appareils se sont retirés l'un l'autre. Lequel as-tu encore en main ?" with both names and "Aucun des deux". The choice excludes the other signer.
- **What never happens**: C never moves to R_B without the user confirming a summary that names B as the rotator and A as removed; A never moves to R_B at all; no device erases or drops anything. `rotation.pv` proves that C never adopts any record signed by B when the user only did "A revokes B", and `rotation_autofollow.pv` shows that without the user step C adopts R_B.

A record signed by B that does not revoke A (B rotates "for itself") is excluded on any device that knows R_A (R_A revokes its signer), and needs the user on any device that does not.

### 8.4 Reading one's own revocation

A valid child that revokes this device may be honest (the user removed this device, maybe lost) or forged by a device the user has not removed yet. The device therefore does not erase itself at once (this changes rulings B6 and A5 of milestone 2b): it locks, deletes its biometric enrollment, records `since` (its own clock), and shows "iPhone de Quentin a retiré cet appareil le 28 oct. Il sera effacé le 4 nov. Si c'est toi, efface-le maintenant. Sinon, garde-le et retire plutôt iPhone de Quentin." Until then the local database stays encrypted under the old keys, which the revoked device's finder cannot use without the master password. Erasing now is a button; after 7 days the device erases itself (R8, O1 ruled 2026-10-30). "Ce n'était pas moi" with the password cancels the erase. Only a valid lineage record triggers this path (device signature from the local roster and identity signature, resolver decision `Quarantine`); nothing else read from storage or the server ever erases. A clock moved back only delays the erase; it never brings it forward. The same rule now applies to the account-signed device list: a `revoked_at` there no longer erases anything, since today any holder of the account signing key (including a device revoked under milestone 2b) can sign such a list.

### 8.5 Honest concurrency and convergence

Siblings are valid lineage records with the same parent. For a device, among the siblings it knows:

1. **Exclusion**: sibling X excludes sibling Y if `X.revoked` contains `Y.rotator`. Exclusion is settled as a grounded fixpoint: a sibling that no other sibling excludes is accepted; a sibling excluded by an accepted sibling is rejected, and its own exclusions no longer count; siblings left undecided (a cycle such as "A revokes B" and "B revokes A") give a `Mutual` prompt where the user chooses (8.3), even when an accepted third sibling exists. Only accepted siblings enter the order of step 2. (Read literally, "excluded by another, never recommended" let a record signed by B decide between honest siblings and left two followers on different heads; the property test of task 4 shows it.) A cycle that includes a sibling revoking this device also gives the `Mutual` prompt, never a quarantine: a forged revocation must not start the erase clock while an honest alternative exists.
2. **Order**: among siblings not excluded, the one with the smallest lineage hash is the winner. The order is a pure function of the records, so the server cannot choose it, only delay it; it cannot be ground by the attacker either, because the attacker's siblings are excluded by the honest revocation or need the user.
3. **Branches**: two branches are compared at their first divergence; the winning branch's newest descendant the device can validate is the target.
4. **Switch**: a device whose head is on a losing branch goes to `Candidate` for the winner's newest descendant ("iPad de Quentin a aussi fait tourner les clés au même moment. OnePass garde un seul jeu de clés : saisis ton mot de passe pour continuer avec celles de iPad de Quentin. Les changements faits sur cet appareil sont gardés."). Its own writes are replayed (10.4).
5. **Re-application**: a device whose own rotation lost re-applies, as a `Reapply` child of the winner's tip, the removals the winner's `revoked` lacks; a password change is re-applied as a params epoch (7.3). Re-application is part of the same user step as the switch.

**No livelock (G6).** Siblings are created only by user actions (honest) or by excluded or user-rejected signers. Settling a divergence never creates a sibling at that divergence: switches move to an existing record, re-applications create children of the winner's tip. Each re-application covers at least one pending removal of a losing rotator or is dropped when the winner already covers it, so the set of uncovered removals strictly shrinks; the process ends once every device has seen the same records. A device switches at most once per divergence point once it has seen both sides; the server can delay that moment, never make it oscillate. An attacker-signed record costs the user at most one "Ce n'était pas moi" per signer, after which the signer is excluded on that device. Hold-out 2 is closed: B cannot postpone A's revocation on A (local and immediate), nor on another device except by the server withholding A's record, which is T2 denial of service; section 8.6 gives the exit (re-pair).

Not proved in ProVerif (stateful ordering); proved by a property test over interleavings in the plan (task 4).

### 8.6 Stuck states and their exits

| Stuck state | Exit |
| --- | --- |
| Device paired before device keys, rotation arrives before it ever unlocked after the update (`Orphaned` or `Legacy`) | re-pair (QR, SAS: carries Secret Key and trust snapshot) or Emergency Kit |
| Biometric-only device (hold-out 3) | none needed: delivery to its device key, then the master password once, then biometry re-enrolled. No "known Secret Keys" memory any more |
| Device not in the winner's roster (paired concurrently) | its introducer re-introduces it under the new head automatically; otherwise re-pair or kit |
| Rotator lost after phase 1 (identity adopted, content not pushed) | followers keep reading their local copy; any of them can run a `Finish` child rotation from its own copy, allowed only for vaults whose local head equals `from_heads` (password asked) |
| Deliveries or records withheld by the server | after 24 h in `Candidate` without completeness: "Les nouvelles clés n'arrivent pas. Ajoute de nouveau cet appareil depuis iPhone de Quentin." (re-pair) |
| Quarantined by a forged record | "Ce n'était pas moi" with the password, within 7 days |
| Mutual revocation | user picks the device they still hold |
| User excluded an honest device by mistake | Réglages > Sécurité > "Rotations ignorées": revisit and confirm; or re-pair that device |
| All remaining devices lost | latest Emergency Kit on a new device (7.5) |
| Only an outdated kit, no device | refused when the rotation is visible; nothing else can help (by design: the old kit is what the revoked device has) |
| Cut on the rotator between commit and push | resumes from `Rotating { phase }`; Secret Key pending in the Keychain (K6, K12 kept) |
| Cut on a follower during adoption | one transaction: before it nothing changed, after it the new head is pinned |
| Password forgotten | no exit, as today (2SKD) |

### 8.7 What never happens silently

- A device never adopts an identity without the user's confirmation on that device and the master password.
- A device never erases itself or drops local items, pending writes or own writes because of anything it reads, except the erase 7 days after a valid lineage record revoked it (8.4).
- A device never treats a record signed by an account key, or anything from the server, as proof of a rotation.
- A Secret Key is never typed to follow a rotation (only to restore from a kit).

## 9. User-visible flows (app texts in French, the app's language)

- **Rotator, after "Retirer cet appareil"**: presence, password, then "Retrait en cours…" and, after the local commit: the new Emergency Kit to save and confirm (as at creation), the rotation code, "Tes autres appareils te demanderont de confirmer avec ce code et ton mot de passe." Réglages > Appareils shows each remaining device as "à jour" or "en attente" (from the lineage head it last introduced or acknowledged, open question O6).
- **Follower, confirmation**: title "Les clés de ton compte ont changé"; text "iPhone de Quentin a fait tourner les clés le 28 oct. à 14:02 et a retiré iPad de Quentin." (names from the local roster, never from the record); "Code de rotation : 482 913, le même s'affiche sur iPhone de Quentin."; buttons "C'est moi" and "Ce n'était pas moi", same weight, no default. "C'est moi" asks the master password. While the screen is pending, the app reads but does not write (banner "Lecture seule jusqu'à ta réponse").
- **Rotator signed by a legacy (TOFU) device**: extra line "Cet appareil n'a pas été vérifié depuis la mise à jour." (section 15).
- **"Ce n'était pas moi"**: "OnePass ne fait plus confiance à iPad de Quentin sur cet appareil. Retire-le de ton compte pour couper son accès." with "Retirer et faire tourner les clés" (password) and "Plus tard".
- **Mutual revocation, quarantine, orphaned, outdated kit, keys not arriving**: texts in sections 8.3, 8.4, 7.5, 8.6.
- **Switch after honest concurrency**: text in 8.5.

## 10. Interactions

### 10.1 Signed device and vault lists

They stay (display, renames, vault list completeness) and are re-signed by the new signing key under the identity id. Trust decisions (who may sign a rotation, who receives the Secret Key, who is revoked) come from the lineage and the local `TrustState` only. `revoked_at` in the device list is derived from the lineage and no longer triggers an erase (8.4). Adoption of unlisted vaults (B7) is restricted to vaults whose manifest is signed by the device's current identity.

### 10.2 Restore epochs

Not used by rotations any more: the rotation record carries `from_heads` and acts as the epoch for that step (R12). The `KeyRotation` reason of the first design is dropped. Restore epochs (backups, alerts) are identity-keyed and numbered from 1 per identity; epochs of a left identity are ignored (closes `zz2_hostile_epoch_inflation` and the epoch wedge).

### 10.3 Manifests

Signed by the identity's signing key. After adoption `last_seen[v] = from_heads[v]`, so the first manifest of the new identity chains normally (6.7). A manifest signed by any other key is refused as today (`Signature`), except the two cases of R21 (rotator in `Rotating` overwriting foreign content, never reading it).

### 10.4 Own writes and replay (G4)

`OwnWriteLog`: per vault, the item intents this device wrote (pending or confirmed) since the last head it adopted, with the old-identity manifest they were based on. After an adoption or a switch, every own write not reflected in the new content (based on a manifest newer than `from_heads[v]`, or still pending) is decrypted with the keys it was written with (still on the device: the retired keyset, kept sealed under the current AUK in local meta until the replay is done) and replayed under the new keys through the normal rebase path. Writes by other devices made under the old identity after `from_heads` are not imported: they could be the revoked device's forgeries, and their authors replay them (R11). Bounded to 30 days and 10 000 intents; beyond that the device keeps the local copy and shows an alert with "Réimporter depuis cet appareil".

### 10.5 CloudKit push order

Section 7.1. The batch limits (400 records, 1.5 MiB) split each phase in that order. Phase 1 has no conditional conflicts by construction. Pending writes of other kinds wait while the device is `Rotating { phase: 1 }`.

### 10.6 Travel Mode

Rotation refused while Travel Mode is on (K8 kept). A follower in Travel Mode may adopt: its `TravelState` was sealed for the old identity's KEM key, which the new keyset carries in `retired_kem`, and is signed by the old signing key, kept as public data in `retired`. `travel off` then copies the parked vaults from the server under the new identity and uses `from_heads` instead of the parked `last_seen` for every vault the rotation covered.

### 10.7 Archives and backups

Account-bound archives made before a rotation: their key opens with `retired_kem`; their signature verifies under a retired signing key from `TrustState.retired`, and the restore screen says "Sauvegarde faite avant le changement de clés du 28 oct." (the revoked device can forge such files, so the user is told, R18). Passphrase exports unchanged. `backup restore` never restores account records or lineage: it imports content under the current identity, as `restore_plan` does today.

### 10.8 CLI

The CLI keeps its device keys in `device.bin`. It can rotate (`account rotate-keys`, `account remove-device`). It has no pairing, so it follows a rotation made elsewhere only through the Emergency Kit path (7.5). Documented.

### 10.9 AutoFill extension, Watch, widgets, public sessions

The extension never follows a rotation and never holds device keys; in `Candidate`, `Quarantined` or `Orphaned` it shows "Ouvre OnePass pour continuer". The Watch payload, widgets and glance do not use account keys (security README 13); the phone rebuilds them after adoption. Public sessions are refused outside `Current`.

## 11. Limits

- The past is not protected: what the revoked device decrypted, or can decrypt from old ciphertexts a hostile server keeps.
- A user who confirms a rotation naming a device they no longer hold adopts the attacker's identity on that device (formal negative control `rotation_autofollow.pv` shows what happens without the user step; with it, the user is the arbiter).
- An outdated Emergency Kit plus the password, with a server hiding the rotation, restores into the old identity, which the revoked device also controls (`rotation.pv`, `restore_old`, expected false). After a rotation the app asks to destroy old kits.
- Legacy devices are trusted on first use at migration (section 15) until verified.
- Server denial of service delays following; the exit is re-pairing.
- Each rotation rewrites every vault (as the first design).
- Writes by other devices under the old identity after the rotator's snapshot reach the new identity only when their author follows and replays them.
- A revoked device that writes "B revokes A" before the user removes it quarantines A; if nobody answers A's screen within 7 days, A erases itself and its unsynced writes are lost (O1). The user's other devices still see the record as a prompt naming B, so the exit is "Ce n'était pas moi" on any of them, then removing B.

## 12. Attack catalogue (reviewer repros) under v2

| Repro or round | v2 outcome |
| --- | --- |
| `zz4_revoked_device_fake_complete_rotation_beats_a` | B's record is signed by B: invalid on A (B revoked). A never abandons anything. On C it needs the user, who sees "iPad de Quentin a retiré ..." and refuses. No Secret Key is ever typed to follow. |
| `zz5_two_incomplete_rotations_alternate` | No completeness contest; identity-keyed records do not overwrite each other; the order of 8.5 settles both in one switch per device. |
| `zz_biometric_device_has_no_known_keys`, `zz6_updated_device_follows_legit_rotation` | No known-keys memory: the device follows through its device key and the password; a forged record signed by the old key path does not exist any more. |
| `zz_revoked_device_wedges_rotation_with_epoch_jump`, `zz2_epoch_drop_reopens_pair_drop`, `zz2_hostile_epoch_inflation` | Params and epochs are per identity; nothing of the left identity is ever compared or obeyed. |
| `zz1_concurrent_password_change` | The password change lives on old-identity records, never overwrites the rotation's records, and is offered for re-application after following (7.3). |
| `zz3_two_concurrent_rotations` | Honest siblings: 8.5. The loser's writes are replayed. |
| Hold-out 4, unverified params | G8, 7.3. |
| `unlock_after_rotation` argument order | API removed; follow takes no Secret Key argument. |
| Device list signed by a 2b-revoked device marking A revoked (new finding while designing) | lists no longer erase anything (8.4, 10.1). |

## 13. Formal model

Files: `formal/proverif/rotation_core.pvl` (shared declarations and processes), `rotation.pv`, `rotation_autofollow.pv`, `rotation_account_anchor.pv`. Run by `make formal` like the others; results in `formal/expected.txt` and `docs/security/formal/results.md`.

Modeled: device signing and KEM keys pinned through a private setup (the SAS channel); the attacker holds the revoked device's device keys, the master password and the old Secret Key; rotation record with device and identity signatures; identity-keyed params; keyset under `AUK(password, new Secret Key)`; delivery to the device KEM key; the follower's checks; the user's confirmation as a private table of what the user really did; a vault and an item written after the rotation by the rotator and by the follower; a second-generation rotation by the follower, adopted by the first rotator; Emergency Kit restores with the latest and an outdated kit.

| Property | Query | Result |
| --- | --- | --- |
| G1 items written after rotation secret from the revoked device | `ItemSealedNew && attacker` | true |
| new Secret Key and new identity secret | `Rotated && attacker(k)`, `attacker(ik)` | true, true |
| G2 adoption only of identities introduced by an honest device | `Adopt ==> Rotated` | true |
| forged rotation fails on A (which revoked B) and on C (which still pinned B), so the race never ends on B's identity | `not Adopt(devA, devB)`, `not Adopt(devC, devB)` | true, true |
| substituted vault key never accepted | `VaultAcceptedNew ==> VaultCreatedNew` | true |
| latest kit pins only an honest roster | `PinRoster(restore_new) ==> Rotated` | true |
| outdated kit (documented limit) | `PinRoster(restore_old) ==> Rotated` | false, by design |
| negative control: no user step | `rotation_autofollow.pv`, `Adopt ==> Rotated`, `not Adopt(devC, devB)`, secrecy | false (attack found), by design |
| negative control: account-key anchor | `rotation_account_anchor.pv`, `Adopt ==> Rotated`, secrecy | false (attack found), by design |
| sanity: C follows A, A follows C, vault accepted, item written, kit restore | reachability | reached |

`rotation.pv` takes about 130 s on the owner's Mac (limit 300 s per file in `formal/run.sh`); the two controls take about a second. The whole `make formal` run matches `expected.txt`, the earlier models unchanged.

Not modeled: sibling ordering, re-application and convergence (state, covered by a property test, task 4); quarantine; intros and the pairing extension (the pairing channel itself is `bridge.pv`'s construction); legacy migration (TOFU, out of the proof by definition); phase ordering on CloudKit; own-write replay; the 6-digit code (the user's confirmation is modeled as comparing the summary, the code is extra).

## 14. What the first design keeps and replaces

| Item of `fix/key-rotation` | v2 |
| --- | --- |
| K1 all three keys and the Secret Key rotate | kept |
| K3 vault keys rotate, every item resealed | kept (code reused: `repo/rotation.rs` vault pass) |
| K5 one local transaction (`put_all_if_version_and_delete`) | kept; the restore epoch part replaced by `from_heads` (R12) |
| K6 caller supplies the new Secret Key, pending in the Keychain | kept |
| K8 refused in Travel Mode | kept |
| K11 new Secret Key must differ | kept (the follow half dropped: no Secret Key argument) |
| K12 never fail after the write | kept |
| `Account::rotate`, CLI `account rotate-keys` | kept, adapted to `OPK3` and identity-keyed records |
| K2 no new format, no link | replaced: lineage records, device-key and identity signatures |
| K4 no automatic delivery | replaced: delivery to device KEM keys (R4), re-pairing as fallback |
| K9 normal unlock never follows | kept in spirit: only the confirmed follow flow does |
| K10, K13, K14, K16, K17, K19, P1, P3 (pair-first push, rotation marker, reissue, overtaken flags, first complete wins) | removed: identity-keyed records and the lineage make the contest disappear (R3, R20) |
| K15, K18, K20, P2 (known Secret Keys memory) | removed: device keys replace it (R20) |
| `unlock_after_rotation`, `keys_rotated`, `RotationOvertaken`, `password_change_overtaken`, `note_secret_key` | removed; replaced by `pending_rotation`, `follow_rotation`, `reject_rotation` (section 18) |
| erase on revocation (2b B6, A5) | replaced by quarantine, then erase after 7 days (R8) |

The implementation starts again from `main` and ports the kept parts; `fix/key-rotation` stays as a reference and is not merged.

## 15. Migration

Accounts and devices from before this design have no lineage and no device keys.

1. On the first unlock after the update (password or Face ID: both open a Rust session), a device creates its device keys.
2. If the account has no lineage, the device writes a **legacy genesis**: `GenesisBody` for the current identity (generation 0, ids unchanged), signed by its new device key and by the current identity. It is trusted on first use: a device revoked under milestone 2b, or a thief holding the account keys, could race to write a genesis of its own. Rule: among genesis records for the account, a device accepts the one whose creator is itself, else the one with the smallest hash whose creator is not revoked in the account-signed device list; a second genesis seen later is an alert, never followed silently.
3. Every other legacy device publishes a **legacy intro**: `LegacyIntroBody { account_id, genesis_hash, entry, pop }` signed by its device key (`pop`) and by the account signing key of the current identity (domain `onepass/legacy-device/v1`). Accepted only for a device id present and not revoked in the account-signed device list, once per id; two different keys for one id put that id in `excluded` everywhere until verified.
4. Legacy entries have level `Tofu`. **"Vérifier mes appareils"** (Réglages > Appareils) runs the pairing QR and SAS between two devices with no grant, exchanges `DevicePublic`, and upgrades both to `Verified`. A rotation signed by a `Tofu` device carries the warning of section 9.
5. If the account-signed device list has a device revoked under milestone 2b and no rotation followed, every device shows once: "Un appareil retiré garde encore les clés de ton compte. Fais tourner les clés maintenant." (F1 for existing accounts.)
6. New accounts write a genesis at creation; devices paired with the extended protocol are `Verified`.

Open question O4: if no account in use has more than one device yet, skip steps 2 to 4 and ask legacy multi-device users to re-pair.

## 16. Rulings

Format: decision - why - cost if wrong.

- **R1** Trust anchor = per-device keys pinned through the SAS pairing channel, plus the user; never an account key, never the server - the revoked device holds every account secret, so only keys it lacks and the user's memory can tell real from forged (section 1, `rotation_account_anchor.pv`) - device keys to manage and migrate (section 15).
- **R2** A rotation record is accepted only as a child of the device's head, signed by a rotator in its local roster that is neither revoked nor excluded - pins come from pairing, the server only carries records - a device that missed intros cannot validate records signed by devices it never pinned (re-pair).
- **R3** Account records of generation 1 and later are keyed by identity id; the new identity signs the rotation record too (proof of possession) - sibling rotations never overwrite each other's params or keyset (hold-outs 1, 2, `zz1`, `zz2`), and nobody can claim someone else's new identity - more record ids; generation 0 keeps the old ids.
- **R4** The new Secret Key is delivered sealed to each remaining device's KEM key; a Secret Key is typed only to restore from a kit - closes the "type the attacker's Secret Key" exit and strands no biometric-only device - a hostile server can withhold deliveries (re-pair).
- **R5** Every adoption of a new identity is a user step on that device (summary from local pins, rotation code, master password); never automatic - without it the race of 8.3 ends silently on the attacker's side on any device that has not yet seen the honest record (`rotation_autofollow.pv`) - one confirmation per device and rotation, which the password entry needed anyway.
- **R6** The user arbitrates races: mutual exclusion asks which device they still hold; "Ce n'était pas moi" excludes the signer locally and offers to remove it - the device cannot tell the two records apart, the user can - a user who answers wrong adopts the attacker's identity (limit 11).
- **R7** Never drop local data automatically: own writes are replayed after any adoption or switch, under the new keys - G4 - a replay log to keep (bounded, 10.4).
- **R8** A device that reads its own revocation in a valid lineage record is quarantined (locked, biometric enrollment deleted, data kept encrypted) and erases itself 7 days later unless the user answers "Ce n'était pas moi"; the account-signed device list never erases - a lost device must not keep data forever, and a forged record must leave the user a window to object - a forged record nobody answers for 7 days destroys that device's unsynced data (O1, ruled 2026-10-30).
- **R9** Honest concurrent rotations: exclusion first, then the smallest lineage hash; losers switch with the user and re-apply uncovered removals as a child of the winner's tip - deterministic, server-independent, no livelock (8.5) - two confirmations on each device in the rare case of two concurrent rotations.
- **R10** `Candidate` is read-only - writing under the old keys while a real revocation is pending would hand new secrets to the revoked device - an attacker-signed record blocks writes until the user answers once.
- **R11** Nothing signed by a left identity is accepted as new content; each device replays only its own writes - the revoked device can sign under the left identity - other devices' late writes wait for their authors to follow.
- **R12** The rotation record's `from_heads` replaces the `KeyRotation` restore epoch; adoption sets `last_seen` from it - one signed, confirmed source of truth instead of an epoch the revoked device or the server could replay or inflate - none.
- **R13** Every params record is verified under an identity of the device's lineage before any use; unverified records are ignored - hold-out 4 - none.
- **R14** Emergency Kit restore pins the roster through the identity signature on the lineage record; an identity with visible children is an outdated kit and is refused; a kit-restored device is pinned by others only on the user's yes - 2SKD authenticates the identity, the identity authenticates the roster (`rotation.pv`, `restore_new`) - an outdated kit with a server hiding the rotation lands on the old identity (limit, `restore_old`).
- **R15** Device keys are hybrid (ML-DSA-87 + Ed25519, ML-KEM-1024 + X25519); on Apple the ML-DSA-87 and ML-KEM-1024 halves are Secure Enclave keys, the classical halves and the SE blobs sit in the Keychain, `WhenUnlockedThisDeviceOnly`, app-only access group - same post-quantum stance as the account keys, and since iOS/macOS 26 the SE holds exactly those two algorithms, so no new primitive and no format change - malware on the unlocked device can still use the keys there, but nothing copied off the device can (O3, ruled 2026-10-30).
- **R16** Pairing carries device keys inside the SAS channel (`ConfirmedWithKey`, `Grant::FullV2` with a trust snapshot) and the approver writes a signed intro - the SAS already authenticates that channel - an old approver pairs a legacy device.
- **R17** Migration by legacy genesis and legacy intros, trusted on first use, upgraded by a SAS verification; conflicting claims are excluded; existing 2b revocations prompt a rotation - no forced re-pairing - TOFU window for a device already stolen before the update (O4).
- **R18** The new keyset carries the retired KEM secrets (at most 16), never retired signing or identity keys; archives signed by a retired key open with a warning - old backups and travel states stay readable; the revoked device already holds those KEM keys - a forged old-key archive file can be imported if the user accepts the warning.
- **R19** Rotation refused in Travel Mode on the rotator; a follower in Travel Mode adopts and `travel off` uses `from_heads` - travel state is bound to the old keys - none.
- **R20** The sync contest of the first design (K10, K13, K14, K16, K17, K19, P1, P3) and the known-keys memory (K15, K18, K20, P2) are removed - they tried to decide from data the attacker also produces - code to delete, tests to port as attack regressions.
- **R21** In state `Rotating`, the rotator overwrites single-slot vault records holding old-identity or sibling-identity content; item records sealed under another vault key are ignored as leftovers and collected by the winner - otherwise a losing sibling's content blocks the winner's vaults - a server injecting garbage records is no longer an integrity alert for unlisted records of foreign key generations (it never could change what is shown).
- **R22** A rotation requires a full sync and a verified load of every live vault; any integrity error refuses it - the rotator must not rotate a partial or forged view - a server hiding a vault blocks rotation (alert, re-try after the integrity screen).
- **R23** Old item records are deleted only after phase 2 is confirmed, and only those listed in the `from_heads` manifests - never delete content a sibling or a follower may still need - old ciphertexts stay on the server a little longer.
- **R24** The design is checked by a ProVerif model before any code, with two negative controls that are expected to fail - shows what each part buys (F-03) - the model abstracts the state machine, which tests must cover.

## 17. Open questions for the owner

- **O1** Ruled 2026-10-30: automatic erase, 7 days after the device first reads its own revocation (R8, 8.4).
- **O2** Rotation code: shown on both sides (proposed), or mandatory comparison before "C'est moi" (stronger against a careless click, but the user rarely has the rotating device at hand)?
- **O3** Ruled 2026-10-30: Secure Enclave. The ML-DSA-87 and ML-KEM-1024 halves of the device keys live in the SE on Apple (5.1, R15).
- **O4** Do accounts with more than one device exist outside development? If not, drop the TOFU migration and require re-pairing.
- **O5** Deliver the new AUK to each device's biometric Secure Enclave key too, so a biometric device follows without typing the password? Needs that SE public key pinned and kept current.
- **O6** Per-device acknowledgment records (signed "I am on head h") so the rotator shows who followed? Small, but one more record kind.
- **O7** Should a rotation signed by a `Tofu` device require a verification first, instead of a warning?
- **O8** Spec language: written in English as requested, while the other specs in this folder and the first rotation spec are in French. Translate?

## 18. Implementation plan (TDD)

New branch from `main` (not from `fix/key-rotation`); kept parts are ported. Each task: write the failing tests, implement, run `cargo test -p onepass-core` (and the crate touched), commit. API sketch:

- `Repository::rotate(req: RotateRequest { revoke: Vec<Id>, new_password: Option<&str>, password, secret_key, new_secret_key }) -> Result<RotationOutcome { auk, code }>`
- `Repository::pending_rotation(store, device_state) -> Result<RotationPrompt>` (no unlock: summary, names from the local roster, code, kind: single, mutual, switch, self-revoked, orphaned, outdated)
- `Repository::follow_rotation(store, choice: [u8; 32], password, device_keys) -> Result<(Repository, Auk)>`
- `Repository::reject_rotation(store, choice, exclude: bool)`
- `Repository::quarantine_resolve(store, Erase | NotMe { password })`, `quarantine_tick(store, now)`

Tasks:

1. **Device keys** (`device_keys.rs`): `DeviceKeys`, `DevicePublic`, generation, strict codec, fingerprint, pop sign and verify. Tests: round trip, trailing bytes, wrong domain, pop over another transcript refused.
2. **Lineage records** (`lineage.rs`): genesis, rotation, intro, legacy intro, delivery ids; strict canonical codec; sign and verify with the six domains; lineage hash and record ids; structural checks of 6.3. Tests: each domain separated (a signature under one domain fails under every other), unsorted or duplicate lists refused, rotator in `revoked` refused, roster without rotator refused, 64-entry cap, golden hex vectors.
3. **Trust state** (`trust.rs`): `TrustState` codec, persisted with `put_all_if_version_with_chain`-style transactions; monotone `revoked`; bounded `ignored`. Tests: strict decode, monotonicity, transaction atomicity on a cut.
4. **Lineage resolver** (pure): `resolve(&TrustState, &[LineageRecord], completeness) -> Decision`. Tests: table of 8.2 transitions; 8.3 race in all three orders; exclusion and order of 8.5; proptest over random interleavings, withholding and attacker-signed records asserting (a) no `Adopt` without a user choice, (b) honest devices that saw the same records reach the same head, (c) at most one switch per divergence, (d) no automatic action ever creates a sibling of a decided divergence.
5. **Store kinds**: `Lineage = 10`, `DeviceIntro = 11`, `KeyDelivery = 12` added at the end; identity-keyed params, keyset, lists, epochs; immutability; `commit_remote` refuses deletions of the three new kinds and of identity records. Tests: put twice refused, server deletion refused and logged, generation 0 ids unchanged.
6. **Account**: port `Account::rotate`; keyset `OPK3` with `retired_kem`; verified params decoding everywhere (G8). Tests: `OPK2` still opens, `OPK3` round trip, retired keys bounded to 16, unverified server params ignored by the password-change path (hold-out 4).
7. **Rotator**: `Repository::rotate` building phases 1 and 2 in memory, one local transaction, `TrustState` to `Rotating`. Port the vault pass of `repo/rotation.rs`. Tests: K11, K12, travel refused, `VaultMissing` refuses, revoking self refused, roster and deliveries exact, old items still readable locally until phase 3.
8. **Sync phases** (`sync/store.rs`): phase ordering, phase 1 never conflicting, R21 overwrite, leftover item records of foreign key generations ignored, phase 3 deletion scope. Tests: cut between phases resumes; `zz2_hostile_epoch_inflation` and the epoch wedge become no-ops (ported as assertions).
9. **Follow**: `pending_rotation`, `follow_rotation`, `reject_rotation`; delivery opening; `last_seen` reset; biometric re-enrollment AUK returned. Tests: honest follow; `zz6` biometric device follows with the password only; `zz_biometric_device_has_no_known_keys` cannot be built any more (forged record refused or prompts); follow without completeness waits.
10. **Own-write log and replay**: log on every write, replay after adoption and switch. Tests: C writes during A's rotation (`zz2_epoch_drop...` scenario) and keeps its item; a write by B under the old identity after `from_heads` is not imported; bounds.
11. **Siblings and re-application**: switch flow, `Reapply` child, password re-application. Tests: `zz3`, `zz5` converge in at most two turns per device; re-application dropped when covered.
12. **Quarantine and exclusion**: self-revocation lock, erase 7 days later; "not me" exclusion; remove-and-rotate from the prompt; device list `revoked_at` no longer erases. Tests: `zz4` on A, on C in both orders; forged device-list revocation of A by a 2b-revoked device.
13. **Pairing v2**: `ConfirmedWithKey`, `Grant::FullV2` with trust snapshot, intro written with the grant in one transaction, re-intro after adoption. Tests: pop mismatch refused, intro by a revoked or excluded device refused, old peer falls back to legacy, snapshot lineage imported and pinned.
14. **Genesis and migration**: genesis at creation; legacy genesis and legacy intros; conflicting genesis or keys; verify ceremony; the one-time "rotate now" prompt flag. Tests: two legacy devices migrate in both orders; a 2b-revoked device's legacy intro refused; conflicting keys excluded.
15. **Emergency Kit restore**: lineage-aware restore, roster pinned through the identity signature, outdated kit refused when children are visible, kit-restored device intro needing a yes. Tests mirror `rotation.pv` (`restore_new`, `restore_old`).
16. **Travel, archives, backups**: R18, R19, 10.7. Tests: archive made before rotation opens with warning; travel off after following; backup restore never touches lineage.
17. **FFI** (`onepass-ffi`): rotate, prompt, follow, reject, quarantine, device key Keychain hooks (Swift supplies storage), error kinds. Tests in `tests/m2b.rs` and a new `tests/rotation.rs`.
18. **CLI**: `account rotate-keys`, `account remove-device`, device keys in `device.bin`, follow only via kit. Tests in `tests/cli.rs`.
19. **Attack regression suite** (`tests/rotation_v2_attacks.rs`): every `zz*` repro of the reviewer rewritten against the v2 API with assertions, plus 8.3 in all orders.
20. **Docs and model**: `docs/security/README.md` (French) new section on rotation v2, limits; update `rotation_core.pvl` names to the code; `make formal`.

Swift (VaultKit and app: screens of section 9, Keychain item, quarantine screen, pairing extension) is a separate plan after the Rust tasks, as for milestone 2b.

Size: 20 Rust tasks plus a Swift plan; roughly 8 to 12 implementation days with reviews, larger than `fix/key-rotation` (3,400 lines) because of the lineage resolver, migration and pairing changes, smaller in sync code because the contest disappears.
