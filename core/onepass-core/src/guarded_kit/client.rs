//! Client side: registration (spec 7.1), restore (7.2), owner status and
//! delete (8.4). The core holds no network code: the app or the CLI moves
//! the bytes through a [`RealmTransport`].

use aws_lc_rs::hmac::{self, HMAC_SHA256};
use zeroize::Zeroizing;

use super::descriptor::{Locator, Placement};
use super::oprf;
use super::shamir::{self, SECRET_LEN, Share};
use super::wire::{
    GuardId, Request, ResponseBody, delete_message, encode_request, open_response, status_message,
};
use super::{GuardError, GuardSecret, RealmInfo};
use crate::Id;
use crate::crypto::key::hkdf32;
use crate::crypto::sign::{ed25519_public_of, ed25519_sign};
use crate::crypto::{Aad, BlobKind, SymmetricKey, open, random_array, seal};

const TAG_KEY_INFO: &[u8] = b"onepass/guard/tag-key/v1";
const TAG_INFO: &[u8] = b"onepass/guard/tag/v1";
const SHARE_KEY_INFO: &[u8] = b"onepass/guard/share-key/v1";
const OWNER_INFO: &[u8] = b"onepass/guard/owner/v1";
const SHARE_SCHEMA: u16 = 1;

/// Carries one request to one realm and returns its raw response.
pub trait RealmTransport {
    fn call(&self, realm: &RealmInfo, request: &[u8]) -> Result<Vec<u8>, GuardError>;
}

/// The owner key of a guard: `HKDF(G, "onepass/guard/owner/v1")` as an
/// Ed25519 seed. Every device that holds `G` may poll, re-register and
/// delete; a kit holder without `G` may not.
fn owner_seed(guard: &GuardSecret) -> Result<Zeroizing<[u8; 32]>, GuardError> {
    let k = hkdf32(&[], guard.expose(), &[OWNER_INFO]).map_err(|_| GuardError::Crypto)?;
    Ok(Zeroizing::new(*k.expose()))
}

fn binding(realm_id: &[u8; 16], index: u8, version: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(21);
    b.extend_from_slice(realm_id);
    b.push(index);
    b.extend_from_slice(&version.to_be_bytes());
    b
}

/// The tag of one realm: `HMAC(HKDF(y, "onepass/guard/tag-key/v1"),
/// "onepass/guard/tag/v1" || realm_id || index || version)`, where `y` is
/// the OPRF output under the whole key. Public for the attack tests.
pub fn tag_of(
    y: &[u8],
    realm_id: &[u8; 16],
    index: u8,
    version: u32,
) -> Result<[u8; 32], GuardError> {
    let tag_key = hkdf32(&[], y, &[TAG_KEY_INFO]).map_err(|_| GuardError::Crypto)?;
    let mut m = TAG_INFO.to_vec();
    m.extend(binding(realm_id, index, version));
    let t = hmac::sign(&hmac::Key::new(HMAC_SHA256, tag_key.expose()), &m);
    t.as_ref().try_into().map_err(|_| GuardError::Crypto)
}

fn share_key(
    y: &[u8],
    realm_id: &[u8; 16],
    index: u8,
    version: u32,
) -> Result<SymmetricKey, GuardError> {
    hkdf32(
        &[],
        y,
        &[SHARE_KEY_INFO, &binding(realm_id, index, version)],
    )
    .map_err(|_| GuardError::Crypto)
}

fn share_aad(realm_id: &[u8; 16], index: u8) -> Aad {
    let mut b = [0u8; 16];
    b[15] = index;
    Aad {
        blob_id: Id(b),
        vault_id: Some(Id(*realm_id)),
        schema: SHARE_SCHEMA,
    }
}

fn call(
    transport: &dyn RealmTransport,
    realm: &RealmInfo,
    request: &Request,
) -> Result<ResponseBody, GuardError> {
    let req = encode_request(request)?;
    let resp = transport.call(realm, &req)?;
    open_response(&resp, &req, &realm.response_key)
}

/// Register `guard` at every realm of `realms`, `threshold` of which will
/// rebuild it. `input` is the guard input `x` of the spec.
///
/// The client draws the OPRF key `k`, computes `y = OPRF(k, x)` itself,
/// and sends each realm only its share `k_i`, its tag and its sealed share
/// of `G`; `k` is dropped (wiped) on return. All realms must accept: a
/// guard that starts with a missing realm starts weaker.
pub fn register(
    transport: &dyn RealmTransport,
    realms: &[RealmInfo],
    threshold: u8,
    input: &[u8; 32],
    guard: &GuardSecret,
    version: u32,
) -> Result<Locator, GuardError> {
    let n = u8::try_from(realms.len()).map_err(|_| GuardError::Config("realm count"))?;
    let shares = shamir::split(guard.expose(), threshold, n)?;
    let k = oprf::new_key()?;
    let key_shares = oprf::split_key(&k, threshold, n)?;
    let y = oprf::evaluate_full(&k, input)?;
    drop(k);
    let owner = owner_seed(guard)?;
    let owner_pub = ed25519_public_of(&owner).map_err(|_| GuardError::Crypto)?;

    let mut placements = Vec::with_capacity(realms.len());
    for ((realm, share), ks) in realms.iter().zip(shares.iter()).zip(key_shares.iter()) {
        // The guard id is the realm's, unknown before the call: tag and
        // share bind the realm id, the key share index and the version, and
        // the realm binds the guard id to the record it stores.
        let tag = tag_of(y.as_slice(), &realm.id, ks.index, version)?;
        let key = share_key(y.as_slice(), &realm.id, ks.index, version)?;
        let mut plain = Zeroizing::new(Vec::with_capacity(1 + SECRET_LEN));
        plain.push(share.x);
        plain.extend_from_slice(&share.y);
        let share_ct = seal(
            &key,
            BlobKind::GuardShare,
            &share_aad(&realm.id, ks.index),
            &plain,
        )
        .map_err(|_| GuardError::Crypto)?;
        let guard_id = match call(
            transport,
            realm,
            &Request::Register {
                owner: owner_pub,
                version,
                key_share: *ks.key,
                tag,
                share_ct,
            },
        )? {
            ResponseBody::Registered { guard_id } => guard_id,
            _ => return Err(GuardError::Unexpected),
        };
        placements.push(Placement {
            realm_id: realm.id,
            guard_id,
            index: ks.index,
        });
    }
    Ok(Locator {
        version,
        threshold,
        placements,
    })
}

/// Rebuild the guard from the realms of `locator` that are in the pinned
/// list `pinned`. A placement naming a realm outside `pinned` is skipped:
/// the realm list never comes from storage (spec 5).
///
/// Phase 1 sends one blinded element to realms until `threshold` of them
/// evaluated (each counts an attempt), combines their evaluations into the
/// OPRF output, then phase 2 unlocks at those realms. It stops at the
/// first wrong tag (`WrongPassword`): the password is wrong at every realm.
pub fn restore(
    transport: &dyn RealmTransport,
    pinned: &[RealmInfo],
    locator: &Locator,
    input: &[u8; 32],
) -> Result<GuardSecret, GuardError> {
    let t = usize::from(locator.threshold);
    let b = oprf::blind(input)?;
    let mut evaluated: Vec<(&RealmInfo, &Placement, [u8; 32])> = Vec::new();
    let mut fewest: Option<u8> = None;
    for p in &locator.placements {
        if evaluated.len() >= t {
            break;
        }
        if p.index == 0 || evaluated.iter().any(|(_, q, _)| q.index == p.index) {
            continue;
        }
        let Some(realm) = pinned.iter().find(|r| r.id == p.realm_id) else {
            continue;
        };
        // Gone, refused, unreachable or forged: try the next realm.
        if let Ok(ResponseBody::Evaluated {
            evaluation,
            remaining,
        }) = call(
            transport,
            realm,
            &Request::Evaluate {
                guard_id: p.guard_id,
                blinded: b.message,
            },
        ) {
            fewest = Some(fewest.map_or(remaining, |f| f.min(remaining)));
            evaluated.push((realm, p, evaluation));
        }
    }
    if evaluated.len() < t {
        return Err(GuardError::Unavailable {
            reached: u8::try_from(evaluated.len()).unwrap_or(u8::MAX),
            needed: locator.threshold,
        });
    }
    let evals: Vec<(u8, [u8; 32])> = evaluated.iter().map(|(_, p, e)| (p.index, *e)).collect();
    let y = b.finalize(input, &oprf::combine_evaluations(&evals)?)?;

    let mut shares: Vec<Share> = Vec::with_capacity(t);
    for (realm, p, _) in &evaluated {
        let tag = tag_of(y.as_slice(), &realm.id, p.index, locator.version)?;
        let share_ct = match call(
            transport,
            realm,
            &Request::Unlock {
                guard_id: p.guard_id,
                tag,
            },
        ) {
            Ok(ResponseBody::Unlocked { share_ct }) => share_ct,
            Ok(ResponseBody::WrongTag { remaining }) => {
                return Err(GuardError::WrongPassword {
                    remaining: fewest.map_or(remaining, |f| f.min(remaining)),
                });
            }
            Ok(ResponseBody::Gone) => {
                return Err(GuardError::WrongPassword { remaining: 0 });
            }
            _ => {
                return Err(GuardError::Unavailable {
                    reached: u8::try_from(shares.len()).unwrap_or(u8::MAX),
                    needed: locator.threshold,
                });
            }
        };
        let key = share_key(y.as_slice(), &realm.id, p.index, locator.version)?;
        let plain = Zeroizing::new(
            open(
                &key,
                BlobKind::GuardShare,
                &share_aad(&realm.id, p.index),
                &share_ct,
            )
            .map_err(|_| GuardError::ShareRefused)?,
        );
        if plain.len() != 1 + SECRET_LEN {
            return Err(GuardError::ShareRefused);
        }
        let mut y_share = [0u8; SECRET_LEN];
        y_share.copy_from_slice(&plain[1..]);
        shares.push(Share {
            x: plain[0],
            y: y_share,
        });
    }
    let refs: Vec<&Share> = shares.iter().collect();
    let g = shamir::combine(&refs)?;
    Ok(GuardSecret::from_bytes(*g))
}

/// What a realm reports to the owner (spec 8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardStatus {
    Active {
        version: u32,
        attempts: u8,
        limit: u8,
        failures: Vec<u64>,
    },
    Gone,
}

/// Owner poll of one placement.
pub fn status(
    transport: &dyn RealmTransport,
    realm: &RealmInfo,
    guard_id: &GuardId,
    guard: &GuardSecret,
) -> Result<GuardStatus, GuardError> {
    let owner = owner_seed(guard)?;
    let nonce = random_array::<16>().map_err(|_| GuardError::Crypto)?;
    let sig =
        ed25519_sign(&owner, &status_message(guard_id, &nonce)).map_err(|_| GuardError::Crypto)?;
    match call(
        transport,
        realm,
        &Request::Status {
            guard_id: *guard_id,
            nonce,
            sig: sig.to_vec(),
        },
    )? {
        ResponseBody::Status {
            version,
            attempts,
            limit,
            failures,
        } => Ok(GuardStatus::Active {
            version,
            attempts,
            limit,
            failures,
        }),
        ResponseBody::Gone => Ok(GuardStatus::Gone),
        _ => Err(GuardError::Unexpected),
    }
}

/// Owner delete of every placement of `locator` that a pinned realm holds.
/// Returns how many realms confirmed (deleted or already gone).
pub fn delete(
    transport: &dyn RealmTransport,
    pinned: &[RealmInfo],
    locator: &Locator,
    guard: &GuardSecret,
) -> Result<usize, GuardError> {
    let owner = owner_seed(guard)?;
    let mut done = 0;
    for p in &locator.placements {
        let Some(realm) = pinned.iter().find(|r| r.id == p.realm_id) else {
            continue;
        };
        let sig =
            ed25519_sign(&owner, &delete_message(&p.guard_id)).map_err(|_| GuardError::Crypto)?;
        if let Ok(ResponseBody::Deleted | ResponseBody::Gone) = call(
            transport,
            realm,
            &Request::Delete {
                guard_id: p.guard_id,
                sig: sig.to_vec(),
            },
        ) {
            done += 1;
        }
    }
    Ok(done)
}
