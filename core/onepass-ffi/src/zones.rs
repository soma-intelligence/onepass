//! Shared zones for the apps (sharing plan 4, Task 1): the zone round of
//! `onepass_sync::zones` (share actions against the zone mailboxes, then
//! one driver round per zone), the invite drops and the contact pair
//! mailbox.
//!
//! Zone credential seeds cross only the `FfiZoneSeedStore` callback (the
//! keychain on Apple), never a file, a log or a return value.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use onepass_core::contact::SignedContactCard;
use onepass_core::repo::rekey::AccessRefusal;
use onepass_core::share::{AccessTarget, ShareAction, ZoneAccess, ZoneHome, ZoneSeed};
use onepass_core::store::Zone;
use onepass_core::sync::RebaseReport;
use onepass_mailbox::{Endpoint, MailboxError};
use onepass_sync::{ParentMailbox, ZoneError, ZoneHooks, ZoneRoundReport, ZoneSeedStore, ZoneSync};
use zeroize::Zeroizing;

use crate::convert::{bytes_hex, hex_bytes, id_hex, parse_id};
use crate::error::{OnePassError, invalid};
use crate::mailbox::{FfiMailboxEndpoint, FfiPushKind, FfiRoundStatus, FfiWakeInfo};
use crate::session::{Repo, Session, SyncStoreHandle, identity_left};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---- zones ------------------------------------------------------------------

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiZoneKind {
    Private,
    Vault,
    Contact,
    Family,
}

/// A zone: the private zone (`id` none), or a shared vault, a contact pair
/// or a family by id (32 hex characters).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiZone {
    pub kind: FfiZoneKind,
    pub id: Option<String>,
}

impl From<Zone> for FfiZone {
    fn from(z: Zone) -> Self {
        let (kind, id) = match z {
            Zone::Private => (FfiZoneKind::Private, None),
            Zone::Vault(id) => (FfiZoneKind::Vault, Some(id)),
            Zone::Contact(id) => (FfiZoneKind::Contact, Some(id)),
            Zone::Family(id) => (FfiZoneKind::Family, Some(id)),
        };
        FfiZone {
            kind,
            id: id.map(id_hex),
        }
    }
}

impl TryFrom<FfiZone> for Zone {
    type Error = OnePassError;

    fn try_from(z: FfiZone) -> Result<Self, OnePassError> {
        let id = || -> Result<_, OnePassError> {
            parse_id(z.id.as_deref().ok_or_else(|| invalid("zone"))?).map_err(|_| invalid("zone"))
        };
        Ok(match z.kind {
            FfiZoneKind::Private if z.id.is_none() => Zone::Private,
            FfiZoneKind::Private => return Err(invalid("zone")),
            FfiZoneKind::Vault => Zone::Vault(id()?),
            FfiZoneKind::Contact => Zone::Contact(id()?),
            FfiZoneKind::Family => Zone::Family(id()?),
        })
    }
}

/// Checks an `FfiZone` the app built (an id that is not 32 hex characters
/// is `InvalidInput`), and returns it as the core spells it.
#[uniffi::export]
pub fn zone_normalized(zone: FfiZone) -> Result<FfiZone, OnePassError> {
    Ok(Zone::try_from(zone)?.into())
}

// ---- the seed store ---------------------------------------------------------

/// Where the app keeps zone credential seeds: the keychain, key
/// `mailbox.zone.<mailbox id hex>`, `AfterFirstUnlockThisDeviceOnly`.
/// `mailbox_id` is 16 bytes, `seed` 32.
#[uniffi::export(with_foreign)]
pub trait FfiZoneSeedStore: Send + Sync {
    fn get(&self, mailbox_id: Vec<u8>) -> Option<Vec<u8>>;
    fn put(&self, mailbox_id: Vec<u8>, seed: Vec<u8>);
    fn delete(&self, mailbox_id: Vec<u8>);
}

struct Seeds(Arc<dyn FfiZoneSeedStore>);

impl ZoneSeedStore for Seeds {
    fn get(&self, mailbox_id: [u8; 16]) -> Option<Zeroizing<[u8; 32]>> {
        let v = Zeroizing::new(self.0.get(mailbox_id.to_vec())?);
        let arr: [u8; 32] = v.as_slice().try_into().ok()?;
        Some(Zeroizing::new(arr))
    }

    fn put(&self, mailbox_id: [u8; 16], seed: &[u8; 32]) {
        self.0.put(mailbox_id.to_vec(), seed.to_vec());
    }

    fn delete(&self, mailbox_id: [u8; 16]) {
        self.0.delete(mailbox_id.to_vec());
    }
}

// ---- the round --------------------------------------------------------------

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiZoneStatus {
    pub zone: FfiZone,
    pub status: FfiRoundStatus,
}

/// What the core concluded of a credential the server refused: `removed`
/// (a signed removal was found, the local copy is erased) or not (the vault
/// stays here read-only, "Le serveur refuse l'accès à <coffre>").
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiZoneRefusal {
    pub zone: FfiZone,
    pub removed: bool,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiZoneRoundReport {
    pub zones: Vec<FfiZoneStatus>,
    pub actions_done: u32,
    pub refusals: Vec<FfiZoneRefusal>,
    /// Zones whose mailbox is full ("Stockage du coffre partagé plein").
    pub quota_full: Vec<FfiZone>,
    pub changed: bool,
    pub retry_after_seconds: Option<u32>,
    pub rerun: bool,
}

impl From<ZoneRoundReport> for FfiZoneRoundReport {
    fn from(r: ZoneRoundReport) -> Self {
        FfiZoneRoundReport {
            zones: r
                .zones
                .into_iter()
                .map(|(z, s)| FfiZoneStatus {
                    zone: z.into(),
                    status: s.into(),
                })
                .collect(),
            actions_done: r.actions_done,
            refusals: r
                .refusals
                .into_iter()
                .map(|(z, a)| FfiZoneRefusal {
                    zone: z.into(),
                    removed: a == AccessRefusal::Removed,
                })
                .collect(),
            quota_full: r.quota_full.into_iter().map(Into::into).collect(),
            changed: r.changed,
            retry_after_seconds: r
                .retry_after
                .map(|d| u32::try_from(d.as_secs().max(1)).unwrap_or(u32::MAX)),
            rerun: r.rerun,
        }
    }
}

/// The wake channel of one zone mailbox, and the mailbox id its push
/// target is registered under (`set_push_target`).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiZoneWake {
    pub zone: FfiZone,
    /// 32 hex characters.
    pub mailbox_id: String,
    pub wake: FfiWakeInfo,
}

/// The session lent to a zone round one call at a time, as the private
/// round does (`SessionHooks`): the round's network time is spent without
/// the session's lock.
struct SessionZoneHooks<'a>(&'a Session);

impl SessionZoneHooks<'_> {
    fn with<R>(
        &mut self,
        write: bool,
        f: impl FnOnce(&mut Repo) -> onepass_core::Result<R>,
    ) -> onepass_core::Result<R> {
        let gone = || onepass_core::Error::Store("session locked".into());
        let mut guard = self.0.guard();
        let repo = guard.as_mut().ok_or_else(gone)?;
        if identity_left(repo).map_err(|_| gone())? {
            return Err(gone());
        }
        let out = f(repo)?;
        if write {
            repo.persist_device_state()?;
        }
        Ok(out)
    }
}

impl ZoneHooks for SessionZoneHooks<'_> {
    fn accesses(&mut self) -> onepass_core::Result<Vec<(ZoneAccess, ZoneSeed)>> {
        self.with(false, ZoneHooks::accesses)
    }

    fn pending_share_actions(&mut self) -> onepass_core::Result<Vec<ShareAction>> {
        self.with(false, |r| r.pending_share_actions())
    }

    fn share_action_done(&mut self, a: &ShareAction) -> onepass_core::Result<()> {
        self.with(true, |r| r.share_action_done(a))
    }

    fn set_zone_home(&mut self, target: AccessTarget, home: ZoneHome) -> onepass_core::Result<()> {
        self.with(true, |r| r.set_zone_home(target, home))
    }

    fn anchor(&mut self) -> onepass_core::Result<(Option<ZoneHome>, ZoneSeed)> {
        self.with(true, |r| r.anchor())
    }

    fn zone_access_refused(&mut self, zone: Zone, now: i64) -> onepass_core::Result<AccessRefusal> {
        self.with(true, |r| r.zone_access_refused(zone, now))
    }

    fn rebase(&mut self) -> onepass_core::Result<RebaseReport> {
        self.with(true, |r| r.rebase_report())
    }
}

impl From<ZoneError> for OnePassError {
    fn from(e: ZoneError) -> Self {
        match e {
            ZoneError::Mailbox(m) => m.into(),
            ZoneError::Core(reason) => OnePassError::MailboxUnavailable { reason },
        }
    }
}

/// The shared zones of one account: its seed store, the drivers of the
/// zones it syncs. One round at a time.
#[derive(uniffi::Object)]
pub struct ZoneSyncHandle {
    inner: Mutex<ZoneSync>,
}

#[uniffi::export]
impl ZoneSyncHandle {
    /// `default_base_url`: the server of the anchor mailbox (the Soma
    /// instance), for an account that does not sync through a mailbox of
    /// its own.
    #[uniffi::constructor(default(extra_ca_pem = None))]
    pub fn new(
        seeds: Arc<dyn FfiZoneSeedStore>,
        default_base_url: String,
        extra_ca_pem: Option<String>,
    ) -> Arc<Self> {
        Arc::new(ZoneSyncHandle {
            inner: Mutex::new(ZoneSync::new(
                Box::new(Seeds(seeds)),
                Endpoint {
                    base_url: default_base_url,
                    extra_ca_pem,
                },
            )),
        })
    }

    /// The account mailbox new zones are made under, with this device's
    /// manager credential (a mailbox account). Without it, the anchor on
    /// the default server.
    pub fn set_account_mailbox(
        &self,
        endpoint: FfiMailboxEndpoint,
        mailbox_id: String,
        credential_seed: Vec<u8>,
    ) -> Result<(), OnePassError> {
        let seed = Zeroizing::new(credential_seed);
        let seed: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| invalid("credential seed"))?;
        let mailbox_id: [u8; 16] = hex_bytes(&mailbox_id)
            .filter(|_| mailbox_id.len() == 32)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| invalid("mailbox id"))?;
        lock(&self.inner).set_parent(Some(ParentMailbox {
            url: endpoint.base_url,
            extra_ca_pem: endpoint.extra_ca_pem,
            mailbox_id,
            seed: Zeroizing::new(seed),
        }));
        Ok(())
    }

    /// One zone round (`ZoneSync::run_round`). With an unlocked `session`
    /// the share actions run and the seeds are cached; locked, the zones
    /// sync from the cached seeds.
    pub fn run_round(
        &self,
        session: Option<Arc<Session>>,
        store: Arc<SyncStoreHandle>,
        now: i64,
    ) -> FfiZoneRoundReport {
        let mut inner = lock(&self.inner);
        let unlocked = session.as_deref().filter(|s| {
            s.guard()
                .as_ref()
                .is_some_and(|r| !identity_left(r).unwrap_or(true))
        });
        let mut hooks = unlocked.map(SessionZoneHooks);
        let hooks = hooks.as_mut().map(|h| h as &mut dyn ZoneHooks);
        let mut store = store.guard();
        inner.run_round(hooks, &mut store, now).into()
    }

    /// The wake channel of each zone the last round synced.
    pub fn wake_topics(&self) -> Vec<FfiZoneWake> {
        lock(&self.inner)
            .wake_topics()
            .into_iter()
            .map(|w| FfiZoneWake {
                zone: w.zone.into(),
                mailbox_id: bytes_hex(&w.mailbox_id),
                wake: FfiWakeInfo {
                    realtime_url: w.realtime_url,
                    publishable_key: w.publishable_key,
                    topic: bytes_hex(&w.topic),
                },
            })
            .collect()
    }

    /// This device's push target on zone mailbox `mailbox_id` (hex): `tag`
    /// (16 bytes) drawn by the app once per device and mailbox (spec 13.7).
    pub fn set_push_target(
        &self,
        mailbox_id: String,
        tag: Vec<u8>,
        kind: FfiPushKind,
        token: Vec<u8>,
    ) -> Result<(), OnePassError> {
        let mailbox_id: [u8; 16] = hex_bytes(&mailbox_id)
            .filter(|_| mailbox_id.len() == 32)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| invalid("mailbox id"))?;
        let tag: [u8; 16] = tag.try_into().map_err(|_| invalid("push tag"))?;
        Ok(lock(&self.inner).set_push_target(mailbox_id, tag, kind.into(), &token)?)
    }

    /// The contact pair's mailbox during a verification (spec 13.5): made
    /// (or kept), the peer's credential granted, the signed offer returned
    /// for the verification session. Needs the network; a failure leaves
    /// nothing pinned. `peer_card`: the peer's signed contact card.
    pub fn contact_zone_create(
        &self,
        session: Arc<Session>,
        peer_card: Vec<u8>,
        now: i64,
    ) -> Result<Vec<u8>, OnePassError> {
        let card = SignedContactCard::decode(&peer_card).map_err(|_| invalid("contact card"))?;
        let mut inner = lock(&self.inner);
        session.with(|repo| Ok(inner.contact_zone_create(repo, &card, now)?))
    }
}

// ---- invite drops -----------------------------------------------------------

fn drop_endpoint(base_url: String, extra_ca_pem: Option<String>) -> Endpoint {
    Endpoint {
        base_url,
        extra_ca_pem,
    }
}

fn drop_id(id: Vec<u8>) -> Result<[u8; 16], OnePassError> {
    id.try_into().map_err(|_| invalid("drop id"))
}

/// Write slot `slot` (0 to 3) of invite drop `id` (16 bytes) on
/// `base_url`. A slot already written is `Conflict`.
#[uniffi::export(default(extra_ca_pem = None))]
pub fn drop_put(
    base_url: String,
    id: Vec<u8>,
    slot: u8,
    bytes: Vec<u8>,
    extra_ca_pem: Option<String>,
) -> Result<(), OnePassError> {
    match onepass_mailbox::drop_put(
        &drop_endpoint(base_url, extra_ca_pem),
        drop_id(id)?,
        slot,
        &bytes,
    ) {
        Err(MailboxError::Conflict) => Err(OnePassError::Conflict),
        other => Ok(other?),
    }
}

/// Read slot `slot` of drop `id`: `None` when nothing is there (yet).
#[uniffi::export(default(extra_ca_pem = None))]
pub fn drop_get(
    base_url: String,
    id: Vec<u8>,
    slot: u8,
    extra_ca_pem: Option<String>,
) -> Result<Option<Vec<u8>>, OnePassError> {
    Ok(onepass_mailbox::drop_get(
        &drop_endpoint(base_url, extra_ca_pem),
        drop_id(id)?,
        slot,
    )?)
}

/// Delete drop `id` (every slot).
#[uniffi::export(default(extra_ca_pem = None))]
pub fn drop_delete(
    base_url: String,
    id: Vec<u8>,
    extra_ca_pem: Option<String>,
) -> Result<(), OnePassError> {
    Ok(onepass_mailbox::drop_delete(
        &drop_endpoint(base_url, extra_ca_pem),
        drop_id(id)?,
    )?)
}

/// Which half of a remote invitation (`invite_put`).
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiInvitePart {
    /// The invitee's reply.
    Reply,
    /// The inviter's answer.
    Answer,
}

impl From<FfiInvitePart> for onepass_mailbox::InvitePart {
    fn from(p: FfiInvitePart) -> onepass_mailbox::InvitePart {
        match p {
            FfiInvitePart::Reply => onepass_mailbox::InvitePart::Reply,
            FfiInvitePart::Answer => onepass_mailbox::InvitePart::Answer,
        }
    }
}

/// Write one half of the remote invitation at `rdv_id` (16 bytes, from
/// the invitation): a sealed reply or answer is larger than one slot, so
/// it spreads over the slots of a drop of its own. A retry after a partial
/// write is safe; other bytes already there are `Conflict`.
#[uniffi::export(default(extra_ca_pem = None))]
pub fn invite_put(
    base_url: String,
    rdv_id: Vec<u8>,
    part: FfiInvitePart,
    bytes: Vec<u8>,
    extra_ca_pem: Option<String>,
) -> Result<(), OnePassError> {
    match onepass_mailbox::invite_put(
        &drop_endpoint(base_url, extra_ca_pem),
        drop_id(rdv_id)?,
        part.into(),
        &bytes,
    ) {
        Err(MailboxError::Conflict) => Err(OnePassError::Conflict),
        other => Ok(other?),
    }
}

/// Read one half of the remote invitation at `rdv_id`: `None` until it
/// is all there.
#[uniffi::export(default(extra_ca_pem = None))]
pub fn invite_get(
    base_url: String,
    rdv_id: Vec<u8>,
    part: FfiInvitePart,
    extra_ca_pem: Option<String>,
) -> Result<Option<Vec<u8>>, OnePassError> {
    Ok(onepass_mailbox::invite_get(
        &drop_endpoint(base_url, extra_ca_pem),
        drop_id(rdv_id)?,
        part.into(),
    )?)
}

/// Close the drop of one half of the remote invitation at `rdv_id`.
#[uniffi::export(default(extra_ca_pem = None))]
pub fn invite_delete(
    base_url: String,
    rdv_id: Vec<u8>,
    part: FfiInvitePart,
    extra_ca_pem: Option<String>,
) -> Result<(), OnePassError> {
    Ok(onepass_mailbox::invite_delete(
        &drop_endpoint(base_url, extra_ca_pem),
        drop_id(rdv_id)?,
        part.into(),
    )?)
}

/// Tests only (fast-KDF test framework): the creator's zone offer for
/// `peer_card` without a server, the pair's mailbox at a made-up home
/// (`https://zones.test`, a random mailbox id). For the Swift tests of the
/// verification flows; never built into a shipped framework.
#[cfg(feature = "dev-fast-kdf")]
#[uniffi::export]
pub fn test_contact_zone_offer(
    session: Arc<Session>,
    peer_card: Vec<u8>,
    now: i64,
) -> Result<Vec<u8>, OnePassError> {
    let card = SignedContactCard::decode(&peer_card).map_err(|_| invalid("contact card"))?;
    let mailbox_id: [u8; 16] = onepass_core::crypto::random_array()?;
    session.with(|repo| {
        let plan = repo.prepare_contact_zone(&card, now)?;
        Ok(repo.seal_contact_zone_offer(
            plan,
            ZoneHome {
                url: "https://zones.test/functions/v1/mailbox".into(),
                mailbox_id,
                extra_ca_pem: None,
            },
        )?)
    })
}
