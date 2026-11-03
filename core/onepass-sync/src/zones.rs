//! Shared zones over the mailbox (sharing spec 13.3 to 13.9, plan 4 Task 1,
//! ruling C-1): one round opens every `ZoneAccess` of the account, runs the
//! core's `ShareAction`s against the zone mailboxes, then syncs each zone
//! that has a home and a seed with its own `SyncDriver::for_zone`.
//!
//! The transport is never a source of truth (plan 4, global constraints):
//! nothing here decides a right from a server answer. A credential the
//! server no longer accepts goes back to the core (`zone_access_refused`),
//! which decides what it means.
//!
//! Order of a round:
//! - unlocked: every access opened, its seed kept in the `ZoneSeedStore`
//!   (the keychain on Apple) under its mailbox id, so a locked round can
//!   sync too;
//! - unlocked: the pending share actions, in the core's order, each one
//!   acknowledged (`share_action_done`) once the server took it; a network
//!   error leaves it (and the later steps of its zone) queued;
//! - locked or not: one driver round per zone with a home and a seed. A
//!   zone that cannot be reached ends `Offline` on its own; the others go
//!   on.
//!
//! The account's own mailbox is the parent of the zones it creates; an
//! account that syncs elsewhere (iCloud) uses its anchor mailbox on the
//! default server (spec 13.3), created on first use.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use onepass_core::contact::SignedContactCard;
use onepass_core::repo::Repository;
use onepass_core::repo::rekey::AccessRefusal;
use onepass_core::repo::share::list_zone_accesses;
use onepass_core::share::{
    AccessTarget, ShareAction, ZoneAccess, ZoneHome, ZoneMailboxKind, ZoneRole, ZoneSeed,
};
use onepass_core::store::Zone;
use onepass_core::sync::{RebaseReport, SyncStore, VaultSyncHealth};
use onepass_core::{Error, Id};
use onepass_mailbox::{Credential, Endpoint, ErrorCode, MailboxApi, MailboxClient, MailboxError};
use onepass_mailbox_proto::{ChildKind, CredentialRole, PushKind};
use zeroize::Zeroizing;

use crate::driver::{RoundHooks, RoundStatus, SyncDriver};
use crate::mailbox::{MailboxTransport, transport_error};
use crate::transport::TransportError;

/// What the server sees of a label: nothing.
const LABEL: &[u8] = b"";

/// Passes over the action queue in one round (a create unblocks the
/// grants of its zone for the next pass).
const ACTION_PASSES: usize = 4;

/// Where zone credential seeds live between rounds, by mailbox id: the
/// keychain on Apple (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`),
/// never a file or a log.
pub trait ZoneSeedStore: Send + Sync {
    fn get(&self, mailbox_id: [u8; 16]) -> Option<Zeroizing<[u8; 32]>>;
    fn put(&self, mailbox_id: [u8; 16], seed: &[u8; 32]);
    fn delete(&self, mailbox_id: [u8; 16]);
}

/// Opens a mailbox client for a server and a credential seed.
pub trait Connect: Send {
    type Api: MailboxApi;
    fn connect(
        &self,
        url: &str,
        extra_ca_pem: Option<&str>,
        seed: &[u8; 32],
    ) -> Result<Self::Api, MailboxError>;
}

/// The real client over HTTPS.
pub struct HttpConnect;

impl Connect for HttpConnect {
    type Api = MailboxClient;

    fn connect(
        &self,
        url: &str,
        extra_ca_pem: Option<&str>,
        seed: &[u8; 32],
    ) -> Result<MailboxClient, MailboxError> {
        MailboxClient::new(
            Endpoint {
                base_url: url.to_string(),
                extra_ca_pem: extra_ca_pem.map(str::to_string),
            },
            Credential::from_seed(seed)?,
        )
    }
}

/// What the unlocked session lends a zone round, one call at a time.
pub trait ZoneHooks {
    /// Every verified access of the account with its opened seed (an
    /// access that does not open is left out).
    fn accesses(&mut self) -> onepass_core::Result<Vec<(ZoneAccess, ZoneSeed)>>;
    fn pending_share_actions(&mut self) -> onepass_core::Result<Vec<ShareAction>>;
    fn share_action_done(&mut self, a: &ShareAction) -> onepass_core::Result<()>;
    fn set_zone_home(&mut self, target: AccessTarget, home: ZoneHome) -> onepass_core::Result<()>;
    fn anchor(&mut self) -> onepass_core::Result<(Option<ZoneHome>, ZoneSeed)>;
    fn zone_access_refused(&mut self, zone: Zone, now: i64) -> onepass_core::Result<AccessRefusal>;
    fn rebase(&mut self) -> onepass_core::Result<RebaseReport>;
}

impl ZoneHooks for Repository<SyncStore> {
    fn accesses(&mut self) -> onepass_core::Result<Vec<(ZoneAccess, ZoneSeed)>> {
        let mut out = Vec::new();
        for a in self.zone_accesses()? {
            if let Ok(Some(pair)) = self.zone_access(a.target) {
                out.push(pair);
            }
        }
        Ok(out)
    }

    fn pending_share_actions(&mut self) -> onepass_core::Result<Vec<ShareAction>> {
        Repository::pending_share_actions(self)
    }

    fn share_action_done(&mut self, a: &ShareAction) -> onepass_core::Result<()> {
        Repository::share_action_done(self, a)
    }

    fn set_zone_home(&mut self, target: AccessTarget, home: ZoneHome) -> onepass_core::Result<()> {
        Repository::set_zone_home(self, target, home)
    }

    fn anchor(&mut self) -> onepass_core::Result<(Option<ZoneHome>, ZoneSeed)> {
        Repository::anchor(self)
    }

    fn zone_access_refused(&mut self, zone: Zone, now: i64) -> onepass_core::Result<AccessRefusal> {
        Repository::zone_access_refused(self, zone, now)
    }

    fn rebase(&mut self) -> onepass_core::Result<RebaseReport> {
        self.rebase_report()
    }
}

/// The zone driver's view of the session: the rebase only (no sync health,
/// no `SyncHome` in a shared zone).
struct RebaseOnly<'a, 'b>(&'a mut (dyn ZoneHooks + 'b));

impl RoundHooks for RebaseOnly<'_, '_> {
    fn rebase(&mut self) -> onepass_core::Result<RebaseReport> {
        self.0.rebase()
    }

    fn note_round(&mut self, _now: i64) -> onepass_core::Result<Vec<(Id, VaultSyncHealth)>> {
        Ok(Vec::new())
    }

    fn health(&mut self) -> onepass_core::Result<Vec<(Id, VaultSyncHealth)>> {
        Ok(Vec::new())
    }

    fn keep_this_device(&mut self) -> onepass_core::Result<u64> {
        Err(Error::Store("no safe exit in a shared zone".into()))
    }

    fn sync_home(&mut self) -> onepass_core::Result<Option<onepass_core::synchome::SyncHomeBody>> {
        Ok(None)
    }
}

/// The account mailbox this device holds a manager credential on: the
/// parent of the zones it creates.
pub struct ParentMailbox {
    pub url: String,
    pub extra_ca_pem: Option<String>,
    pub mailbox_id: [u8; 16],
    pub seed: Zeroizing<[u8; 32]>,
}

/// Why a zone step failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneError {
    Mailbox(MailboxError),
    Core(String),
}

impl From<MailboxError> for ZoneError {
    fn from(e: MailboxError) -> Self {
        ZoneError::Mailbox(e)
    }
}

impl From<Error> for ZoneError {
    fn from(e: Error) -> Self {
        ZoneError::Core(e.to_string())
    }
}

impl ZoneError {
    /// The server could not be reached or asked to wait: the step stays
    /// queued for the next round.
    pub fn is_network(&self) -> bool {
        matches!(
            self,
            ZoneError::Mailbox(MailboxError::Offline | MailboxError::Retry { .. })
        )
    }

    pub fn is_quota(&self) -> bool {
        matches!(
            self,
            ZoneError::Mailbox(MailboxError::Server(ErrorCode::Quota))
        )
    }
}

/// The wake channel of one zone mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneWake {
    pub zone: Zone,
    pub mailbox_id: [u8; 16],
    pub realtime_url: String,
    pub publishable_key: String,
    pub topic: [u8; 16],
}

/// How a zone round ended.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZoneRoundReport {
    /// One entry per zone synced this round.
    pub zones: Vec<(Zone, RoundStatus)>,
    pub actions_done: u32,
    /// What the core concluded of a credential the server refused.
    pub refusals: Vec<(Zone, AccessRefusal)>,
    /// Zones whose mailbox refused writes for quota (the app shows "Stockage
    /// du coffre partagé plein"; nothing is undone).
    pub quota_full: Vec<Zone>,
    /// Remote changes applied, a home set or a refusal handled: reload.
    pub changed: bool,
    /// The shortest wait any zone asked for.
    pub retry_after: Option<Duration>,
    pub rerun: bool,
}

struct ZoneDriver<A: MailboxApi> {
    home: ZoneHome,
    driver: SyncDriver<MailboxTransport<A>>,
}

/// See the module doc.
pub struct ZoneSync<C: Connect = HttpConnect> {
    seeds: Box<dyn ZoneSeedStore>,
    connect: C,
    default_endpoint: Endpoint,
    parent: Option<ParentMailbox>,
    drivers: BTreeMap<Zone, ZoneDriver<C::Api>>,
}

impl ZoneSync<HttpConnect> {
    pub fn new(seeds: Box<dyn ZoneSeedStore>, default_endpoint: Endpoint) -> Self {
        ZoneSync::with_connect(seeds, default_endpoint, HttpConnect)
    }
}

fn credential_role(r: ZoneRole) -> CredentialRole {
    match r {
        ZoneRole::Read => CredentialRole::Read,
        ZoneRole::Write => CredentialRole::Write,
        ZoneRole::Manage => CredentialRole::Manage,
    }
}

fn child_kind(k: ZoneMailboxKind) -> ChildKind {
    match k {
        ZoneMailboxKind::Shared => ChildKind::Shared,
        ZoneMailboxKind::Contact => ChildKind::Contact,
    }
}

/// A revocation or deletion of something already gone is done.
fn gone(e: &MailboxError) -> bool {
    matches!(
        e,
        MailboxError::Server(
            ErrorCode::NotFound | ErrorCode::UnknownCredential | ErrorCode::RevokedCredential
        )
    )
}

impl<C: Connect> ZoneSync<C> {
    pub fn with_connect(
        seeds: Box<dyn ZoneSeedStore>,
        default_endpoint: Endpoint,
        connect: C,
    ) -> Self {
        ZoneSync {
            seeds,
            connect,
            default_endpoint,
            parent: None,
            drivers: BTreeMap::new(),
        }
    }

    /// The account mailbox new zones are created under (a mailbox
    /// account). `None`: the anchor on the default server (an iCloud
    /// account).
    pub fn set_parent(&mut self, parent: Option<ParentMailbox>) {
        self.parent = parent;
    }

    /// One round, see the module doc. `hooks`: the unlocked session, `None`
    /// while locked (zones sync from the cached seeds, no action runs).
    pub fn run_round(
        &mut self,
        mut hooks: Option<&mut dyn ZoneHooks>,
        store: &mut SyncStore,
        now: i64,
    ) -> ZoneRoundReport {
        let mut report = ZoneRoundReport::default();
        if let Some(h) = hooks.as_deref_mut() {
            self.run_actions(h, &mut report);
        }
        let targets = self.targets(&mut hooks, store);
        let wanted: BTreeSet<Zone> = targets.iter().map(|(z, _, _)| *z).collect();
        self.drivers.retain(|z, _| wanted.contains(z));
        for (zone, home, seed) in targets {
            let status = self.sync_zone(&mut hooks, store, zone, home, &seed, now, &mut report);
            report.zones.push((zone, status));
        }
        report
    }

    /// The zones to sync: unlocked, every access with a home (its seed
    /// cached); locked, the accesses read from the store without checks and
    /// the cached seeds.
    fn targets(
        &mut self,
        hooks: &mut Option<&mut dyn ZoneHooks>,
        store: &mut SyncStore,
    ) -> Vec<(Zone, ZoneHome, Zeroizing<[u8; 32]>)> {
        let mut out = Vec::new();
        if let Some(h) = hooks.as_deref_mut()
            && let Ok(accesses) = h.accesses()
        {
            for (a, seed) in accesses {
                let (AccessTarget::Zone(zone), Some(home)) = (a.target, a.home) else {
                    continue;
                };
                self.seeds.put(home.mailbox_id, seed.expose());
                out.push((zone, home, Zeroizing::new(*seed.expose())));
            }
            return out;
        }
        for a in list_zone_accesses(store).unwrap_or_default() {
            let (AccessTarget::Zone(zone), Some(home)) = (a.target, a.home) else {
                continue;
            };
            if home.check().is_err() {
                continue;
            }
            if let Some(seed) = self.seeds.get(home.mailbox_id) {
                // A seed that does not match the access's credential is not
                // this zone's (a stale cache entry): skip the zone.
                if ZoneSeed::from_bytes(*seed).credential_id() == a.credential_id {
                    out.push((zone, home, seed));
                }
            }
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn sync_zone(
        &mut self,
        hooks: &mut Option<&mut dyn ZoneHooks>,
        store: &mut SyncStore,
        zone: Zone,
        home: ZoneHome,
        seed: &[u8; 32],
        now: i64,
        report: &mut ZoneRoundReport,
    ) -> RoundStatus {
        if self.drivers.get(&zone).is_none_or(|d| d.home != home) {
            let api = match self.connect_zone(&home, seed) {
                Ok(api) => api,
                Err(e) => {
                    return match transport_error(e) {
                        TransportError::Offline => RoundStatus::Offline,
                        _ => RoundStatus::Retrying,
                    };
                }
            };
            self.drivers.insert(
                zone,
                ZoneDriver {
                    home: home.clone(),
                    driver: SyncDriver::for_zone(MailboxTransport::new(api), zone),
                },
            );
        }
        let d = self.drivers.get_mut(&zone).expect("driver inserted");
        let r = {
            let mut rebase = hooks.as_deref_mut().map(RebaseOnly);
            let round_hooks = rebase.as_mut().map(|r| r as &mut dyn RoundHooks);
            d.driver.run_round(store, round_hooks, now)
        };
        report.changed |= r.changed;
        report.rerun |= r.rerun;
        if let Some(after) = r.retry_after {
            report.retry_after = Some(report.retry_after.map_or(after, |a| a.min(after)));
        }
        match d.driver.last_error() {
            Some(TransportError::Quota) => report.quota_full.push(zone),
            Some(TransportError::Revoked) => {
                if let Some(h) = hooks.as_deref_mut()
                    && matches!(zone, Zone::Vault(_))
                    && let Ok(refusal) = h.zone_access_refused(zone, now)
                {
                    report.refusals.push((zone, refusal));
                    report.changed = true;
                }
            }
            _ => {}
        }
        r.status
    }

    fn connect_zone(&self, home: &ZoneHome, seed: &[u8; 32]) -> Result<C::Api, MailboxError> {
        let mut api = self
            .connect
            .connect(&home.url, home.extra_ca_pem.as_deref(), seed)?;
        api.open(home.mailbox_id);
        Ok(api)
    }

    /// The pending share actions, in order, a few passes (a create lets the
    /// grants of its zone through on the next pass).
    fn run_actions(&mut self, h: &mut dyn ZoneHooks, report: &mut ZoneRoundReport) {
        let mut blocked: BTreeSet<Zone> = BTreeSet::new();
        for _ in 0..ACTION_PASSES {
            let Ok(actions) = h.pending_share_actions() else {
                return;
            };
            let Ok(accesses) = h.accesses() else {
                return;
            };
            let mut progress = false;
            for a in actions {
                let zone = a.zone();
                if blocked.contains(&zone) {
                    continue;
                }
                match self.run_action(h, &accesses, &a) {
                    Ok(()) => {
                        if h.share_action_done(&a).is_err() {
                            blocked.insert(zone);
                            continue;
                        }
                        report.actions_done += 1;
                        report.changed = true;
                        progress = true;
                    }
                    Err(e) => {
                        if e.is_quota() && !report.quota_full.contains(&zone) {
                            report.quota_full.push(zone);
                        }
                        // Later steps of the zone wait for this one.
                        blocked.insert(zone);
                    }
                }
            }
            if !progress {
                return;
            }
        }
    }

    fn access_of(
        accesses: &[(ZoneAccess, ZoneSeed)],
        zone: Zone,
    ) -> Result<&(ZoneAccess, ZoneSeed), ZoneError> {
        accesses
            .iter()
            .find(|(a, _)| a.target == AccessTarget::Zone(zone))
            .ok_or_else(|| ZoneError::Core("no access to the zone".into()))
    }

    /// A client on the zone's mailbox with my credential.
    fn zone_client(
        &self,
        accesses: &[(ZoneAccess, ZoneSeed)],
        zone: Zone,
    ) -> Result<(C::Api, ZoneHome), ZoneError> {
        let (a, seed) = Self::access_of(accesses, zone)?;
        let home = a
            .home
            .clone()
            .ok_or_else(|| ZoneError::Core("zone has no home".into()))?;
        Ok((self.connect_zone(&home, seed.expose())?, home))
    }

    fn run_action(
        &mut self,
        h: &mut dyn ZoneHooks,
        accesses: &[(ZoneAccess, ZoneSeed)],
        a: &ShareAction,
    ) -> Result<(), ZoneError> {
        match a {
            ShareAction::CreateZoneMailbox {
                zone,
                kind,
                owner_public_key,
            } => {
                let (access, seed) = Self::access_of(accesses, *zone)?;
                if access.home.is_some() {
                    // Made in an earlier round whose acknowledgement was
                    // lost.
                    return Ok(());
                }
                if seed.public_key() != *owner_public_key {
                    return Err(ZoneError::Core("owner key is not my credential".into()));
                }
                let home = self.create_child(h, child_kind(*kind), *owner_public_key)?;
                h.set_zone_home(AccessTarget::Zone(*zone), home.clone())?;
                self.seeds.put(home.mailbox_id, seed.expose());
                Ok(())
            }
            ShareAction::GrantCredential {
                zone,
                public_key,
                role,
                put_kinds,
            } => {
                let (api, _) = self.zone_client(accesses, *zone)?;
                api.grant(*public_key, credential_role(*role), *put_kinds, LABEL)?;
                Ok(())
            }
            ShareAction::SetCredentialRole {
                zone,
                credential_id,
                role,
                put_kinds,
            } => {
                let (api, _) = self.zone_client(accesses, *zone)?;
                api.set_role(*credential_id, credential_role(*role), *put_kinds)?;
                Ok(())
            }
            ShareAction::RevokeCredential {
                zone,
                credential_id,
            } => {
                let (api, _) = self.zone_client(accesses, *zone)?;
                match api.revoke(*credential_id) {
                    Ok(()) => Ok(()),
                    Err(e) if gone(&e) => Ok(()),
                    Err(e) => Err(e.into()),
                }
            }
            ShareAction::DeleteZoneMailbox { zone } => {
                let (api, home) = self.zone_client(accesses, *zone)?;
                match api.abandon() {
                    Ok(()) => {}
                    Err(e) if gone(&e) => {}
                    Err(e) => return Err(e.into()),
                }
                self.seeds.delete(home.mailbox_id);
                self.drivers.remove(zone);
                Ok(())
            }
        }
    }

    /// A child mailbox of `kind` owned by `owner_public_key` under the
    /// account mailbox, or under the anchor (made on first use).
    fn create_child(
        &mut self,
        h: &mut dyn ZoneHooks,
        kind: ChildKind,
        owner_public_key: [u8; 32],
    ) -> Result<ZoneHome, ZoneError> {
        let (api, url, ca) = self.parent_client(h)?;
        let created = api.create_child(kind, owner_public_key, LABEL)?;
        let home = ZoneHome {
            url,
            mailbox_id: created.mailbox_id,
            extra_ca_pem: ca,
        };
        home.check()?;
        Ok(home)
    }

    fn parent_client(
        &mut self,
        h: &mut dyn ZoneHooks,
    ) -> Result<(C::Api, String, Option<String>), ZoneError> {
        if let Some(p) = &self.parent {
            let mut api = self
                .connect
                .connect(&p.url, p.extra_ca_pem.as_deref(), &p.seed)?;
            api.open(p.mailbox_id);
            return Ok((api, p.url.clone(), p.extra_ca_pem.clone()));
        }
        let (home, seed) = h.anchor()?;
        let home = match home {
            Some(home) => home,
            None => {
                let e = &self.default_endpoint;
                let mut api =
                    self.connect
                        .connect(&e.base_url, e.extra_ca_pem.as_deref(), seed.expose())?;
                let created = api.create(None, LABEL)?;
                let home = ZoneHome {
                    url: e.base_url.clone(),
                    mailbox_id: created.mailbox_id,
                    extra_ca_pem: e.extra_ca_pem.clone(),
                };
                h.set_zone_home(AccessTarget::Anchor, home.clone())?;
                home
            }
        };
        let api = self.connect_zone(&home, seed.expose())?;
        Ok((api, home.url, home.extra_ca_pem))
    }

    /// The mailbox of a contact pair, made during a verification (spec
    /// 13.5, plan 2 Task 7b in one call): my access prepared, the child
    /// mailbox made (or the existing one kept), the peer's fresh credential
    /// granted `Write`, the signed offer returned. Needs the network: a
    /// failure leaves my access without a home and returns the error.
    pub fn contact_zone_create(
        &mut self,
        repo: &mut Repository<SyncStore>,
        peer: &SignedContactCard,
        now: i64,
    ) -> Result<Vec<u8>, ZoneError> {
        let plan = repo.prepare_contact_zone(peer, now)?;
        let target = AccessTarget::Zone(plan.zone);
        let (access, seed) = repo
            .zone_access(target)?
            .ok_or_else(|| ZoneError::Core("no access to the pair".into()))?;
        let home = match access.home {
            Some(home) => home,
            None => self.create_child(repo, ChildKind::Contact, plan.owner_public_key)?,
        };
        let api = self.connect_zone(&home, seed.expose())?;
        api.grant(plan.peer_public_key, CredentialRole::Write, None, LABEL)?;
        let offer = repo.seal_contact_zone_offer(plan, home.clone())?;
        self.seeds.put(home.mailbox_id, seed.expose());
        Ok(offer)
    }

    /// The wake channel of every zone synced in the last round.
    pub fn wake_topics(&self) -> Vec<ZoneWake> {
        let mut out = Vec::new();
        for (zone, d) in &self.drivers {
            let api = d.driver.transport().api();
            let (Ok(config), Ok(info)) = (api.server_config(), api.info()) else {
                continue;
            };
            out.push(ZoneWake {
                zone: *zone,
                mailbox_id: d.home.mailbox_id,
                realtime_url: config.realtime_url,
                publishable_key: config.publishable_key,
                topic: info.wake_topic,
            });
        }
        out
    }

    /// This device's push target `tag` on zone mailbox `mailbox_id` (a
    /// zone synced in the last round), spec 13.7.
    pub fn set_push_target(
        &mut self,
        mailbox_id: [u8; 16],
        tag: [u8; 16],
        kind: PushKind,
        token: &[u8],
    ) -> Result<(), MailboxError> {
        let d = self
            .drivers
            .values()
            .find(|d| d.home.mailbox_id == mailbox_id)
            .ok_or(MailboxError::Malformed("unknown zone mailbox"))?;
        d.driver.transport().api().set_push_target(tag, kind, token)
    }

    /// The zones with a driver (synced in the last round).
    pub fn zones(&self) -> Vec<(Zone, [u8; 16])> {
        self.drivers
            .iter()
            .map(|(z, d)| (*z, d.home.mailbox_id))
            .collect()
    }
}
