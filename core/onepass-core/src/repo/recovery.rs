//! Organizer-assisted recovery on the `Repository` (sharing plan 3 Tasks
//! 4 to 6, spec 11.3 to 11.7). See `crate::recovery`.

use super::Repository;
use super::kit::store_account_id;
use super::pairing::stored_intros;
use super::rotate::{RecoverRequest, RotationOutcome, recover_rotate};
use crate::account::Account;
use crate::account::AccountParams;
use crate::contact::{ContactEntry, LegacyIntros, roster_at};
use crate::contact::{ContactInitiator, ContactResponder};
use crate::contact::{ContactLevel, pair_id};
use crate::crypto::HybridVerifyingKey;
use crate::crypto::kem::{unwrap_key_labeled, wrap_key_labeled};
use crate::crypto::{BlobKind, SecretKey, SymmetricKey, open, random_array, seal};
use crate::device_keys::DeviceKeys;
use crate::family::FamilyRole;
use crate::lineage::LineageRecord;
use crate::lineage::RosterEntry;
use crate::lineage::identity_id;
use crate::lists::AccountList;
use crate::recovery::messages::unsigned;
use crate::recovery::{
    RECOVERY_DELAY_MAX_SECS, RECOVERY_DELAY_MIN_SECS, RecoveryEnrollment, RecoveryHalf,
    RecoveryMessage, SHARE_LABEL, derive_rk, half_aad, share_context, slot_aad, store_seal_key,
};
use crate::share::{AccessTarget, SignedZoneAccess, ZONE_ACCESS_KIND};
use crate::share::{MemberLineageRecord, MemberRef};
use crate::store::account_record_id;
use crate::store::{Record, RecordKind, RecordStore, Zone};
use crate::synchome::SyncBackend;
use crate::{Error, Id, IntegrityError, Result, ValidationError};

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

/// My enrollment as the member's screen shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEnrollmentView {
    pub enrollment_id: Id,
    pub organizer_name_local: String,
    pub delay_secs: u32,
    pub created_at: i64,
    /// False once my identity or the organizer's changed since (spec
    /// 11.4): the member is asked to enroll again.
    pub valid: bool,
}

/// A member who chose me to help (organizer side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperView {
    pub member: Id,
    pub name_local: String,
    pub enrollment_id: Id,
    pub delay_secs: u32,
}

impl<S: RecordStore> Repository<S> {
    /// The master password and Secret Key of the session, checked by
    /// opening the stored params and keyset with every unlock check
    /// (`WrongPassword` otherwise).
    pub(crate) fn confirm_password(&self, password: &str, secret_key: &SecretKey) -> Result<()> {
        let params = self
            .store
            .get(RecordKind::AccountParams, self.records_id)?
            .ok_or(Error::NotFound)?;
        let keyset = self
            .store
            .get(RecordKind::Keyset, self.records_id)?
            .ok_or(Error::NotFound)?;
        let (stored, _) = Account::unlock_exporting_auk_at(
            password,
            secret_key,
            &params.data,
            &keyset.data,
            self.device.pinned.as_ref(),
            self.chain.params_epoch,
        )?;
        if stored.params != self.account.params {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// Spec 11.4, S17, S18, A9, A10: enroll in organizer-assisted
    /// recovery, from my own screen only, after my password and Secret Key
    /// (2SKD; the Secret Key also seals `S_store` on the mailbox, 11.7).
    /// `organizer` must be an `Active`, `Verified` contact and an organizer
    /// of my family; `delay_secs` within the bounds. One transaction: the
    /// slot (my keyset sealed under RK), the half, and the signed `Enroll`
    /// in our contact zone, `S_org` wrapped for the organizer's KEM key as
    /// pinned in my book. A previous enrollment is replaced (slot and half
    /// rewritten; its `Enroll` stays, without effect).
    pub fn enroll_recovery(
        &mut self,
        organizer: Id,
        delay_secs: u32,
        password: &str,
        secret_key: &SecretKey,
        now: i64,
    ) -> Result<RecoveryEnrollment> {
        self.writable()?;
        if !(RECOVERY_DELAY_MIN_SECS..=RECOVERY_DELAY_MAX_SECS).contains(&delay_secs) {
            return Err(refused("delay", "out of bounds"));
        }
        let me = self.me();
        if organizer == me.account_id {
            return Err(refused("organizer", "self"));
        }
        let c = self
            .contact(organizer)?
            .ok_or_else(|| refused("organizer", "unknown"))?;
        if !c.usable_for(ContactLevel::Verified) {
            return Err(refused("organizer", "not verified"));
        }
        let is_organizer = self.family()?.is_some_and(|f| {
            f.members
                .iter()
                .any(|m| m.account_id == organizer && m.role == FamilyRole::Organizer)
        });
        if !is_organizer {
            return Err(refused("organizer", "not an organizer"));
        }
        self.confirm_password(password, secret_key)?;
        let zone = self.contact_zone(organizer)?;

        let org = MemberRef {
            account_id: organizer,
            identity_id: identity_id(&c.identity_pub),
        };
        let enrollment = RecoveryEnrollment {
            member: me,
            organizer: org,
            enrollment_id: Id::new(),
            delay_secs,
            created_at: now,
        };
        enrollment.check()?;
        let eid = enrollment.enrollment_id;
        let s_org = zeroize::Zeroizing::new(random_array::<32>()?);
        let s_store = zeroize::Zeroizing::new(random_array::<32>()?);
        let rk = derive_rk(&s_org, &s_store, me.account_id, me.identity_id, eid)?;
        let plain = self.account.recovery_keyset()?;
        let slot = seal(
            &rk,
            BlobKind::RecoverySlot,
            &slot_aad(me.identity_id),
            &plain,
        )?;
        let mailbox = matches!(
            self.sync_home()?.map(|h| h.backend),
            Some(SyncBackend::Mailbox { .. })
        );
        let half = if mailbox {
            let k_store = store_seal_key(&secret_key.0, eid)?;
            RecoveryHalf::Sealed {
                enrollment_id: eid,
                sealed: seal(
                    &k_store,
                    BlobKind::RecoverySlot,
                    &half_aad(me.identity_id, eid),
                    &s_store[..],
                )?,
            }
        } else {
            RecoveryHalf::Clear {
                enrollment_id: eid,
                s_store: *s_store,
            }
        };
        let envelope = wrap_key_labeled(
            &c.kem_pub,
            &SymmetricKey::from_bytes(*s_org),
            SHARE_LABEL,
            &share_context(&me, &org, eid),
        )?;
        let msg = RecoveryMessage::Enroll {
            enrollment: enrollment.clone(),
            envelope,
            sig: unsigned(),
        }
        .sign_with(|d, b| self.account.keyset().signing.sign(d, b))?;

        let prev = |kind| -> Result<Option<u64>> {
            Ok(self.store.get(kind, me.identity_id)?.map(|r| r.version))
        };
        let slot_prev = prev(RecordKind::RecoverySlot)?;
        let half_prev = prev(RecordKind::RecoveryHalf)?;
        let next = |p: Option<u64>| p.map_or(1, |v| v + 1);
        let mut zoned = self.own_lineage_for(zone)?;
        zoned.extend(vec![
            (
                Zone::Private,
                Record {
                    kind: RecordKind::RecoverySlot,
                    id: me.identity_id,
                    version: next(slot_prev),
                    data: slot,
                },
                slot_prev,
            ),
            (
                Zone::Private,
                Record {
                    kind: RecordKind::RecoveryHalf,
                    id: me.identity_id,
                    version: next(half_prev),
                    data: half.encode().to_vec(),
                },
                half_prev,
            ),
            (
                zone,
                Record {
                    kind: RecordKind::RecoveryMessage,
                    id: msg.record_id(),
                    version: 1,
                    data: msg.encode(),
                },
                None,
            ),
        ]);
        self.store.put_all_zoned(zoned, vec![], None, &[])?;
        Ok(enrollment)
    }

    /// My lineage (every record of my account and the intros under my
    /// head) as `MemberLineage` rows of `zone` not there yet: the
    /// organizer checks a cancellation against my roster from them (spec
    /// 11.5 step 3).
    pub(crate) fn own_lineage_for(&self, zone: Zone) -> Result<Vec<(Zone, Record, Option<u64>)>> {
        let me = self.me();
        let mut published: Vec<MemberLineageRecord> = Vec::new();
        for r in self.store.list(RecordKind::Lineage)? {
            if let Ok(l) = LineageRecord::decode(&r.data)
                && l.account_id() == me.account_id
            {
                published.push(MemberLineageRecord::Lineage(l));
            }
        }
        if let Some(t) = self.store.trust_state()? {
            for i in stored_intros(&self.store)? {
                if i.body.account_id == me.account_id && i.body.head == t.head.hash {
                    published.push(MemberLineageRecord::Intro(i));
                }
            }
        }
        let mut out = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for m in published {
            let id = m.id();
            if !seen.insert(id)
                || self
                    .store
                    .get_in(zone, RecordKind::MemberLineage, id)?
                    .is_some()
            {
                continue;
            }
            out.push((
                zone,
                Record {
                    kind: RecordKind::MemberLineage,
                    id,
                    version: 1,
                    data: m.encode(),
                },
                None,
            ));
        }
        Ok(out)
    }

    /// Every recovery message of the contact zones, with the zone it was
    /// read from; the ones that do not decode are left out.
    pub(crate) fn recovery_messages(&mut self) -> Result<Vec<(Zone, RecoveryMessage)>> {
        let mut out = Vec::new();
        for zone in self.contact_zones()? {
            for rec in self.store.list_in(zone, RecordKind::RecoveryMessage)? {
                if let Ok(m) = RecoveryMessage::decode(&rec.data)
                    && m.record_id() == rec.id
                {
                    out.push((zone, m));
                }
            }
        }
        Ok(out)
    }

    /// The half of my current enrollment, if any (any identity: a half
    /// under an older identity shows the enrollment as no longer valid).
    fn my_half(&mut self) -> Result<Option<(Id, RecoveryHalf)>> {
        let me = self.me();
        let mut halves: Vec<(Id, RecoveryHalf)> = self
            .store
            .list(RecordKind::RecoveryHalf)?
            .iter()
            .filter_map(|r| RecoveryHalf::decode(&r.data).ok().map(|h| (r.id, h)))
            .collect();
        halves.sort_by_key(|(id, _)| *id != me.identity_id);
        Ok(halves.into_iter().next())
    }

    /// My enrollment (member side), `None` when I am not enrolled.
    pub fn recovery_enrollment(&mut self) -> Result<Option<RecoveryEnrollmentView>> {
        let Some((half_id, half)) = self.my_half()? else {
            return Ok(None);
        };
        let me = self.me();
        let eid = half.enrollment_id();
        let found = self
            .recovery_messages()?
            .into_iter()
            .find_map(|(zone, m)| match m {
                RecoveryMessage::Enroll { enrollment, .. }
                    if enrollment.enrollment_id == eid
                        && enrollment.member.account_id == me.account_id
                        && zone
                            == Zone::Contact(pair_id(
                                me.account_id,
                                enrollment.organizer.account_id,
                            )) =>
                {
                    Some(enrollment)
                }
                _ => None,
            });
        let Some(enrollment) = found else {
            return Ok(None);
        };
        let c = self.contact(enrollment.organizer.account_id)?;
        let organizer_ok = c.as_ref().is_some_and(|c| {
            c.usable_for(ContactLevel::Verified)
                && identity_id(&c.identity_pub) == enrollment.organizer.identity_id
        });
        Ok(Some(RecoveryEnrollmentView {
            enrollment_id: eid,
            organizer_name_local: c.map(|c| c.name_local).unwrap_or_default(),
            delay_secs: enrollment.delay_secs,
            created_at: enrollment.created_at,
            valid: organizer_ok
                && half_id == me.identity_id
                && enrollment.member.identity_id == me.identity_id,
        }))
    }

    /// Turn recovery off (member side): the slot and the half go, after
    /// my password and Secret Key.
    pub fn disable_recovery(&mut self, password: &str, secret_key: &SecretKey) -> Result<()> {
        self.writable()?;
        self.confirm_password(password, secret_key)?;
        let mut deletes = Vec::new();
        for kind in [RecordKind::RecoverySlot, RecordKind::RecoveryHalf] {
            for r in self.store.list(kind)? {
                deletes.push((Zone::Private, kind, r.id));
            }
        }
        if deletes.is_empty() {
            return Ok(());
        }
        self.store.put_all_zoned(vec![], deletes, None, &[])
    }

    /// The members that chose me to help (organizer side): per member, the
    /// newest `Enroll` of our contact zone whose signature verifies under
    /// the member's key pinned in my book, for the member's identity held
    /// there, naming my current identity as organizer. An enrollment the
    /// member did not sign (a server's, A9) is never listed.
    pub fn recovery_enrollments_for_me(&mut self) -> Result<Vec<HelperView>> {
        Ok(self
            .valid_enrollments_for_me()?
            .into_iter()
            .map(|(e, name)| HelperView {
                member: e.member.account_id,
                name_local: name,
                enrollment_id: e.enrollment_id,
                delay_secs: e.delay_secs,
            })
            .collect())
    }

    /// See `recovery_enrollments_for_me`: the enrollments themselves, with
    /// the member's local name, one per member, sorted by member.
    pub(crate) fn valid_enrollments_for_me(&mut self) -> Result<Vec<(RecoveryEnrollment, String)>> {
        let me = self.me();
        let mut best: std::collections::BTreeMap<Id, (RecoveryEnrollment, String)> =
            std::collections::BTreeMap::new();
        for (zone, m) in self.recovery_messages()? {
            let RecoveryMessage::Enroll { enrollment, .. } = &m else {
                continue;
            };
            let member = enrollment.member.account_id;
            if enrollment.organizer != me || zone != Zone::Contact(pair_id(me.account_id, member)) {
                continue;
            }
            let Some(c) = self.contact(member)? else {
                continue;
            };
            if !c.usable_for(ContactLevel::Link)
                || identity_id(&c.identity_pub) != enrollment.member.identity_id
                || m.verify(&c.sign_pub).is_err()
            {
                continue;
            }
            let newer = best.get(&member).is_none_or(|(b, _)| {
                (enrollment.created_at, enrollment.enrollment_id) > (b.created_at, b.enrollment_id)
            });
            if newer {
                best.insert(member, (enrollment.clone(), c.name_local.clone()));
            }
        }
        Ok(best.into_values().collect())
    }
}

/// Where a recovery stands, on the organizer's side (spec 11.5 steps 2 to
/// 4, B-7: the delay runs on the organizer's clock).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStatus {
    Waiting {
        release_after: i64,
    },
    Ready,
    /// A device of the member cancelled, at its own time `at`.
    Cancelled {
        at: i64,
    },
    /// The member enrolled again since the request: the request is void.
    Replaced,
    NotEnrolled,
}

/// A request shown on the member's devices, without unlocking: "Quentin a
/// demandé à récupérer ton compte. Ce sera possible le … Si ce n'est pas
/// toi, annule."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryAlert {
    pub enrollment_id: Id,
    pub organizer_name_local: String,
    pub release_after: i64,
}

/// What a locked device can read and check of its own account: the
/// account id and the current identity's signing key, from the trust
/// state and the params that identity signed.
fn offline_keys(store: &dyn RecordStore) -> Result<(Id, Id, HybridVerifyingKey)> {
    let t = store.trust_state()?.ok_or(Error::NotFound)?;
    let records_id = account_record_id(
        t.account_id,
        (t.head.generation > 0).then_some(&t.identity_pub),
    );
    let params = store
        .get(RecordKind::AccountParams, records_id)?
        .ok_or(Error::NotFound)?;
    let p = AccountParams::decode_verified(&params.data, &t.identity_pub)?;
    if p.account_id != t.account_id {
        return Err(IntegrityError::WrongContext.into());
    }
    Ok((t.account_id, records_id, p.signing_pub))
}

/// The contact zones of a locked device, from its own signed accesses.
fn offline_contact_zones(
    store: &dyn RecordStore,
    account_id: Id,
    key: &HybridVerifyingKey,
) -> Result<Vec<Zone>> {
    let mut out = Vec::new();
    for r in store.list(ZONE_ACCESS_KIND)? {
        let Ok(s) = SignedZoneAccess::decode(&r.data) else {
            continue;
        };
        if s.access.target.record_id().ok() != Some(r.id) || s.verify(account_id, key).is_err() {
            continue;
        }
        if let AccessTarget::Zone(z @ Zone::Contact(_)) = s.access.target {
            out.push(z);
        }
    }
    Ok(out)
}

/// The enrollment ids of my halves.
fn my_enrollments(store: &dyn RecordStore) -> Result<Vec<Id>> {
    Ok(store
        .list(RecordKind::RecoveryHalf)?
        .iter()
        .filter_map(|r| {
            RecoveryHalf::decode(&r.data)
                .ok()
                .map(|h| h.enrollment_id())
        })
        .collect())
}

/// Spec 11.5 step 3, on a member device, locked or not: the requests of
/// my organizers for my current enrollments, each signed by the
/// organizer's key as my book holds it.
pub fn recovery_alerts(store: &dyn RecordStore) -> Result<Vec<RecoveryAlert>> {
    let Ok((account_id, records_id, key)) = offline_keys(store) else {
        return Ok(Vec::new());
    };
    let mine = my_enrollments(store)?;
    if mine.is_empty() {
        return Ok(Vec::new());
    }
    let book = match store.get(RecordKind::ContactBook, records_id)? {
        Some(rec) => {
            crate::lists::verify::<ContactEntry>(&key, ContactEntry::DOMAIN, &rec.data, None)?
                .entries
        }
        None => Vec::new(),
    };
    let mut out = Vec::new();
    for zone in offline_contact_zones(store, account_id, &key)? {
        let messages: Vec<(Id, RecoveryMessage)> = store
            .list_in(zone, RecordKind::RecoveryMessage)?
            .iter()
            .filter_map(|r| RecoveryMessage::decode(&r.data).ok().map(|m| (r.id, m)))
            .collect();
        // My own enrollments of this zone, signed by my key: who each one
        // names as organizer.
        let named: std::collections::BTreeMap<Id, MemberRef> = messages
            .iter()
            .filter_map(|(id, m)| match m {
                RecoveryMessage::Enroll { enrollment, .. }
                    if *id == enrollment.enrollment_id
                        && enrollment.member.account_id == account_id
                        && m.verify(&key).is_ok() =>
                {
                    Some((enrollment.enrollment_id, enrollment.organizer))
                }
                _ => None,
            })
            .collect();
        for (rec_id, m) in &messages {
            let RecoveryMessage::Request {
                enrollment_id,
                release_after,
                organizer,
                ..
            } = &m
            else {
                continue;
            };
            if m.record_id() != *rec_id
                || !mine.contains(enrollment_id)
                || named.get(enrollment_id) != Some(organizer)
                || zone != Zone::Contact(pair_id(account_id, organizer.account_id))
            {
                continue;
            }
            let Some(c) = book.iter().find(|c| c.account_id == organizer.account_id) else {
                continue;
            };
            if identity_id(&c.identity_pub) != organizer.identity_id
                || m.verify(&c.sign_pub).is_err()
            {
                continue;
            }
            out.push(RecoveryAlert {
                enrollment_id: *enrollment_id,
                organizer_name_local: c.name_local.clone(),
                release_after: *release_after,
            });
        }
    }
    out.sort_by_key(|a| (a.release_after, a.enrollment_id));
    Ok(out)
}

/// "Annuler" on a member device (spec 11.5 step 3): a `Cancel` signed by
/// this device's key, in the zone that carries the request, with no
/// password (a locked device must be able to cancel).
pub fn cancel_recovery(
    store: &mut dyn RecordStore,
    enrollment_id: Id,
    device_keys: &DeviceKeys,
    now: i64,
) -> Result<()> {
    let (account_id, _, key) = offline_keys(&*store)?;
    let device = store.chain_state()?.device_id.ok_or(Error::NotFound)?;
    if !my_enrollments(&*store)?.contains(&enrollment_id) {
        return Err(refused("enrollment", "not mine"));
    }
    let mut target = None;
    for zone in offline_contact_zones(&*store, account_id, &key)? {
        let found = store
            .list_in(zone, RecordKind::RecoveryMessage)?
            .iter()
            .filter_map(|r| RecoveryMessage::decode(&r.data).ok())
            .any(|m| m.enrollment_id() == enrollment_id);
        if found {
            target = Some(zone);
            break;
        }
    }
    let zone = target.ok_or(Error::NotFound)?;
    let msg = RecoveryMessage::Cancel {
        enrollment_id,
        device,
        at: now,
        sig: unsigned(),
    }
    .sign_with(|d, b| device_keys.sign(d, b))?;
    if store
        .get_in(zone, RecordKind::RecoveryMessage, msg.record_id())?
        .is_some()
    {
        return Ok(());
    }
    store.put_all_zoned(
        vec![(
            zone,
            Record {
                kind: RecordKind::RecoveryMessage,
                id: msg.record_id(),
                version: 1,
                data: msg.encode(),
            },
            None,
        )],
        vec![],
        None,
        &[],
    )
}

impl<S: RecordStore> Repository<S> {
    /// Spec 11.5 step 2, the organizer: after my password and Secret Key,
    /// a signed request for `member`'s current enrollment naming me;
    /// `release_after = now + delay`. Asking again changes nothing.
    pub fn request_recovery(
        &mut self,
        member: Id,
        password: &str,
        secret_key: &SecretKey,
        now: i64,
    ) -> Result<RecoveryStatus> {
        self.writable()?;
        let enrollment = self
            .valid_enrollments_for_me()?
            .into_iter()
            .map(|(e, _)| e)
            .find(|e| e.member.account_id == member)
            .ok_or_else(|| refused("member", "not enrolled"))?;
        self.confirm_password(password, secret_key)?;
        if self.my_request(member, enrollment.enrollment_id)?.is_some() {
            return self.recovery_status(member, now);
        }
        let zone = self.contact_zone(member)?;
        let release_after = now
            .checked_add(i64::from(enrollment.delay_secs))
            .ok_or(Error::InvalidFormat("recovery"))?;
        let msg = RecoveryMessage::Request {
            enrollment_id: enrollment.enrollment_id,
            requested_at: now,
            release_after,
            organizer: self.me(),
            sig: unsigned(),
        }
        .sign_with(|d, b| self.account.keyset().signing.sign(d, b))?;
        self.store.put_all_zoned(
            vec![(
                zone,
                Record {
                    kind: RecordKind::RecoveryMessage,
                    id: msg.record_id(),
                    version: 1,
                    data: msg.encode(),
                },
                None,
            )],
            vec![],
            None,
            &[],
        )?;
        Ok(RecoveryStatus::Waiting { release_after })
    }

    /// My request for `enrollment_id` of `member`, signed by my current
    /// key: `(requested_at, release_after)`.
    fn my_request(&mut self, member: Id, enrollment_id: Id) -> Result<Option<(i64, i64)>> {
        let me = self.me();
        let zone = Zone::Contact(pair_id(me.account_id, member));
        let key = self.account.params.signing_pub.clone();
        Ok(self
            .recovery_messages()?
            .into_iter()
            .filter(|(z, _)| *z == zone)
            .find_map(|(_, m)| match &m {
                RecoveryMessage::Request {
                    enrollment_id: e,
                    requested_at,
                    release_after,
                    organizer,
                    ..
                } if *e == enrollment_id && *organizer == me && m.verify(&key).is_ok() => {
                    Some((*requested_at, *release_after))
                }
                _ => None,
            }))
    }

    /// The newest of my requests for `member`, any enrollment.
    fn my_latest_request(&mut self, member: Id) -> Result<Option<(Id, i64)>> {
        let me = self.me();
        let zone = Zone::Contact(pair_id(me.account_id, member));
        let key = self.account.params.signing_pub.clone();
        Ok(self
            .recovery_messages()?
            .into_iter()
            .filter(|(z, _)| *z == zone)
            .filter_map(|(_, m)| match &m {
                RecoveryMessage::Request {
                    enrollment_id,
                    requested_at,
                    release_after,
                    organizer,
                    ..
                } if *organizer == me && m.verify(&key).is_ok() => {
                    Some((*requested_at, *enrollment_id, *release_after))
                }
                _ => None,
            })
            .max()
            .map(|(_, e, r)| (e, r)))
    }

    /// The member's roster at the head my book pins, from the lineage the
    /// zones carry (`roster_at`): who may cancel.
    fn member_roster(&mut self, member: Id) -> Result<Vec<RosterEntry>> {
        let Some(c) = self.contact(member)? else {
            return Ok(Vec::new());
        };
        let published = self.published_lineage()?;
        let Some(p) = published.get(&member) else {
            return Ok(Vec::new());
        };
        Ok(roster_at(
            &p.records,
            &p.intros,
            &LegacyIntros::default(),
            &c.pinned_head.hash,
        )
        .unwrap_or_default())
    }

    /// Where my request for `member` stands at `now` (organizer side, B-7:
    /// my clock). `Cancelled` once a cancellation signed by a device of
    /// the member's roster at the head I pin is read (a device outside it,
    /// or one its lineage revoked, counts for nothing); `Replaced` once
    /// the member enrolled again; `NotEnrolled` with no enrollment naming
    /// me. No request: `NotFound`.
    pub fn recovery_status(&mut self, member: Id, now: i64) -> Result<RecoveryStatus> {
        let Some(enrollment) = self
            .valid_enrollments_for_me()?
            .into_iter()
            .map(|(e, _)| e)
            .find(|e| e.member.account_id == member)
        else {
            return Ok(RecoveryStatus::NotEnrolled);
        };
        let (eid, release_after) = self.my_latest_request(member)?.ok_or(Error::NotFound)?;
        if eid != enrollment.enrollment_id {
            return Ok(RecoveryStatus::Replaced);
        }
        if let Some(at) = self.cancelled_at(member, eid)? {
            return Ok(RecoveryStatus::Cancelled { at });
        }
        if now >= release_after {
            Ok(RecoveryStatus::Ready)
        } else {
            Ok(RecoveryStatus::Waiting { release_after })
        }
    }

    /// The earliest valid cancellation of `enrollment_id`.
    fn cancelled_at(&mut self, member: Id, enrollment_id: Id) -> Result<Option<i64>> {
        let me = self.me();
        let zone = Zone::Contact(pair_id(me.account_id, member));
        let roster = self.member_roster(member)?;
        Ok(self
            .recovery_messages()?
            .into_iter()
            .filter(|(z, _)| *z == zone)
            .filter_map(|(_, m)| match &m {
                RecoveryMessage::Cancel {
                    enrollment_id: e,
                    device,
                    at,
                    ..
                } if *e == enrollment_id => roster
                    .iter()
                    .find(|r| r.device_id == *device)
                    .filter(|r| m.verify(&r.sign_pub).is_ok())
                    .map(|_| *at),
                _ => None,
            })
            .min())
    }
}

impl<S: RecordStore> Repository<S> {
    /// My `Released` note for `enrollment_id` of `member`, signed by my
    /// current key.
    fn released(&mut self, member: Id, enrollment_id: Id) -> Result<bool> {
        let me = self.me();
        let zone = Zone::Contact(pair_id(me.account_id, member));
        let key = self.account.params.signing_pub.clone();
        Ok(self.recovery_messages()?.into_iter().any(|(z, m)| {
            z == zone
                && matches!(&m, RecoveryMessage::Released { enrollment_id: e, organizer, .. }
                    if *e == enrollment_id && *organizer == me)
                && m.verify(&key).is_ok()
        }))
    }

    /// Spec 11.5 step 4, the organizer, face to face with the member's new
    /// device: once `recovery_status` is `Ready` and I confirmed the SAS
    /// of `session` (`ContactInitiator::confirm_sas_for_recovery`), open
    /// `S_org` from the member's `Enroll` (my current KEM key, then my
    /// retired ones) and seal it into the channel. One release per
    /// enrollment: a signed `Released` note in our contact zone, written
    /// once the frame exists. Refused, nothing written: not `Ready`
    /// (`Validation("recovery", "not ready")`), released before
    /// (`"already released"`), SAS not confirmed (`Validation`).
    pub fn release_recovery_share(
        &mut self,
        member: Id,
        session: &mut ContactInitiator,
        now: i64,
    ) -> Result<Vec<u8>> {
        self.writable()?;
        if self.recovery_status(member, now)? != RecoveryStatus::Ready {
            return Err(refused("recovery", "not ready"));
        }
        let enrollment = self
            .valid_enrollments_for_me()?
            .into_iter()
            .map(|(e, _)| e)
            .find(|e| e.member.account_id == member)
            .ok_or_else(|| refused("member", "not enrolled"))?;
        let eid = enrollment.enrollment_id;
        if self.released(member, eid)? {
            return Err(refused("recovery", "already released"));
        }
        let zone = self.contact_zone(member)?;
        let envelope = self
            .recovery_messages()?
            .into_iter()
            .find_map(|(z, m)| match m {
                RecoveryMessage::Enroll {
                    enrollment: e,
                    envelope,
                    ..
                } if z == zone && e == enrollment => Some(envelope),
                _ => None,
            })
            .ok_or(Error::NotFound)?;
        let context = share_context(&enrollment.member, &enrollment.organizer, eid);
        let keyset = self.account.keyset();
        let key = std::iter::once(&keyset.kem)
            .chain(keyset.retired_kem.iter())
            .find_map(|k| unwrap_key_labeled(k, &envelope, SHARE_LABEL, &context).ok())
            .ok_or(IntegrityError::Signature)?;
        let s_org = zeroize::Zeroizing::new(*key.expose());
        drop(key);
        let frame = session.send_recovery_share(eid, &s_org, now)?;
        let note = RecoveryMessage::Released {
            enrollment_id: eid,
            at: now,
            organizer: self.me(),
            sig: unsigned(),
        }
        .sign_with(|d, b| self.account.keyset().signing.sign(d, b))?;
        self.store.put_all_zoned(
            vec![(
                zone,
                Record {
                    kind: RecordKind::RecoveryMessage,
                    id: note.record_id(),
                    version: 1,
                    data: note.encode(),
                },
                None,
            )],
            vec![],
            None,
            &[],
        )?;
        Ok(frame)
    }
}

/// Spec 11.5 steps 5 and 6, S20, S21, the member's new device after a
/// full sync of its private base (no unlock): take the organizer's
/// `RecoveryShare` from `session` (`ContactResponder::new_for_recovery`),
/// find the half of that enrollment (`Validation("recovery", "wrong
/// enrollment")` when none), open `S_store` (clear on iCloud; sealed on
/// the mailbox, opened with `kit_secret_key`, the Secret Key of the
/// Emergency Kit: absent, `Validation("recovery", "emergency kit
/// needed")`), derive RK, open the keyset of the slot and rotate with
/// reason `Recover` (`recover_rotate`). `req.keyset_record` is not read:
/// the slot gives it. Then the slot and the half go, in a transaction of
/// their own (the rotation's deletes nothing, R23). RK, `S_org`, `S_store`
/// and the keyset are wiped on drop.
pub fn recover_with_share<S: RecordStore>(
    store: S,
    session: &mut ContactResponder,
    frame: &[u8],
    kit_secret_key: Option<&SecretKey>,
    req: RecoverRequest<'_>,
    now: i64,
) -> Result<(Repository<S>, RotationOutcome)> {
    let (eid, s_org) = session.take_recovery_share(frame, now)?;
    let account_id = store_account_id(&store)?;
    let (identity, half) = store
        .list(RecordKind::RecoveryHalf)?
        .iter()
        .filter_map(|r| RecoveryHalf::decode(&r.data).ok().map(|h| (r.id, h)))
        .find(|(_, h)| h.enrollment_id() == eid)
        .ok_or_else(|| refused("recovery", "wrong enrollment"))?;
    let s_store = match &half {
        RecoveryHalf::Clear { s_store, .. } => zeroize::Zeroizing::new(*s_store),
        RecoveryHalf::Sealed { sealed, .. } => {
            let sk = kit_secret_key.ok_or_else(|| refused("recovery", "emergency kit needed"))?;
            let k = store_seal_key(&sk.0, eid)?;
            let plain = open(&k, BlobKind::RecoverySlot, &half_aad(identity, eid), sealed)?;
            let b: [u8; 32] = plain[..]
                .try_into()
                .map_err(|_| Error::InvalidFormat("recovery half"))?;
            zeroize::Zeroizing::new(b)
        }
    };
    drop(half);
    let slot = store
        .get(RecordKind::RecoverySlot, identity)?
        .ok_or(Error::NotFound)?;
    let rk = derive_rk(&s_org, &s_store, account_id, identity, eid)?;
    drop((s_org, s_store));
    let keyset = open(&rk, BlobKind::RecoverySlot, &slot_aad(identity), &slot.data)?;
    drop(rk);
    let (mut repo, out) = recover_rotate(
        store,
        RecoverRequest {
            keyset_record: &keyset,
            new_password: req.new_password,
            new_secret_key: req.new_secret_key,
            device_keys: req.device_keys,
            device_name: req.device_name,
            kind: req.kind,
            mode: req.mode,
            device: req.device,
        },
        now,
    )?;
    let mut deletes = Vec::new();
    for kind in [RecordKind::RecoverySlot, RecordKind::RecoveryHalf] {
        for r in repo.store.list(kind)? {
            deletes.push((Zone::Private, kind, r.id));
        }
    }
    if !deletes.is_empty() {
        // The rotation is committed (K12): a failure here leaves a slot
        // of the retired identity, which the next `disable_recovery` or
        // enrollment replaces.
        let _ = repo.store.put_all_zoned(vec![], deletes, None, &[]);
    }
    Ok((repo, out))
}
