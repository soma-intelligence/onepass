//! "Marquer comme volé" (founder decision 2026-11-03, recover-wipe): the
//! issuing side of a wipe order (`crate::lineage::wipe`).
//!
//! Only a device the lineage already removed can be marked: a device still
//! in the roster holds the current keys, so the user removes it first (a
//! rotation, `Repository::rotate` with `Revoke`), then marks it. After a
//! `Recover` every old device is removed already: the recovered device
//! marks them directly.

use std::collections::BTreeMap;

use super::follow::lineage_records;
use super::migrate::stored_legacy_intros;
use super::pairing::stored_intros;
use super::{Repository, trust_of};
use crate::device_keys::DevicePublic;
use crate::lineage::wipe::{
    self, SignedWipe, WipeBody, sign_wipe, signed_rotations, stored_wipes, target_key, wipe_record,
};
use crate::lineage::{LINEAGE_FORMAT, LineageRecord, RotationBody, Signed};
use crate::store::RecordStore;
use crate::trust::{DeviceLineageState, TrustState};
use crate::{Error, Id, Result, ValidationError};

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

/// The rotation of this device's own chain (head back to genesis) that
/// revoked `device`, with its lineage hash.
fn removal_of<'a>(
    trust: &TrustState,
    rotations: &BTreeMap<[u8; 32], &'a Signed<RotationBody>>,
    device: Id,
) -> Option<([u8; 32], &'a Signed<RotationBody>)> {
    let mut at = trust.head.hash;
    let mut found = None;
    let mut steps = 0u64;
    while let Some(r) = rotations.get(&at) {
        if r.body.revoked.contains(&device) {
            found = Some((at, *r));
        }
        at = r.body.parent;
        steps += 1;
        if steps > trust.head.generation {
            break;
        }
    }
    found
}

/// The public keys `device` had in the lineage: an entry of a roster, a
/// genesis creator, or a stored intro (or legacy intro) naming it.
fn public_of<S: RecordStore + ?Sized>(
    store: &S,
    records: &[LineageRecord],
    device: Id,
) -> Result<Option<DevicePublic>> {
    let public = |e: &crate::lineage::RosterEntry| DevicePublic {
        device_id: e.device_id,
        sign_pub: e.sign_pub.clone(),
        kem_pub: e.kem_pub.clone(),
    };
    for r in records {
        let found = match r {
            LineageRecord::Genesis(g) => {
                (g.body.creator.device_id == device).then(|| public(&g.body.creator))
            }
            LineageRecord::Rotation(s) => s
                .body
                .roster
                .iter()
                .find(|e| e.device_id == device)
                .map(public),
        };
        if found.is_some() {
            return Ok(found);
        }
    }
    if let Some(i) = stored_intros(store)?
        .iter()
        .find(|i| i.body.entry.device_id == device)
    {
        return Ok(Some(public(&i.body.entry)));
    }
    Ok(stored_legacy_intros(store)?
        .iter()
        .find(|i| i.body.entry.device_id == device)
        .map(|i| public(&i.body.entry)))
}

impl<S: RecordStore> Repository<S> {
    /// "Marquer comme volé": write a wipe order for `device`, signed by
    /// this device's current identity (the identity of its head), bound to
    /// the device's id and public keys and to the rotation that removed
    /// it. Once the order syncs, the device erases its local copy at its
    /// next tick (`crate::repo::follow::quarantine_tick`), with no 7-day
    /// wait. The app asks the user to confirm (and for presence, as for any
    /// removal) before the call.
    ///
    /// Refused, nothing written: no trust state (a legacy account: removal
    /// there never erases, spec 10.1) or this device not `Current`
    /// (`Validation("device")`), a write refused (`ReadOnly`), `device`
    /// this one (`Validation("device", "this device")`), a device the
    /// lineage has not removed (`Validation("device", "not removed")`: it
    /// must be removed first) or whose keys this device never saw
    /// (`NotFound`), an unlocked identity other than the head's
    /// (`Validation("device", "identity")`). Marking a device marked
    /// already changes nothing.
    pub fn mark_stolen(&mut self, device: Id, now: i64) -> Result<()> {
        self.writable()?;
        let trust = trust_of(&self.store)?.ok_or_else(|| refused("device", "no device keys"))?;
        if trust.state != DeviceLineageState::Current {
            return Err(refused("device", "not current"));
        }
        if device == trust.me.device_id {
            return Err(refused("device", "this device"));
        }
        if !trust.revoked.contains(&device) {
            return Err(refused("device", "not removed"));
        }
        let identity = &self.account().keyset().identity;
        if identity.verifying_key() != trust.identity_pub {
            return Err(refused("device", "identity"));
        }
        let records = lineage_records(&self.store)?;
        let rotations = signed_rotations(&records);
        if !rotations.contains_key(&trust.head.hash) {
            return Err(refused("device", "not removed"));
        }
        let (removed_by, _) = removal_of(&trust, &rotations, device)
            .ok_or_else(|| refused("device", "not removed"))?;
        let public = public_of(&self.store, &records, device)?.ok_or(Error::NotFound)?;
        if self.stolen_devices()?.contains(&device) {
            return Ok(());
        }
        let body = WipeBody {
            format: LINEAGE_FORMAT,
            account_id: trust.account_id,
            target: device,
            target_key: target_key(&public),
            removed_by,
            head: trust.head.hash,
            issuer: trust.me.device_id,
            issued_at: now,
        };
        let order = sign_wipe(body, identity)?;
        self.store
            .put_if_version(wipe_record(&order, trust.head.generation), None)
    }

    /// The devices a valid wipe order of this account names: issued from a
    /// head of this device's own chain, signed by that head's identity, by
    /// a device of its roster, for the rotation that removed the device.
    /// Sorted, for the device list ("Marqué comme volé").
    pub fn stolen_devices(&self) -> Result<Vec<Id>> {
        let Some(trust) = trust_of(&self.store)? else {
            return Ok(Vec::new());
        };
        let records = lineage_records(&self.store)?;
        let rotations = signed_rotations(&records);
        let mut own = BTreeMap::new();
        let mut at = trust.head.hash;
        while let Some(r) = rotations.get(&at) {
            own.insert(at, *r);
            at = r.body.parent;
            if own.len() as u64 > trust.head.generation {
                break;
            }
        }
        let valid = |w: &SignedWipe| {
            let b = &w.body;
            b.account_id == trust.account_id
                && own
                    .get(&b.removed_by)
                    .is_some_and(|r| r.body.revoked.contains(&b.target))
                && own.get(&b.head).is_some_and(|h| {
                    h.body.roster.iter().any(|e| e.device_id == b.issuer)
                        && wipe::verify_wipe(w, &h.body.identity_pub).is_ok()
                })
        };
        let mut out: Vec<Id> = stored_wipes(&self.store)?
            .iter()
            .filter(|w| valid(w))
            .map(|w| w.body.target)
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }
}
