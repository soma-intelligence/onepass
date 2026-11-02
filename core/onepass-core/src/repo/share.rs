//! Shared vaults and zones on the repository (sharing plan 2): zone
//! accesses (Task 5b), then sharing, members and roles (Tasks 6 to 15).

use super::Repository;
use crate::lineage::identity_id;
use crate::share::{
    AccessTarget, MemberRef, SignedZoneAccess, ZONE_ACCESS_KIND, ZoneAccess, ZoneHome, ZoneSeed,
};
use crate::store::{Record, RecordStore, Zone};
use crate::{Error, IntegrityError, Result, ValidationError};

/// Every zone access in `store`'s private zone, decoded but neither
/// verified nor opened: what a locked device may show (which zones, on
/// which servers). Records that do not decode are skipped.
pub fn list_zone_accesses(store: &impl RecordStore) -> Result<Vec<ZoneAccess>> {
    Ok(store
        .list(ZONE_ACCESS_KIND)?
        .iter()
        .filter_map(|r| {
            SignedZoneAccess::decode(&r.data)
                .ok()
                .filter(|s| s.access.target.record_id().ok() == Some(r.id))
        })
        .map(|s| s.access)
        .collect())
}

impl<S: RecordStore> Repository<S> {
    /// This session's account and identity.
    pub fn me(&self) -> MemberRef {
        MemberRef {
            account_id: self.account.params.account_id,
            identity_id: identity_id(&self.account.params.identity_pub),
        }
    }

    /// The stored access record of `target`, decoded, its signature checked
    /// against this account and its id matching its target.
    fn stored_access(&self, target: AccessTarget) -> Result<Option<(Record, SignedZoneAccess)>> {
        let id = target.record_id()?;
        let Some(r) = self.store.get(ZONE_ACCESS_KIND, id)? else {
            return Ok(None);
        };
        let s = SignedZoneAccess::decode(&r.data)?;
        if s.access.target != target {
            return Err(IntegrityError::WrongContext.into());
        }
        s.verify(
            self.account.params.account_id,
            &self.account.params.signing_pub,
        )?;
        Ok(Some((r, s)))
    }

    /// My access to `target` and its opened seed. Refused: a record signed
    /// by another key (`Integrity(Signature)`), an envelope that does not
    /// open for this account (`Crypto`), a seed that does not match its
    /// credential id (`Integrity(WrongContext)`).
    pub fn zone_access(&self, target: AccessTarget) -> Result<Option<(ZoneAccess, ZoneSeed)>> {
        let Some((_, s)) = self.stored_access(target)? else {
            return Ok(None);
        };
        let seed = s.open(
            self.account.params.account_id,
            &self.account.params.signing_pub,
            self.account.keyset(),
        )?;
        Ok(Some((s.access, seed)))
    }

    /// Every verified access of this account, without seeds.
    pub fn zone_accesses(&self) -> Result<Vec<ZoneAccess>> {
        let mut out = Vec::new();
        for r in self.store.list(ZONE_ACCESS_KIND)? {
            let Ok(s) = SignedZoneAccess::decode(&r.data) else {
                continue;
            };
            if s.access.target.record_id().ok() != Some(r.id) {
                continue;
            }
            if s.verify(
                self.account.params.account_id,
                &self.account.params.signing_pub,
            )
            .is_ok()
            {
                out.push(s.access);
            }
        }
        Ok(out)
    }

    /// The record of my access to `target` with `home` and `seed`, at the
    /// version after the stored one, for the caller to write in its
    /// transaction (with the stored version as the expected one).
    pub(crate) fn zone_access_record(
        &self,
        target: AccessTarget,
        home: Option<ZoneHome>,
        seed: &ZoneSeed,
    ) -> Result<(Record, Option<u64>)> {
        let id = target.record_id()?;
        let expected = self.store.get(ZONE_ACCESS_KIND, id)?.map(|r| r.version);
        let s = SignedZoneAccess::seal(
            self.account.params.account_id,
            &self.account.params.kem_pub,
            &self.account.keyset().signing,
            target,
            home,
            seed,
        )?;
        let version = expected.map_or(Ok(1), |v| {
            v.checked_add(1)
                .ok_or(Error::InvalidFormat("zone access version"))
        })?;
        Ok((
            Record {
                kind: ZONE_ACCESS_KIND,
                id,
                version,
                data: s.encode(),
            },
            expected,
        ))
    }

    /// Write my access to `target` on its own.
    pub(crate) fn write_zone_access(
        &mut self,
        target: AccessTarget,
        home: Option<ZoneHome>,
        seed: &ZoneSeed,
    ) -> Result<Record> {
        let (r, expected) = self.zone_access_record(target, home, seed)?;
        self.store.put_all_zoned(
            vec![(Zone::Private, r.clone(), expected)],
            vec![],
            None,
            &[],
        )?;
        Ok(r)
    }

    /// `write_zone_access` for the integration tests.
    #[cfg(all(feature = "dev-fast-kdf", debug_assertions))]
    #[doc(hidden)]
    pub fn test_write_zone_access(
        &mut self,
        target: AccessTarget,
        home: Option<ZoneHome>,
        seed: &ZoneSeed,
    ) -> Result<Record> {
        self.write_zone_access(target, home, seed)
    }

    /// Set the mailbox of a zone this account created, once the transport
    /// made it. A home already set is never changed here
    /// (`Validation("zone", "home already set")`): only a `Rekey` body with
    /// `moved_to` moves a zone. Setting the same home again is a no-op.
    pub fn set_zone_home(&mut self, target: AccessTarget, home: ZoneHome) -> Result<()> {
        home.check()?;
        let (access, seed) = self.zone_access(target)?.ok_or(Error::NotFound)?;
        match &access.home {
            Some(h) if *h == home => Ok(()),
            Some(_) => Err(ValidationError {
                field: "zone".into(),
                reason: "home already set",
            }
            .into()),
            None => self
                .write_zone_access(target, Some(home), &seed)
                .map(|_| ()),
        }
    }

    /// The account's anchor mailbox access: created on the first call
    /// without a home, its seed returned.
    pub fn anchor(&mut self) -> Result<(Option<ZoneHome>, ZoneSeed)> {
        if let Some((a, seed)) = self.zone_access(AccessTarget::Anchor)? {
            return Ok((a.home, seed));
        }
        let seed = ZoneSeed::generate()?;
        self.write_zone_access(AccessTarget::Anchor, None, &seed)?;
        Ok((None, seed))
    }
}
