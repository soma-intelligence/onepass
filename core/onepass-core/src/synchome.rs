//! `SyncHome`: where the account syncs, signed by the account (cross-platform
//! spec 4.13, 8).
//!
//! One record per identity (kind `RecordKind::SyncHome`, id = the
//! identity's record id, version = `seq`), cast in the mould of the signed
//! lists (`crate::lists`): `postcard(Wire{postcard(body), sig})`, the
//! hybrid signature of the account signing key under `SYNC_HOME_DOMAIN`,
//! chained by `seq` and `prev_hash`, the last accepted body pinned in
//! `ChainState::sync_home`. An older `seq`, the same `seq` with another
//! hash, or the next one that does not point at the pinned body is a
//! rollback (`IntegrityError::SyncHomeRollback`).
//!
//! The server holding the record can neither move the account to another
//! mailbox (it cannot sign) nor bring back an older home (the pin). It can
//! withhold the record: a device then keeps the home it pinned. A deletion
//! from the server is ignored (`protected_from_remote_deletion`), and no
//! client deletes it.
//!
//! The record syncs with the account's other records. Two devices that set
//! a home at once both sign `seq + 1`; the server keeps one, and the other
//! device's rebase drops its own (`Repository::rebase_sync_home`): a home
//! another device chose is never overwritten silently.

use aws_lc_rs::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

use crate::chain::Seen;
use crate::crypto::{HybridSignature, HybridVerifyingKey};
use crate::repo::Repository;
use crate::store::{Record, RecordKind, RecordStore};
use crate::sync::SyncStore;
use crate::{Error, Id, IntegrityError, Result};

/// Signature domain of `SyncHome` (spec 4.13).
pub const SYNC_HOME_DOMAIN: &[u8] = b"onepass/sync-home/v1";
/// Longest mailbox base URL, bytes.
pub const SYNC_HOME_URL_MAX: usize = 256;

const BAD: Error = Error::InvalidFormat("sync home");

/// Where an account syncs. Appended variants only (postcard indexes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncBackend {
    /// The iCloud private database of the Apple ID of each device.
    CloudKit,
    /// A OnePass mailbox: its base URL (`https://`, at most 256 bytes) and
    /// the mailbox id.
    Mailbox { url: String, mailbox_id: [u8; 16] },
}

impl SyncBackend {
    /// `https://`, a host, visible ASCII, no user info, query or fragment,
    /// at most `SYNC_HOME_URL_MAX` bytes. CloudKit always passes.
    pub fn well_formed(&self) -> bool {
        match self {
            Self::CloudKit => true,
            Self::Mailbox { url, .. } => mailbox_url_ok(url),
        }
    }
}

/// The URL rule of `SyncBackend::Mailbox`.
pub fn mailbox_url_ok(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or("");
    url.len() <= SYNC_HOME_URL_MAX
        && url.bytes().all(|b| (0x21..=0x7e).contains(&b))
        && !url.contains(['?', '#', '@', '\\'])
        && !host.is_empty()
}

/// The signed content of a `SyncHome`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncHomeBody {
    pub account_id: Id,
    pub seq: u64,
    /// SHA-256 of the previous body, zeros for the first one.
    pub prev_hash: [u8; 32],
    pub backend: SyncBackend,
    /// Unix seconds, as the signing device's clock said.
    pub issued_at: i64,
}

impl SyncHomeBody {
    /// `postcard(self)`: the signed bytes.
    pub fn encode(&self) -> Vec<u8> {
        // Ids, integers, hashes, a string: cannot fail.
        postcard::to_allocvec(self).expect("sync home body encodes")
    }

    /// SHA-256 of the encoded body: the next body's `prev_hash`.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.encode())
    }

    /// What a device remembers of this body once accepted.
    pub fn seen(&self) -> Seen {
        Seen {
            seq: self.seq,
            hash: self.hash(),
        }
    }

    /// The body following `prev` (or the first one, seq 1).
    pub fn next(
        prev: Option<&SyncHomeBody>,
        account_id: Id,
        backend: SyncBackend,
        issued_at: i64,
    ) -> Result<SyncHomeBody> {
        let (seq, prev_hash) = match prev {
            Some(p) => (p.seq.checked_add(1).ok_or(BAD)?, p.hash()),
            None => (1, [0u8; 32]),
        };
        Ok(SyncHomeBody {
            account_id,
            seq,
            prev_hash,
            backend,
            issued_at,
        })
    }

    fn well_formed(&self) -> bool {
        self.seq >= 1 && self.backend.well_formed()
    }
}

/// A body and the account's signature over its encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSyncHome {
    pub body: SyncHomeBody,
    pub sig: HybridSignature,
}

/// The stored form: the body as the exact bytes signed.
#[derive(Serialize, Deserialize)]
struct Wire {
    #[serde(with = "serde_bytes")]
    body: Vec<u8>,
    sig: HybridSignature,
}

impl SignedSyncHome {
    /// The record data: `postcard(Wire{postcard(body), sig})`.
    pub fn encode(&self) -> Vec<u8> {
        let wire = Wire {
            body: self.body.encode(),
            sig: self.sig.clone(),
        };
        postcard::to_allocvec(&wire).expect("sync home encodes")
    }

    /// Strict decode, no signature check: the whole buffer, a canonical
    /// body (re-encodes to the same bytes), seq at least 1 and a well formed
    /// backend; `InvalidFormat("sync home")` otherwise.
    pub fn decode(bytes: &[u8]) -> Result<SignedSyncHome> {
        let wire: Wire = match postcard::take_from_bytes(bytes) {
            Ok((w, [])) => w,
            _ => return Err(BAD),
        };
        let body: SyncHomeBody = match postcard::take_from_bytes(&wire.body) {
            Ok((b, [])) => b,
            _ => return Err(BAD),
        };
        if body.encode() != wire.body || !body.well_formed() {
            return Err(BAD);
        }
        Ok(SignedSyncHome {
            body,
            sig: wire.sig,
        })
    }

    /// SHA-256 of the body.
    pub fn hash(&self) -> [u8; 32] {
        self.body.hash()
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, bytes).as_ref());
    out
}

/// Verify a stored `SyncHome`, which may come from a hostile server. In
/// order: strict decode (`InvalidFormat("sync home")`), the signature of
/// `key` under `SYNC_HOME_DOMAIN` (`Signature`), the account id
/// (`WrongContext`), then the history against `seen`: an older seq, the
/// same seq with another hash, or the next seq that does not chain to
/// `seen` is `SyncHomeRollback`; a larger gap cannot be chained and is
/// accepted.
pub fn verify_sync_home(
    bytes: &[u8],
    key: &HybridVerifyingKey,
    account_id: Id,
    seen: Option<&Seen>,
) -> Result<SyncHomeBody> {
    let signed = SignedSyncHome::decode(bytes)?;
    key.verify(SYNC_HOME_DOMAIN, &signed.body.encode(), &signed.sig)?;
    if signed.body.account_id != account_id {
        return Err(IntegrityError::WrongContext.into());
    }
    if let Some(last) = seen {
        let body = &signed.body;
        let consistent = if body.seq < last.seq {
            false
        } else if body.seq == last.seq {
            body.hash() == last.hash
        } else if body.seq - last.seq == 1 {
            body.prev_hash == last.hash
        } else {
            true
        };
        if !consistent {
            return Err(IntegrityError::SyncHomeRollback.into());
        }
    }
    Ok(signed.body)
}

impl<S: RecordStore> Repository<S> {
    /// The stored record of the current identity, verified against the
    /// pinned one, with its record version. Absent while one was pinned is
    /// a rollback.
    fn stored_sync_home(&self) -> Result<Option<(u64, SyncHomeBody)>> {
        let seen = self.chain.sync_home;
        match self.store.get(RecordKind::SyncHome, self.records_id)? {
            Some(rec) => {
                let body = verify_sync_home(
                    &rec.data,
                    &self.account.params.signing_pub,
                    self.account.params.account_id,
                    seen.as_ref(),
                )?;
                if rec.version != body.seq {
                    return Err(IntegrityError::WrongContext.into());
                }
                Ok(Some((rec.version, body)))
            }
            None if seen.is_some() => Err(IntegrityError::SyncHomeRollback.into()),
            None => Ok(None),
        }
    }

    /// Where the account syncs, as last signed, verified and pinned (the
    /// pin only moves forward). `None` when no home was ever set: an
    /// account from before the mailbox, on CloudKit.
    pub fn sync_home(&mut self) -> Result<Option<SyncHomeBody>> {
        let home = self.stored_sync_home()?;
        if let Some((_, body)) = &home {
            self.chain.sync_home = Some(body.seen());
        }
        Ok(home.map(|(_, b)| b))
    }

    /// The signed record of the current home, as stored and verified (and
    /// pinned): what a pairing grant carries (`FullGrantV2::sync`).
    pub fn signed_sync_home(&mut self) -> Result<Option<Vec<u8>>> {
        let Some((_, body)) = self.stored_sync_home()? else {
            return Ok(None);
        };
        self.chain.sync_home = Some(body.seen());
        Ok(self
            .store
            .get(RecordKind::SyncHome, self.records_id)?
            .map(|r| r.data))
    }

    /// The signed record of the home following the current one, without
    /// writing it.
    pub(crate) fn sync_home_write(
        &self,
        backend: SyncBackend,
        now: i64,
    ) -> Result<(Record, Option<u64>, SyncHomeBody)> {
        if !backend.well_formed() {
            return Err(BAD);
        }
        // A kit-restored device signs no account record before a device
        // pins it (rotation spec 7.5 step 5), the lists' rule.
        self.signs_lists()?;
        let current = self.stored_sync_home()?;
        let body = SyncHomeBody::next(
            current.as_ref().map(|(_, b)| b),
            self.account.params.account_id,
            backend,
            now,
        )?;
        let sig = self
            .account
            .keyset()
            .signing
            .sign(SYNC_HOME_DOMAIN, &body.encode())?;
        let signed = SignedSyncHome {
            body: body.clone(),
            sig,
        };
        let rec = Record {
            id: self.records_id,
            kind: RecordKind::SyncHome,
            version: body.seq,
            data: signed.encode(),
        };
        Ok((rec, current.map(|(v, _)| v), body))
    }

    /// The signed record of the home following the adopted one (seq 1 when
    /// none), chained to it, without writing anything (spec D.5 step 2: a
    /// migrating device claims the home elsewhere before adopting it). Two
    /// calls without an adoption between them sign the same seq.
    pub fn sign_sync_home(&self, backend: SyncBackend, now: i64) -> Result<Vec<u8>> {
        Ok(self.sync_home_write(backend, now)?.0.data)
    }

    /// Verify `signed` against the account key and the pinned home, then
    /// write it (conditional on the version read: a lost race is
    /// `Error::Conflict`) and pin it in the same transaction. The home
    /// already adopted is accepted again without a write; another body at
    /// its seq, or an older one, is `SyncHomeRollback`.
    pub fn adopt_sync_home(&mut self, signed: &[u8]) -> Result<SyncHomeBody> {
        self.writable()?;
        let current = self.stored_sync_home()?;
        let pinned = current
            .as_ref()
            .map(|(_, b)| b.seen())
            .or(self.chain.sync_home);
        let body = verify_sync_home(
            signed,
            &self.account.params.signing_pub,
            self.account.params.account_id,
            pinned.as_ref(),
        )?;
        if let Some((_, adopted)) = &current
            && adopted.seq == body.seq
        {
            return Ok(body);
        }
        let rec = Record {
            id: self.records_id,
            kind: RecordKind::SyncHome,
            version: body.seq,
            data: signed.to_vec(),
        };
        let mut chain = self.chain.clone();
        chain.sync_home = Some(body.seen());
        self.store
            .put_all_if_version_with_chain(vec![(rec, current.map(|(v, _)| v))], &chain)?;
        self.chain = chain;
        Ok(body)
    }

    /// Sign and adopt the next home: `adopt_sync_home(sign_sync_home(..))`.
    pub fn set_sync_home(&mut self, backend: SyncBackend, now: i64) -> Result<SyncHomeBody> {
        self.writable()?;
        let signed = self.sign_sync_home(backend, now)?;
        self.adopt_sync_home(&signed)
    }
}

impl Repository<SyncStore> {
    /// Rebase of a pending home over one the server moved on to: the
    /// server's stands (another device chose it), this device's pending one
    /// is dropped and the server's pinned. Never a silent overwrite.
    pub(crate) fn rebase_sync_home(&mut self) -> Result<()> {
        let id = self.records_id;
        let ancestor = match self.store.ancestor_record(RecordKind::SyncHome, id)? {
            Some(rec) => Some(verify_sync_home(
                &rec.data,
                &self.account.params.signing_pub,
                self.account.params.account_id,
                None,
            )?),
            None => None,
        };
        let server = self
            .store
            .base_record(RecordKind::SyncHome, id)?
            .ok_or(Error::NotFound)?;
        let server = verify_sync_home(
            &server.data,
            &self.account.params.signing_pub,
            self.account.params.account_id,
            ancestor.as_ref().map(SyncHomeBody::seen).as_ref(),
        )?;
        let previous = self.chain.clone();
        let forced = self.lists_forced;
        self.store.begin_batch()?;
        let result = self
            .store
            .drop_pending_record(RecordKind::SyncHome, id)
            .and_then(|()| {
                self.chain.sync_home = Some(server.seen());
                // The local pin (same seq, another hash) must not refuse
                // the server's at the next persist.
                self.lists_forced = true;
                self.persist_device_state()
            })
            .and_then(|()| self.store.commit_batch());
        if let Err(e) = result {
            let _ = self.store.rollback_batch();
            self.chain = previous;
            self.lists_forced = forced;
            return Err(e);
        }
        Ok(())
    }
}
