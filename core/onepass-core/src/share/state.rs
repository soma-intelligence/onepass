//! The local pinned state of one shared vault (sharing spec 7.2, 8.2, 10.2,
//! 12.3): the membership head this device accepted, its known ancestors,
//! the identities seen to rotate, and local settings. Kept in the device's
//! local metadata, never synced.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{MEMBERSHIP_HISTORY, MemberRef, MembershipBody, MembershipView, ShareAction};
use crate::lineage::decode_strict_with;
use crate::manifest::{ManifestEntry, SeenManifest};
use crate::store::Zone;
use crate::{Error, Id, Result};

const BAD: Error = Error::InvalidFormat("share state");
/// Encoding version of `ShareState`.
pub const SHARE_STATE_VERSION: u8 = 1;

/// My own new identity, not yet adopted in this vault (spec 12.3, S24).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingIdentity {
    pub new_identity: MemberRef,
    pub since: i64,
}

/// A membership change that resealed the vault (spec 9.2), being pushed in
/// three phases: (1) the new envelopes and item records, (2) the body and
/// the manifest, conditional, (3) once (2) is confirmed, the deletion of
/// the old records and envelopes, the signed removal copy in the removed
/// member's contact zone, and the revocation of its credential. Kept in the
/// share state, so it is written in the rekey's transaction and a cut
/// resumes at the phase reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharePush {
    /// 1 to 3.
    pub phase: u8,
    /// Item records of the old generation, deleted in phase 3
    /// (attachment chunks are rewrapped in place, same id).
    pub collect: Vec<Id>,
    /// The `MemberKey` records of the old generations.
    pub old_keys: Vec<Id>,
    /// The removed member's contact zone, and the id and bytes of the
    /// `InviteRecord::Removed` written there in phase 3 (none when we have
    /// no contact zone with that member).
    pub notice: Option<(Zone, Id, Vec<u8>)>,
    /// The removed member's credential, revoked in phase 3.
    pub revoke: Option<[u8; 16]>,
    /// The manifest the reseal started from (a rebase verifies the
    /// server's manifest against it).
    pub from: SeenManifest,
    /// Each item resealed: item id, the version it was resealed from, the
    /// new record's blob id and its manifest entry.
    pub resealed: Vec<(Id, u64, Id, ManifestEntry)>,
}

/// Items a former member saw (spec 9.3): the item versions of the reseal
/// that followed its removal. An item still at that version is unchanged
/// since and the former member may still know it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormerMemberExposure {
    pub vault_id: Id,
    pub account_id: Id,
    pub removed_at: i64,
    pub items: Vec<(Id, u64)>,
}

/// What this device pins for one shared vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareState {
    pub version: u8,
    pub vault_id: Id,
    pub zone: Zone,
    pub head: MembershipBody,
    /// At most `MEMBERSHIP_HISTORY`, newest first.
    pub ancestors: Vec<MembershipBody>,
    /// A member identity seen to rotate, and the last membership seq this
    /// device accepted under it (plan 2 ruling A-12): a later body or
    /// manifest signed by that identity is refused.
    pub retired_signers: BTreeMap<MemberRef, u64>,
    pub identity_pending: Option<PendingIdentity>,
    /// Local only: hide this vault from the MCP server even when its meta
    /// allows it (spec 10.2).
    pub mcp_hidden: bool,
    /// Mailbox steps queued for the transport, in order, written in the
    /// same transaction as the change that needs them.
    pub actions: Vec<ShareAction>,
    /// The last shared manifest this device accepted (the personal vaults
    /// keep theirs in the device state).
    pub last_manifest: Option<SeenManifest>,
    /// The `meta_hash` that manifest committed to: a change needs a
    /// manager (spec 8.2 rule 4).
    pub last_meta: Option<[u8; 32]>,
    /// The resealing being pushed, if any.
    pub push: Option<SharePush>,
    /// The mailbox refused my credential and no signed removal was found
    /// (spec 13.8): the vault stays readable here, writes are refused.
    pub access_refused: Option<i64>,
    /// Former members and what they saw (spec 9.3).
    pub exposures: Vec<FormerMemberExposure>,
    /// The vault's name as this device last opened it (a removal can make
    /// the meta unreadable before the personal copy is named).
    pub name: String,
    /// I signed a `Leave` (spec 9.4): the vault is erased here once the
    /// body and the rekey request are sent and my credential revoked.
    pub leaving: bool,
    /// I am copying this vault to a new one under my mailbox (Task 12):
    /// its id. Writes to this one are refused meanwhile.
    pub moving_to: Option<Id>,
}

impl ShareState {
    /// The state of a vault whose first body this device just accepted.
    pub fn new(zone: Zone, head: MembershipBody) -> ShareState {
        ShareState {
            version: SHARE_STATE_VERSION,
            vault_id: head.vault_id,
            zone,
            head,
            ancestors: Vec::new(),
            retired_signers: BTreeMap::new(),
            identity_pending: None,
            mcp_hidden: false,
            actions: Vec::new(),
            last_manifest: None,
            last_meta: None,
            push: None,
            access_refused: None,
            exposures: Vec::new(),
            name: String::new(),
            leaving: false,
            moving_to: None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("share state encodes")
    }

    /// Strict decoding: version, a shared zone, bodies of this vault,
    /// ancestors capped and strictly older than the head, newest first.
    pub fn decode(b: &[u8]) -> Result<ShareState> {
        let s: ShareState = decode_strict_with(b, BAD)?;
        let ordered = std::iter::once(&s.head)
            .chain(s.ancestors.iter())
            .collect::<Vec<_>>()
            .windows(2)
            .all(|w| w[0].seq > w[1].seq);
        if s.version != SHARE_STATE_VERSION
            || !s.zone.is_shared()
            || s.ancestors.len() > MEMBERSHIP_HISTORY
            || !ordered
            || s.head.vault_id != s.vault_id
            || s.ancestors.iter().any(|a| a.vault_id != s.vault_id)
            || s.push.as_ref().is_some_and(|p| !(1..=3).contains(&p.phase))
        {
            return Err(BAD);
        }
        Ok(s)
    }

    pub fn view(&self) -> MembershipView<'_> {
        MembershipView {
            head: &self.head,
            ancestors: &self.ancestors,
        }
    }

    /// Pin `next` as the head; the old head becomes the newest ancestor and
    /// the oldest falls out past `MEMBERSHIP_HISTORY`.
    pub fn advance(&mut self, next: MembershipBody) {
        let old = std::mem::replace(&mut self.head, next);
        self.ancestors.insert(0, old);
        self.ancestors.truncate(MEMBERSHIP_HISTORY);
    }
}
